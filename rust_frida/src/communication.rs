#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::session::{PendingRelayFrame, Session};
use crate::{log_agent, log_error, log_info, log_success, log_warn};

const FRAME_KIND_CMD: u8 = 1;
#[cfg(feature = "qbdi")]
const FRAME_KIND_QBDI_HELPER: u8 = 2;
/// TCP bootstrap frame carrying a host-side script. This is consumed by the
/// server before the session relay is established and never reaches the agent.
pub(crate) const FRAME_KIND_BOOTSTRAP_SCRIPT: u8 = 3;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;
const FRAME_KIND_BYE: u8 = 0x87;

/// Agent payloads are normally small command results or log chunks. Keeping
/// the same upper bound on both TCP and socketpair readers prevents a peer
/// from forcing an unbounded allocation with a forged length field.
pub(crate) const MAX_FRAME_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Frames produced while the textual TCP bootstrap is still in progress.
/// The cap keeps a stalled client from turning script output into unbounded
/// server memory use; the oldest log/event frames are discarded first.
const MAX_RELAY_BACKLOG_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum HostToAgentMessage {
    Command(String),
    #[cfg(feature = "qbdi")]
    QbdiHelper(Vec<u8>),
}

/// 泛型同步通道：在多线程间传递单次值，支持超时等待。
pub(crate) struct SyncChannel<T> {
    mutex: Mutex<Option<T>>,
    cvar: Condvar,
}

impl<T: Clone> SyncChannel<T> {
    pub(crate) fn new() -> Self {
        SyncChannel {
            mutex: Mutex::new(None),
            cvar: Condvar::new(),
        }
    }

    /// 获取 mutex 锁，中毒时自动恢复。
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, Option<T>> {
        self.mutex.lock().unwrap_or_else(|e| {
            log_error!("SyncChannel: mutex poisoned, recovering");
            e.into_inner()
        })
    }

    /// 设置值并通知所有等待者（由 handle_socket_connection 调用）。
    pub(crate) fn send(&self, val: T) {
        let mut guard = self.lock_or_recover();
        *guard = Some(val);
        self.cvar.notify_all();
    }

    /// 清除当前值。
    pub(crate) fn clear(&self) {
        let mut guard = self.lock_or_recover();
        *guard = None;
    }

    /// 持锁等待值到来或超时，返回值的克隆。
    fn wait_for_value(&self, guard: std::sync::MutexGuard<'_, Option<T>>, dur: Duration) -> Option<T> {
        match self.cvar.wait_timeout_while(guard, dur, |val| val.is_none()) {
            Ok((guard, timeout)) => {
                if timeout.timed_out() {
                    None
                } else {
                    guard.clone()
                }
            }
            Err(_) => None,
        }
    }

    /// 在持锁状态下清除值、调用 `f`（通常用于发送请求），再阻塞等待值到来或超时。
    /// 保证"清除→发请求→等待"之间不存在竞态窗口。
    pub(crate) fn clear_then_recv<F: FnOnce()>(&self, dur: Duration, f: F) -> Option<T> {
        let mut guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        *guard = None;
        f();
        self.wait_for_value(guard, dur)
    }

    /// 阻塞等待值到来或超时（调用前需自行 clear）。
    pub(crate) fn recv_timeout(&self, dur: Duration) -> Option<T> {
        let guard = match self.mutex.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        self.wait_for_value(guard, dur)
    }
}

pub(crate) fn send_command(
    sender: &Sender<HostToAgentMessage>,
    cmd: impl Into<String>,
) -> Result<(), std::sync::mpsc::SendError<HostToAgentMessage>> {
    sender.send(HostToAgentMessage::Command(cmd.into()))
}

#[cfg(feature = "qbdi")]
pub(crate) fn send_qbdi_helper(
    sender: &Sender<HostToAgentMessage>,
    blob: Vec<u8>,
) -> Result<(), std::sync::mpsc::SendError<HostToAgentMessage>> {
    sender.send(HostToAgentMessage::QbdiHelper(blob))
}

fn write_frame(stream: &mut dyn Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("frame payload exceeds {} bytes", MAX_FRAME_PAYLOAD_BYTES),
        ));
    }
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
}

pub(crate) fn read_frame(reader: &mut dyn Read) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME_PAYLOAD_BYTES {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("frame payload exceeds {} bytes", MAX_FRAME_PAYLOAD_BYTES),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// Queue agent output while the TCP client is still waiting for its textual
/// bootstrap response, then forward it through the single relay writer. This
/// keeps text and binary traffic from interleaving on the same stream.
fn forward_agent_frame(session: &Session, kind: u8, payload: &[u8]) {
    let mut relay = session.relay.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(writer) = relay.writer.as_mut() {
        if let Err(e) = write_frame(writer, kind, payload) {
            log_info!("[#{}] TCP relay closed: {}", session.id, e);
            relay.writer = None;
            relay.pending.clear();
            relay.pending_bytes = 0;
            relay.queue_enabled = false;
        }
        return;
    }

    if !relay.queue_enabled {
        return;
    }

    let frame_bytes = payload.len().saturating_add(5);
    if frame_bytes > MAX_RELAY_BACKLOG_BYTES {
        log_warn!(
            "[#{}] bootstrap relay frame too large ({} bytes), discarded",
            session.id,
            frame_bytes
        );
        return;
    }
    while relay.pending_bytes.saturating_add(frame_bytes) > MAX_RELAY_BACKLOG_BYTES {
        match relay.pending.pop_front() {
            Some(frame) => {
                relay.pending_bytes = relay.pending_bytes.saturating_sub(frame.payload.len().saturating_add(5));
            }
            None => break,
        }
    }
    relay.pending_bytes = relay.pending_bytes.saturating_add(frame_bytes);
    relay.pending.push_back(PendingRelayFrame {
        kind,
        payload: payload.to_vec(),
    });
}

fn install_tcp_relay(stream: &TcpStream, session: &Session) -> io::Result<()> {
    let writer = Box::new(stream.try_clone()?);
    let mut relay = session.relay.lock().unwrap_or_else(|e| e.into_inner());
    relay.writer = Some(writer);
    relay.queue_enabled = false;

    while let Some(frame) = relay.pending.pop_front() {
        relay.pending_bytes = relay.pending_bytes.saturating_sub(frame.payload.len().saturating_add(5));
        let write_result = match relay.writer.as_mut() {
            Some(writer) => write_frame(writer, frame.kind, &frame.payload),
            None => break,
        };
        if let Err(e) = write_result {
            relay.writer = None;
            relay.pending.clear();
            relay.pending_bytes = 0;
            return Err(e);
        }
    }
    relay.pending_bytes = 0;
    Ok(())
}

fn handle_socket_connection(stream: UnixStream, session: Arc<Session>) {
    let mut reader = stream;

    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                // Keep TCP relay traffic independent from the socketpair
                // dispatcher. The frame is either queued during bootstrap or
                // emitted through the established client writer.
                forward_agent_frame(&session, kind, &payload);
                match kind {
                    FRAME_KIND_HELLO => {
                        if session.id == 0 {
                            log_success!("Agent 已连接");
                        } else {
                            log_success!("[#{}] Agent 已连接", session.id);
                        }
                        let stream_clone = match reader.try_clone() {
                            Ok(s) => s,
                            Err(e) => {
                                log_error!("clone stream 失败: {}", e);
                                return;
                            }
                        };
                        let session2 = session.clone();
                        thread::Builder::new()
                            .name("wwb-socktx".into())
                            .spawn(move || {
                                let mut stream_clone = stream_clone;
                                let (sd, rx) = channel();
                                match session2.sender.set(sd) {
                                    Ok(_) => {}
                                    Err(_) => {
                                        log_error!("[#{}] sender already set!", session2.id);
                                        return;
                                    }
                                }
                                session2.connected.store(true, Ordering::Release);
                                while let Ok(msg) = rx.recv() {
                                    let (kind, payload) = match msg {
                                        HostToAgentMessage::Command(cmd) => (FRAME_KIND_CMD, cmd.into_bytes()),
                                        #[cfg(feature = "qbdi")]
                                        HostToAgentMessage::QbdiHelper(blob) => (FRAME_KIND_QBDI_HELPER, blob),
                                    };
                                    if let Err(e) = write_frame(&mut stream_clone, kind, &payload) {
                                        log_error!("[#{}] stream 写入失败: {}", session2.id, e);
                                        session2.disconnected.store(true, Ordering::Release);
                                        break;
                                    }
                                }
                            })
                            .expect("spawn wwb-socktx thread");
                    }
                    FRAME_KIND_COMPLETE => {
                        let text = String::from_utf8(payload).unwrap_or_default();
                        let candidates: Vec<String> = if text.is_empty() {
                            vec![]
                        } else {
                            text.split('\t')
                                .map(|s| s.to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        };
                        session.complete_state.send(candidates);
                    }
                    FRAME_KIND_EVAL_OK => {
                        session
                            .eval_state
                            .send(Ok(String::from_utf8(payload).unwrap_or_default()));
                    }
                    FRAME_KIND_EVAL_ERR => {
                        session
                            .eval_state
                            .send(Err(String::from_utf8(payload).unwrap_or_default()));
                    }
                    FRAME_KIND_RPC_OK => {
                        session
                            .rpc_state
                            .send(Ok(String::from_utf8(payload).unwrap_or_default()));
                    }
                    FRAME_KIND_RPC_ERR => {
                        session
                            .rpc_state
                            .send(Err(String::from_utf8(payload).unwrap_or_default()));
                    }
                    FRAME_KIND_LOG => {
                        let msg = String::from_utf8(payload).unwrap_or_default();
                        let msg = msg.strip_suffix('\n').unwrap_or(&msg);
                        if !msg.is_empty() {
                            if session.id == 0 {
                                log_agent!("{}", msg);
                            } else {
                                crate::logger::stdout_line(
                                    &format!(
                                        "{}{} [agent#{}]{} {}",
                                        crate::logger::BOLD,
                                        crate::logger::MAGENTA,
                                        session.id,
                                        crate::logger::RESET,
                                        msg
                                    ),
                                    &format!("[agent#{}] {}", session.id, msg),
                                );
                            }
                        }
                    }
                    FRAME_KIND_BYE => {
                        session.disconnected.store(true, Ordering::Release);
                        break;
                    }
                    other => {
                        log_error!("未知 agent frame kind: {}", other);
                    }
                };
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if session.id == 0 {
                    // legacy 模式静默断连
                } else {
                    log_error!("[#{}] Agent 连接已断开", session.id);
                }
                session.disconnected.store(true, Ordering::Release);
                break;
            }
            Err(e)
                if session.shutdown_requested.load(Ordering::Acquire)
                    && matches!(
                        e.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::BrokenPipe
                            | ErrorKind::UnexpectedEof
                    ) =>
            {
                session.disconnected.store(true, Ordering::Release);
                break;
            }
            Err(e) => {
                log_error!("[#{}] 读取连接失败: {}", session.id, e);
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    log_error!("可能原因: 目标进程权限不足 / agent 崩溃 / SELinux 拦截");
                    log_error!("排查: dmesg | grep -i 'deny\\|avc'  或  logcat | grep -E 'FATAL|crash'");
                }
                session.disconnected.store(true, Ordering::Release);
                break;
            }
        }
    }
}

/// 包装 socketpair 的 host_fd 为 UnixStream，启动处理线程
pub(crate) fn start_socketpair_handler(host_fd: RawFd, session: Arc<Session>) -> JoinHandle<()> {
    let stream = unsafe { UnixStream::from_raw_fd(host_fd) };
    thread::Builder::new()
        .name("wwb-sockrx".into())
        .spawn(move || {
            handle_socket_connection(stream, session);
        })
        .expect("spawn wwb-sockrx thread")
}

/// 启动 TCP 中继：把主机端 rfclient 桥接到 agent 会话。
///
/// 双向数据流：
/// - 客户端发来的 CMD/QBDI 帧 → 经 `session.sender`（复用 socktx 写线程 → socketpair → agent）
/// - agent 帧 → 在 `handle_socket_connection` 中转发到 `session.relay`（本函数注册的 TCP 写端）
///
/// 读线程在 TCP 断开/错误时退出，然后调用 `on_disconnect` 回调（由 tcp_server 传入做清理）。
pub(crate) fn start_tcp_relay(
    stream: TcpStream,
    session: Arc<Session>,
    on_disconnect: Option<Box<dyn FnOnce() + Send>>,
) -> JoinHandle<()> {
    // Register the writer and flush frames that arrived while spawn/attach was
    // still producing its textual response. This is the same handshake barrier
    // used by frida-server's connection-owned transport.
    if let Err(e) = install_tcp_relay(&stream, &session) {
        log_info!("[#{}] TCP relay unavailable: {}", session.id, e);
    }

    thread::Builder::new()
        .name("wwb-tcpin".into())
        .spawn(move || {
            let mut stream = stream;
            loop {
                match read_frame(&mut stream) {
                    Ok((kind, payload)) => match kind {
                        FRAME_KIND_CMD => {
                            let requested = String::from_utf8_lossy(&payload).into_owned();
                            let cmd = if session.tcp_owned.load(Ordering::Acquire)
                                && requested.trim() == "shutdown"
                            {
                                // Never expose the unsafe full wxshadow release
                                // through the TCP control plane.
                                "detach".to_string()
                            } else {
                                requested
                            };
                            if let Some(sender) = session.get_sender() {
                                if let Err(e) = send_command(sender, cmd) {
                                    log_error!("[#{}] 转发命令失败: {}", session.id, e);
                                    break;
                                }
                            }
                        }
                        #[cfg(feature = "qbdi")]
                        FRAME_KIND_QBDI_HELPER => {
                            if let Some(sender) = session.get_sender() {
                                if let Err(e) = send_qbdi_helper(sender, payload) {
                                    log_error!("[#{}] 转发 QBDI helper 失败: {}", session.id, e);
                                    break;
                                }
                            }
                        }
                        _ => {}
                    },
                    Err(e) => {
                        log_info!("[#{}] TCP 客户端断开: {}", session.id, e);
                        break;
                    }
                }
            }
            session.clear_relay();
            if let Some(cb) = on_disconnect {
                cb();
            }
        })
        .expect("spawn wwb-tcpin thread")
}
