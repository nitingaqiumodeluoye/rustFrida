//! 本地端口转发（open_channel 的客户端侧）。
//!
//! `forward 8080 127.0.0.1:8080` 在本机监听 127.0.0.1:8080，每来一个连接就向
//! **目标进程**发一个 `CHANNEL_OPEN`，由 agent 在目标进程的网络命名空间里 connect
//! 到给定地址并双向中继字节。于是无需 `adb forward` 就能访问 app 自己的本地服务
//! （例如 app 内嵌的 HTTP 调试端口）。
//!
//! 数据流：
//! ```text
//! 本机应用 → 127.0.0.1:8080 → rfclient ──CHANNEL_DATA──▶ agent → 目标 app 端口
//! ```
//!
//! 关键顺序约束：**必须等 `CHANNEL_OPENED(status=0)` 才能开始读本地 socket**。
//! agent 侧 connect 在独立线程里完成，OPENED 之前到达的 DATA 会被丢弃（通道 id 未就绪），
//! 所以提前泵数据会静默丢掉开头几个字节。

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::proto::*;

const LOCAL_BIND_ADDR: &str = "127.0.0.1";
const READ_CHUNK: usize = 32 * 1024;

/// 一个已建立（或正在建立）的通道。
struct LocalConn {
    socket: Mutex<TcpStream>,
    /// OPENED 之后才开始读本地 socket（见模块头注释）。
    started: AtomicBool,
    closed: AtomicBool,
    /// 这条通道属于哪个本地监听端口，用于 `forwards` 展示与 `unforward` 清理。
    local_port: u16,
    remote: String,
}

impl LocalConn {
    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(socket) = self.socket.lock() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

struct ListenerHandle {
    local_port: u16,
    remote: String,
    stop: Arc<AtomicBool>,
}

/// 端口转发集合：本地监听器 + 活跃通道。
pub struct Channels {
    writer: Arc<Mutex<TcpStream>>,
    conns: Arc<Mutex<HashMap<u32, Arc<LocalConn>>>>,
    listeners: Arc<Mutex<HashMap<u16, Arc<ListenerHandle>>>>,
    next_id: Arc<AtomicU32>,
}

impl Channels {
    pub fn new(writer: Arc<Mutex<TcpStream>>) -> Self {
        Channels {
            writer,
            conns: Arc::new(Mutex::new(HashMap::new())),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// 启动监听：`forward <local_port> <remote>`。
    pub fn forward(&self, local_port: u16, remote: &str) -> Result<String, String> {
        let remote = normalize_remote(remote);
        {
            let listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
            if listeners.contains_key(&local_port) {
                return Err(format!(
                    "本地端口 {} 已在转发中（先 unforward {}）",
                    local_port, local_port
                ));
            }
        }

        let listener = TcpListener::bind((LOCAL_BIND_ADDR, local_port))
            .map_err(|e| format!("监听 {}:{} 失败: {}", LOCAL_BIND_ADDR, local_port, e))?;
        let bound_port = listener.local_addr().map(|a| a.port()).unwrap_or(local_port);
        let stop = Arc::new(AtomicBool::new(false));
        self.listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                bound_port,
                Arc::new(ListenerHandle {
                    local_port: bound_port,
                    remote: remote.clone(),
                    stop: stop.clone(),
                }),
            );

        let writer = self.writer.clone();
        let conns = self.conns.clone();
        let next_id = self.next_id.clone();
        let remote_for_thread = remote.clone();
        thread::Builder::new()
            .name("rf-fwd".into())
            .spawn(move || {
                for accepted in listener.incoming() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(socket) = accepted else { continue };
                    let _ = socket.set_nodelay(true);
                    let id = allocate_id(&next_id);
                    let conn = Arc::new(LocalConn {
                        socket: Mutex::new(socket),
                        started: AtomicBool::new(false),
                        closed: AtomicBool::new(false),
                        local_port: bound_port,
                        remote: remote_for_thread.clone(),
                    });
                    conns.lock().unwrap_or_else(|e| e.into_inner()).insert(id, conn.clone());
                    // 向目标进程发起连接；等 OPENED 回来才开闸放数据。
                    let opened = {
                        let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                        write_channel_open(&mut *w, id, &remote_for_thread)
                    };
                    if let Err(e) = opened {
                        conn.shutdown();
                        conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                        crate::repl::print_line(&format!(
                            "[forward] 发送 channel open 失败 (端口 {}): {}",
                            bound_port, e
                        ));
                    }
                }
            })
            .map_err(|e| format!("启动转发线程失败: {}", e))?;

        Ok(format!(
            "转发已启动: {}:{} -> {}（在目标进程内连接）",
            LOCAL_BIND_ADDR, bound_port, remote
        ))
    }

    /// 停止某个本地端口的转发。
    pub fn unforward(&self, local_port: u16) -> String {
        let handle = self
            .listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&local_port);
        let Some(handle) = handle else {
            return format!("端口 {} 没有正在进行的转发", local_port);
        };
        handle.stop.store(true, Ordering::Release);
        // 叫醒阻塞在 accept 上的监听线程：连一次自己。
        let _ = TcpStream::connect((LOCAL_BIND_ADDR, handle.local_port));

        let mut closed = 0usize;
        let mut ids: Vec<u32> = Vec::new();
        {
            let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
            for (id, conn) in conns.iter() {
                if conn.local_port == local_port {
                    conn.shutdown();
                    ids.push(*id);
                }
            }
            for id in &ids {
                conns.remove(id);
            }
        }
        for id in &ids {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write_channel_close(&mut *w, *id);
            closed += 1;
        }
        format!(
            "已停止转发 {}:{}（关闭 {} 个连接）",
            LOCAL_BIND_ADDR, local_port, closed
        )
    }

    /// `forwards` 列表。
    pub fn list(&self) -> String {
        let listeners = self.listeners.lock().unwrap_or_else(|e| e.into_inner());
        if listeners.is_empty() {
            return "没有正在进行的端口转发".to_string();
        }
        let conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        let mut ports: Vec<&Arc<ListenerHandle>> = listeners.values().collect();
        ports.sort_by_key(|l| l.local_port);
        let mut out = String::from("本地转发：\n");
        for l in ports {
            let active = conns.values().filter(|c| c.local_port == l.local_port).count();
            out.push_str(&format!(
                "  {}:{} -> {}（活跃连接 {}）\n",
                LOCAL_BIND_ADDR, l.local_port, l.remote, active
            ));
        }
        out.trim_end().to_string()
    }

    // ── agent → 本机 的帧路由（由接收线程调用） ──

    pub fn on_opened(&self, channel_id: u32, status: u8, message: &str) {
        let conn = self
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&channel_id)
            .cloned();
        let Some(conn) = conn else { return };
        if status != 0 {
            crate::repl::print_line(&format!(
                "[forward] 目标进程连接失败 ({}): {}（状态码 {}）",
                conn.remote,
                if message.is_empty() { "无详细信息" } else { message },
                status
            ));
            conn.shutdown();
            self.conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&channel_id);
            return;
        }
        if conn.started.swap(true, Ordering::AcqRel) {
            return;
        }

        // 开闸：本地 → 目标进程方向的数据泵。
        let socket = match conn.socket.lock() {
            Ok(s) => match s.try_clone() {
                Ok(c) => c,
                Err(e) => {
                    crate::repl::print_line(&format!("[forward] clone 本地 socket 失败: {}", e));
                    return;
                }
            },
            Err(e) => match e.into_inner().try_clone() {
                Ok(c) => c,
                Err(_) => return,
            },
        };

        let writer = self.writer.clone();
        let conns = self.conns.clone();
        let stop = self
            .listeners
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&conn.local_port)
            .map(|l| l.stop.clone());
        let _ = thread::Builder::new().name("rf-fwd-up".into()).spawn(move || {
            let mut socket = socket;
            let mut buf = vec![0u8; READ_CHUNK];
            loop {
                if let Some(stop) = stop.as_ref() {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                }
                match socket.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let sent = {
                            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                            write_channel_data(&mut *w, channel_id, &buf[..n])
                        };
                        if sent.is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&channel_id);
            let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write_channel_close(&mut *w, channel_id);
        });
    }

    pub fn on_data(&self, channel_id: u32, body: &[u8]) {
        let conn = self
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&channel_id)
            .cloned();
        let Some(conn) = conn else { return };
        if let Ok(mut socket) = conn.socket.lock() {
            if socket.write_all(body).is_err() {
                drop(socket);
                conn.shutdown();
                self.conns
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&channel_id);
            }
        };
    }

    pub fn on_close(&self, channel_id: u32) {
        let conn = self
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&channel_id);
        if let Some(conn) = conn {
            conn.shutdown();
        }
    }

    /// 连接断开时清空所有转发状态。
    pub fn shutdown_all(&self) {
        for (_, handle) in self.listeners.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            handle.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect((LOCAL_BIND_ADDR, handle.local_port));
        }
        for (_, conn) in self.conns.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            conn.shutdown();
        }
    }
}

fn allocate_id(next_id: &AtomicU32) -> u32 {
    // 0 保留给「由 agent 分配」的语义，跳过往回绕。
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        next_id.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

/// `8080` → `127.0.0.1:8080`；已带主机名/端口则原样返回。
pub fn normalize_remote(remote: &str) -> String {
    let trimmed = remote.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let bare_port = !trimmed.contains(':') && trimmed.chars().all(|c| c.is_ascii_digit());
    if bare_port {
        format!("127.0.0.1:{}", trimmed)
    } else {
        trimmed.to_string()
    }
}
