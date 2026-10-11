//! agent 端 socket 通信模块
//!
//! 日志消息 (FRAME_KIND_LOG) 通过非阻塞 socket 写发送，拿不到锁时直接丢弃，
//! 避免为日志保留后台线程影响自定义 linker 卸载。
//! 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 仍走同步路径（低频且需要保序）。

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

const FRAME_KIND_CMD: u8 = 1;
const FRAME_KIND_QBDI_HELPER: u8 = 2;
/// 主机→agent：`4B LE reqid + 命令文本`。agent 对响应帧回填同一 reqid，
/// 使主机端可以并发发出多条命令并按 reqid 匹配响应（协议 v2）。
const FRAME_KIND_CMD_TAGGED: u8 = 4;
/// 主机→agent 的链路保活探测。agent 直接回 PONG，不进入命令分发。
const FRAME_KIND_PING: u8 = 5;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;
const FRAME_KIND_BYE: u8 = 0x87;

/// agent→host：链路保活探测的应答。
const FRAME_KIND_PONG: u8 = 0x97;

/// 协议 v2 tagged 响应帧：`4B LE reqid + 载荷`，kind 语义与对应无 tag 帧一致。
const FRAME_KIND_EVAL_OK_TAGGED: u8 = 0x90;
const FRAME_KIND_EVAL_ERR_TAGGED: u8 = 0x91;
const FRAME_KIND_RPC_OK_TAGGED: u8 = 0x92;
const FRAME_KIND_RPC_ERR_TAGGED: u8 = 0x93;
const FRAME_KIND_COMPLETE_TAGGED: u8 = 0x94;

/// HELLO 帧载荷：宣告本 agent 支持的协议版本。
const HELLO_PAYLOAD: &[u8] = b"proto=2";

thread_local! {
    /// 当前线程正在处理的请求 ID。0 = 无 tag（设备端本地 REPL / 服务内部命令）。
    /// send_eval_ok / send_rpc_ok 等据此选择 tagged 或 legacy 帧。
    /// dispatch_js_task 会在新线程开头继承该值。
    static CURRENT_REQID: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// 读取当前线程的请求 ID（无 tag 时为 0）。
pub(crate) fn current_reqid() -> u32 {
    CURRENT_REQID.with(|c| c.get())
}

/// 设置当前线程的请求 ID（进入命令处理前调用，处理完恢复 0）。
pub(crate) fn set_current_reqid(id: u32) {
    CURRENT_REQID.with(|c| c.set(id));
}

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
}

/// 按 CURRENT_REQID 发送 eval/rpc/complete 响应：
/// reqid != 0 → tagged 帧（4B LE reqid + 载荷）；reqid == 0 → legacy 帧。
fn send_response_frame(untagged: u8, tagged: u8, payload: &[u8]) {
    let reqid = current_reqid();
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = if reqid == 0 {
        write_frame(stream, untagged, payload)
    } else {
        let mut body = Vec::with_capacity(4 + payload.len());
        body.extend_from_slice(&reqid.to_le_bytes());
        body.extend_from_slice(payload);
        write_frame(stream, tagged, &body)
    };
}

pub(crate) fn read_frame(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// 保留调用点但不创建后台线程；agent 卸载前不能留下仍在执行 agent 代码的线程。
pub(crate) fn start_log_writer() {}

/// 非阻塞写日志：控制消息持锁或 socket 短时不可写时直接丢弃日志。
pub(crate) fn write_stream(data: &[u8]) {
    let mut stream = match GLOBAL_STREAM.try_lock() {
        Ok(s) => s,
        Err(std::sync::TryLockError::WouldBlock) => return,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
    };
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_LOG, data);
}

pub(crate) fn write_stream_sync(data: &[u8]) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_LOG, data);
}

pub(crate) fn shutdown_log_writer() {}

/// 直接通过原始 fd 写 socket，供崩溃处理等场景使用。
pub(crate) fn write_stream_raw(data: &[u8]) {
    let fd = GLOBAL_STREAM_FD.load(Ordering::Acquire);
    if fd >= 0 {
        let mut header = [0u8; 5];
        header[0] = FRAME_KIND_LOG;
        header[1..].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let _ = unsafe { libc::write(fd, header.as_ptr() as *const libc::c_void, header.len()) };
        let mut offset = 0usize;
        while offset < data.len() {
            let wrote =
                unsafe { libc::write(fd, data[offset..].as_ptr() as *const libc::c_void, data.len() - offset) };
            if wrote <= 0 {
                break;
            }
            offset += wrote as usize;
        }
    }
}

pub(crate) fn send_hello() {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_HELLO, HELLO_PAYLOAD);
}

pub(crate) fn send_complete(text: &str) {
    send_response_frame(FRAME_KIND_COMPLETE, FRAME_KIND_COMPLETE_TAGGED, text.as_bytes());
}

pub(crate) fn send_eval_ok(text: &str) {
    send_response_frame(FRAME_KIND_EVAL_OK, FRAME_KIND_EVAL_OK_TAGGED, text.as_bytes());
}

pub(crate) fn send_eval_err(text: &str) {
    send_response_frame(FRAME_KIND_EVAL_ERR, FRAME_KIND_EVAL_ERR_TAGGED, text.as_bytes());
}

pub(crate) fn send_rpc_ok(text: &str) {
    send_response_frame(FRAME_KIND_RPC_OK, FRAME_KIND_RPC_OK_TAGGED, text.as_bytes());
}

pub(crate) fn send_rpc_err(text: &str) {
    send_response_frame(FRAME_KIND_RPC_ERR, FRAME_KIND_RPC_ERR_TAGGED, text.as_bytes());
}

/// 回复链路保活探测（直接写，不经过响应帧路由）。
pub(crate) fn send_pong() {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_PONG, &[]);
}

pub(crate) fn send_bye() {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_BYE, &[]);
}

/// 写一个 `4B LE channel_id + body` 的帧（open_channel 用）。
///
/// 用**阻塞**锁（不是 `write_stream` 的 try_lock）：通道数据丢一个字节就全错了，
/// 宁可让 TCP 背压传导回主机。
pub(crate) fn write_channel_frame(kind: u8, channel_id: u32, body: &[u8]) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let mut payload = Vec::with_capacity(4 + body.len());
    payload.extend_from_slice(&channel_id.to_le_bytes());
    payload.extend_from_slice(body);
    let _ = write_frame(stream, kind, &payload);
}

/// 写 `CHANNEL_OPENED`：`4B LE channel_id + 1B status + 可选消息`。
pub(crate) fn write_channel_opened(channel_id: u32, status: u8, message: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let bytes = message.as_bytes();
    let mut payload = Vec::with_capacity(5 + bytes.len());
    payload.extend_from_slice(&channel_id.to_le_bytes());
    payload.push(status);
    payload.extend_from_slice(bytes);
    let _ = write_frame(stream, crate::channel::FRAME_KIND_CHANNEL_OPENED, &payload);
}

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages.
/// 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 直接走此 stream。
pub static GLOBAL_STREAM: Mutex<Option<UnixStream>> = Mutex::new(None);
pub static GLOBAL_STREAM_FD: AtomicI32 = AtomicI32::new(-1);

pub(crate) fn is_cmd_frame(kind: u8) -> bool {
    kind == FRAME_KIND_CMD || kind == FRAME_KIND_CMD_TAGGED
}

/// 判断 CMD 帧是否带 reqid 前缀，并拆出 (reqid, 命令文本)。
pub(crate) fn parse_cmd_frame(kind: u8, payload: &[u8]) -> (u32, &[u8]) {
    if kind == FRAME_KIND_CMD_TAGGED && payload.len() >= 4 {
        let reqid = u32::from_le_bytes(payload[..4].try_into().unwrap());
        (reqid, &payload[4..])
    } else {
        (0, payload)
    }
}

pub(crate) fn is_qbdi_helper_frame(kind: u8) -> bool {
    kind == FRAME_KIND_QBDI_HELPER
}

pub(crate) fn is_ping_frame(kind: u8) -> bool {
    kind == FRAME_KIND_PING
}

pub(crate) static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，连接后走非阻塞 socket 写
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if stream_is_registered() {
        write_stream(prefixed.as_bytes());
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push(prefixed);
        }
    }
}

pub(crate) fn log_msg_sync(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if stream_is_registered() {
        write_stream_sync(prefixed.as_bytes());
    } else if let Ok(mut cache) = CACHE_LOG.lock() {
        cache.push(prefixed);
    }
}

/// 关闭 socket 写端。用 SHUT_WR 保留已排队的 LOG/BYE frame，避免 host 读到 reset。
pub(crate) fn shutdown_stream() {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stream) = stream.as_mut() {
        let _ = stream.flush();
        unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_WR) };
    }
}

pub(crate) fn register_stream(stream: UnixStream) {
    GLOBAL_STREAM_FD.store(stream.as_raw_fd(), Ordering::Release);
    *GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner()) = Some(stream);
}

pub(crate) fn clear_stream() {
    *GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner()) = None;
    GLOBAL_STREAM_FD.store(-1, Ordering::Release);
}

fn stream_is_registered() -> bool {
    GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if stream_is_registered() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                write_stream(msg.as_bytes());
            }
        }
    }
}
