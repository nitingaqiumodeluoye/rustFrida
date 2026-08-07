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

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;
const FRAME_KIND_BYE: u8 = 0x87;

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages.
/// 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 直接走此 stream。
pub static GLOBAL_STREAM: Mutex<Option<UnixStream>> = Mutex::new(None);
pub static GLOBAL_STREAM_FD: AtomicI32 = AtomicI32::new(-1);

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
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
    let _ = write_frame(stream, FRAME_KIND_HELLO, &[]);
}

pub(crate) fn send_complete(text: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_COMPLETE, text.as_bytes());
}

pub(crate) fn send_eval_ok(text: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_EVAL_OK, text.as_bytes());
}

pub(crate) fn send_eval_err(text: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_EVAL_ERR, text.as_bytes());
}

pub(crate) fn send_rpc_ok(text: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_RPC_OK, text.as_bytes());
}

pub(crate) fn send_rpc_err(text: &str) {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_RPC_ERR, text.as_bytes());
}

pub(crate) fn send_bye() {
    let mut stream = GLOBAL_STREAM.lock().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = stream.as_mut() else { return };
    let _ = write_frame(stream, FRAME_KIND_BYE, &[]);
}

pub(crate) fn is_cmd_frame(kind: u8) -> bool {
    kind == FRAME_KIND_CMD
}

pub(crate) fn is_qbdi_helper_frame(kind: u8) -> bool {
    kind == FRAME_KIND_QBDI_HELPER
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
