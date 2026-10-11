//! open_channel：由主机请求、在目标进程内发起 TCP 连接并双向中继。
//!
//! 语义对齐 frida 的 `open_channel`：主机说「帮我连 `127.0.0.1:8080`」，
//! 真正的 connect 发生在**目标进程所在的网络命名空间**里，于是主机无需
//! `adb forward` 就能访问 app 自己的本地服务。
//!
//! 帧格式（均在控制连接上复用，4B LE channel id 区分通道）：
//!
//! | 方向 | kind | 载荷 |
//! | --- | --- | --- |
//! | host→agent | `CHANNEL_OPEN`(6) | `4B id + 地址字符串`（id=0 表示请 agent 分配） |
//! | host→agent | `CHANNEL_DATA`(0x98) | `4B id + 原始字节` |
//! | host→agent | `CHANNEL_CLOSE`(0x99) | `4B id` |
//! | agent→host | `CHANNEL_OPENED`(0x9A) | `4B id + 1B status + 可选错误消息` |
//! | agent→host | `CHANNEL_DATA`(0x98) | `4B id + 原始字节` |
//! | agent→host | `CHANNEL_CLOSE`(0x99) | `4B id` |
//!
//! 关键约束：
//! - **connect 不能在 agent 主循环里同步做**（最长 5s 会卡住心跳/命令处理），
//!   因此 `CHANNEL_OPEN` 只在注册表里占位，连接交给独立线程。
//! - 中继线程必须在 agent 卸载前退出（自定义 linker 会 unmap agent 代码），
//!   因此 `shutdown_all()` 关闭全部 socket，读线程随即 EOF 退出。

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::communication;

/// host→agent：建立通道。
pub(crate) const FRAME_KIND_CHANNEL_OPEN: u8 = 6;
/// 双向：通道数据。
pub(crate) const FRAME_KIND_CHANNEL_DATA: u8 = 0x98;
/// 双向：通道关闭。
pub(crate) const FRAME_KIND_CHANNEL_CLOSE: u8 = 0x99;
/// agent→host：通道建立结果。
pub(crate) const FRAME_KIND_CHANNEL_OPENED: u8 = 0x9A;

const CONNECT_TIMEOUT_MS: u64 = 5_000;
/// 同时存在的通道上限（防止主机把目标进程的 fd 耗光）。
const MAX_CHANNELS: usize = 64;
/// 单次读出的字节数上限，避免单帧过大顶到主机的帧长上限。
const READ_CHUNK: usize = 32 * 1024;

/// OPENED 状态码。
const STATUS_OK: u8 = 0;
const STATUS_DUPLICATE: u8 = 1;
const STATUS_BAD_REQUEST: u8 = 2;
const STATUS_CONNECT_FAILED: u8 = 3;
const STATUS_TOO_MANY: u8 = 4;

struct Channel {
    /// 写端：host→agent 的 DATA 在此写入目标 socket。
    writer: Mutex<TcpStream>,
    #[allow(dead_code)]
    address: String,
    /// 保证 CHANNEL_CLOSE 只发一次（client 主动关 vs 对端 EOF 竞争）。
    close_sent: AtomicBool,
}

static CHANNELS: Mutex<Option<HashMap<u32, Arc<Channel>>>> = Mutex::new(None);
/// 占位集合：已接受 OPEN、连接尚在进行中的 id。
static PENDING: Mutex<Option<Vec<u32>>> = Mutex::new(None);
static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(1);
/// agent 正在退出：拒绝新建通道，已存在通道等待 shutdown_all 收尾。
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

fn with_channels<T>(f: impl FnOnce(&mut HashMap<u32, Arc<Channel>>) -> T) -> T {
    let mut guard = CHANNELS.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

fn with_pending<T>(f: impl FnOnce(&mut Vec<u32>) -> T) -> T {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(Vec::new))
}

/// 发送一个 channel 帧（帧写入在 communication 里对 GLOBAL_STREAM 加锁，保证原子）。
fn send_frame(kind: u8, channel_id: u32, body: &[u8]) {
    communication::write_channel_frame(kind, channel_id, body);
}

fn send_opened(channel_id: u32, status: u8, message: &str) {
    communication::write_channel_opened(channel_id, status, message);
}

/// 处理 `CHANNEL_OPEN`：占位 + 后台连接。
pub(crate) fn handle_open(payload: &[u8]) {
    if SHUTTING_DOWN.load(Ordering::Acquire) {
        return;
    }
    if payload.len() < 4 {
        return;
    }
    let requested = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let address = String::from_utf8_lossy(&payload[4..]).trim().to_string();
    if address.is_empty() {
        send_opened(requested, STATUS_BAD_REQUEST, "empty address");
        return;
    }

    // id=0 → 由 agent 分配；否则沿用主机给的 id（重复则拒绝）。
    let channel_id = if requested == 0 {
        NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed)
    } else {
        requested
    };

    let duplicate = with_channels(|map| map.contains_key(&channel_id)) || with_pending(|list| list.contains(&channel_id));
    if duplicate {
        send_opened(channel_id, STATUS_DUPLICATE, "channel id in use");
        return;
    }
    let too_many = with_channels(|map| map.len()) + with_pending(|list| list.len()) >= MAX_CHANNELS;
    if too_many {
        send_opened(channel_id, STATUS_TOO_MANY, "too many channels");
        return;
    }
    with_pending(|list| list.push(channel_id));

    let spawn = crate::raw_thread::spawn_detached(b"wwb-chan\0", move || {
        connect_and_serve(channel_id, address);
    });
    if let Err(e) = spawn {
        with_pending(|list| list.retain(|id| *id != channel_id));
        send_opened(channel_id, STATUS_CONNECT_FAILED, &format!("spawn failed: {}", e));
    }
}

/// 后台线程：连接目标地址，成功则注册通道并进入中继循环。
fn connect_and_serve(channel_id: u32, address: String) {
    let target = match address.to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => {
                with_pending(|list| list.retain(|id| *id != channel_id));
                send_opened(channel_id, STATUS_CONNECT_FAILED, "unresolved address");
                return;
            }
        },
        Err(e) => {
            with_pending(|list| list.retain(|id| *id != channel_id));
            send_opened(channel_id, STATUS_CONNECT_FAILED, &format!("resolve failed: {}", e));
            return;
        }
    };

    let stream = match TcpStream::connect_timeout(&target, Duration::from_millis(CONNECT_TIMEOUT_MS)) {
        Ok(s) => s,
        Err(e) => {
            with_pending(|list| list.retain(|id| *id != channel_id));
            send_opened(channel_id, STATUS_CONNECT_FAILED, &format!("connect failed: {}", e));
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    // 写超时是防呆：handle_data 在 agent 主循环线程上执行，若目标端不读数据，
    // write_all 会一直阻塞，导致心跳/命令全部停摆。限时后放弃该通道。
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let reader = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            with_pending(|list| list.retain(|id| *id != channel_id));
            send_opened(channel_id, STATUS_CONNECT_FAILED, &format!("clone failed: {}", e));
            return;
        }
    };

    let channel = Arc::new(Channel {
        writer: Mutex::new(stream),
        address: address.clone(),
        close_sent: AtomicBool::new(false),
    });
    with_pending(|list| list.retain(|id| *id != channel_id));
    with_channels(|map| map.insert(channel_id, channel.clone()));

    send_opened(channel_id, STATUS_OK, &address);

    relay_from_target(channel_id, reader, &channel);
}

/// 目标 → 主机方向：读 socket，逐块转成 CHANNEL_DATA；读尽则关闭并通知主机。
fn relay_from_target(channel_id: u32, mut reader: TcpStream, channel: &Arc<Channel>) {
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !with_channels(|map| map.contains_key(&channel_id)) {
                    // 主机已关闭该通道。
                    break;
                }
                send_frame(FRAME_KIND_CHANNEL_DATA, channel_id, &buf[..n]);
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    let _ = reader.shutdown(Shutdown::Both);
    if let Ok(mut w) = channel.writer.lock() {
        let _ = w.shutdown(Shutdown::Both);
    }
    // 通道可能已被 handle_close 摘除（此时它也已通知主机）。
    let removed = with_channels(|map| map.remove(&channel_id).is_some());
    if removed && !channel.close_sent.swap(true, Ordering::AcqRel) {
        send_frame(FRAME_KIND_CHANNEL_CLOSE, channel_id, b"eof");
    }
}

/// 处理 host→agent 的 `CHANNEL_DATA`。
pub(crate) fn handle_data(payload: &[u8]) {
    if payload.len() < 4 {
        return;
    }
    let channel_id = u32::from_le_bytes(payload[..4].try_into().unwrap());
    let body = &payload[4..];
    if body.is_empty() {
        return;
    }
    let channel = with_channels(|map| map.get(&channel_id).cloned());
    let Some(channel) = channel else { return };

    let mut writer = match channel.writer.lock() {
        Ok(w) => w,
        Err(e) => e.into_inner(),
    };
    // 目标端接收缓冲满时这里会阻塞，TCP 背压自然传导回主机 —— 比丢字节好。
    if writer.write_all(body).is_err() {
        drop(writer);
        handle_close(payload);
    }
}

/// 处理双方任一侧发起的 `CHANNEL_CLOSE`。
pub(crate) fn handle_close(payload: &[u8]) {
    if payload.len() < 4 {
        return;
    }
    let channel_id = u32::from_le_bytes(payload[..4].try_into().unwrap());
    with_pending(|list| list.retain(|id| *id != channel_id));

    let channel = with_channels(|map| map.remove(&channel_id));
    let Some(channel) = channel else { return };

    // 关掉 socket，读线程随即退出（它不会重复发 CLOSE，因为条目已被摘除）。
    if let Ok(writer) = channel.writer.lock() {
        let _ = writer.shutdown(Shutdown::Both);
    }
}

/// 关闭全部通道（agent 卸载/退出前调用），并阻止后续新建。
pub(crate) fn shutdown_all() {
    SHUTTING_DOWN.store(true, Ordering::Release);
    with_pending(|list| list.clear());
    let channels: Vec<(u32, Arc<Channel>)> = with_channels(|map| {
        let drained: Vec<(u32, Arc<Channel>)> = map.iter().map(|(id, ch)| (*id, ch.clone())).collect();
        map.clear();
        drained
    });
    for (_, channel) in channels {
        if let Ok(writer) = channel.writer.lock() {
            let _ = writer.shutdown(Shutdown::Both);
        }
    }
}

/// 当前通道数（`status` 类命令用）。
pub(crate) fn active_count() -> usize {
    with_channels(|map| map.len()) + with_pending(|list| list.len())
}

/// 判定帧类型是否属于 channel 协议。
pub(crate) fn is_channel_frame(kind: u8) -> bool {
    matches!(
        kind,
        FRAME_KIND_CHANNEL_OPEN | FRAME_KIND_CHANNEL_DATA | FRAME_KIND_CHANNEL_CLOSE
    )
}

/// 分发 host→agent 的 channel 帧。
pub(crate) fn handle_frame(kind: u8, payload: &[u8]) {
    match kind {
        FRAME_KIND_CHANNEL_OPEN => handle_open(payload),
        FRAME_KIND_CHANNEL_DATA => handle_data(payload),
        FRAME_KIND_CHANNEL_CLOSE => handle_close(payload),
        _ => {}
    }
}
