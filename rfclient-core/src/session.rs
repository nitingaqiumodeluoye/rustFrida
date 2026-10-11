//! 会话：持有控制连接，负责帧收发、reqid 应答匹配、心跳保活、通道路由。
//!
//! 上层（CLI / GUI）只做两件事：
//! 1. `connect()` 拿到 `(Session, Receiver<Event>)` —— 事件流自己排空；
//! 2. `send()` 发命令，从返回的 [`Pending`] 里取应答（阻塞或轮询都行）。
//!
//! 本模块**不做任何终端输出**，也不结束进程：连接断开的处置权交给上层
//! （CLI 需要 `exit()` 以免死在 readline 上，GUI 则只需改状态栏）。

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::channel::Channels;
use crate::event::{ChannelOpened, Disconnect, Event};
use crate::proto::*;

/// 心跳探测间隔：空闲时定期发 PING。
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// 心跳超时：超过该时长未收到任何入站帧，判定链路半开。
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 45;
/// 等待 agent HELLO（协议版本协商）的默认最长时间。
pub const HELLO_WAIT_MILLIS: u64 = 1500;

/// 应答通道类型：eval / rpc 分属两条通道，tagged 模式下按 reqid 匹配。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplyKind {
    Eval,
    Rpc,
}

/// 一次请求的应答结果。
///
/// 用枚举而不是 `Result<_, String>`：超时与「服务端回了个错误」是两回事，
/// 上层（尤其 GUI）需要区分（前者是链路问题，后者是命令问题）。
#[derive(Debug, Clone)]
pub enum Reply {
    Ok(String),
    Err(String),
    Timeout,
}

/// 已发出、等待应答的请求。
///
/// 两种取用方式都支持，互斥使用即可：
/// - [`Pending::wait`]：阻塞到应答或超时（CLI 用）；
/// - [`Pending::try_take`]：非阻塞轮询（GUI 每帧调一次）。
pub struct Pending {
    pub reqid: u32,
    rx: Receiver<Result<String, String>>,
}

impl Pending {
    /// 阻塞等待应答。
    ///
    /// 注意：等待期间**不会**消费事件流，因此调用方若在等应答，
    /// 事件（日志）应由另一个线程排空 —— 否则日志会积压到应答之后才显示。
    pub fn wait(&self, timeout: Duration) -> Reply {
        match self.rx.recv_timeout(timeout) {
            Ok(Ok(text)) => Reply::Ok(text),
            Ok(Err(e)) => Reply::Err(e),
            Err(_) => Reply::Timeout,
        }
    }

    /// 非阻塞取应答；`None` 表示还没到。
    pub fn try_take(&self) -> Option<Reply> {
        match self.rx.try_recv() {
            Ok(Ok(text)) => Some(Reply::Ok(text)),
            Ok(Err(e)) => Some(Reply::Err(e)),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            // 发送端已销毁（请求被注销）→ 视为已结束，避免调用方永久轮询。
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Reply::Timeout),
        }
    }
}

/// 挂起请求表：reqid(或 legacy 的 0) → 响应投递通道。
struct Registry {
    map: Mutex<HashMap<u32, (ReplyKind, SyncSender<Result<String, String>>)>>,
    next_id: AtomicU32,
}

impl Registry {
    fn new() -> Self {
        Registry {
            map: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        }
    }

    /// 分配一个新 reqid（v2），并注册等待者。
    fn register(&self, kind: ReplyKind, reqid: u32) -> Receiver<Result<String, String>> {
        let (tx, rx) = sync_channel(1);
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(reqid, (kind, tx));
        rx
    }

    fn next_reqid(&self) -> u32 {
        // 0 保留给 legacy 语义，跳过回绕后的 0
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if id == 0 {
            self.next_id.fetch_add(1, Ordering::Relaxed)
        } else {
            id
        }
    }

    fn deregister(&self, reqid: u32) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).remove(&reqid);
    }

    /// 投递响应；返回 false 表示没有等待者（老响应/未知 reqid）。
    fn deliver(&self, reqid: u32, expected: ReplyKind, result: Result<String, String>) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&reqid) {
            Some((kind, _)) if *kind == expected => match map.remove(&reqid) {
                Some((_, tx)) => tx.send(result).is_ok(),
                None => false,
            },
            // 类型不匹配：保留挂起项，交由后续正确的响应帧处理
            Some(_) => false,
            None => false,
        }
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 一个已建立的控制会话。
///
/// 生命周期：`connect()` 起两个后台线程（帧读取 + 心跳），
/// `Reader` 线程在连接结束时投递 [`Event::Disconnected`] 后自行退出。
pub struct Session {
    writer: Arc<Mutex<TcpStream>>,
    registry: Arc<Registry>,
    channels: Arc<Channels>,
    disconnected: Arc<AtomicBool>,
    proto_v2: Arc<AtomicBool>,
    hello_seen: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
}

impl Session {
    /// 接管一条已连接且已完成引导握手的 TCP 流。
    ///
    /// `proto_hint` 是引导 OK 行里服务端宣告的 agent 协议版本（`proto=N`）：
    /// `Some(2)` 直接启用 v2，不依赖 HELLO 到达时机；`None`（旧服务端）
    /// 则等 HELLO 或退回 legacy 语义。
    ///
    /// 返回事件流接收端，由调用方排空（见模块头注释）。
    pub fn connect(stream: TcpStream, proto_hint: Option<u32>) -> Result<(Self, Receiver<Event>), String> {
        // 清除读/写超时：中继后 agent 可能长时间无输出（日志/交互），
        // 不能被引导阶段设置的超时打断。
        let _ = stream.set_read_timeout(None);
        let _ = stream.set_write_timeout(None);

        let reader = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;
        let writer = Arc::new(Mutex::new(
            stream.try_clone().map_err(|e| format!("clone stream: {}", e))?,
        ));

        let registry = Arc::new(Registry::new());
        let (event_tx, event_rx) = channel::<Event>();
        let disconnected = Arc::new(AtomicBool::new(false));
        let proto_v2 = Arc::new(AtomicBool::new(false));
        let hello_seen = Arc::new(AtomicBool::new(false));
        let last_activity = Arc::new(AtomicU64::new(now_millis()));

        // 通道（端口转发）需要 writer 回写帧、需要 event_tx 上报错误。
        let channels = Arc::new(Channels::new(writer.clone(), event_tx.clone()));

        if proto_hint == Some(2) {
            proto_v2.store(true, Ordering::Release);
            hello_seen.store(true, Ordering::Release);
        }

        let session = Session {
            writer,
            registry: registry.clone(),
            channels: channels.clone(),
            disconnected: disconnected.clone(),
            proto_v2: proto_v2.clone(),
            hello_seen: hello_seen.clone(),
            last_activity: last_activity.clone(),
        };

        // 帧读取线程
        {
            let ctx = ReadContext {
                registry,
                channels,
                events: event_tx.clone(),
                disconnected: disconnected.clone(),
                proto_v2: proto_v2.clone(),
                hello_seen: hello_seen.clone(),
                last_activity: last_activity.clone(),
            };
            thread::Builder::new()
                .name("rf-recv".into())
                .spawn(move || read_loop(reader, ctx))
                .map_err(|e| format!("spawn recv thread: {}", e))?;
        }

        // 心跳线程：空闲时发 PING，长时间无入站帧则判定链路半开。
        {
            let writer = session.writer.clone();
            let events = event_tx;
            let disconnected = disconnected.clone();
            let last_activity = last_activity.clone();
            thread::Builder::new()
                .name("rf-ping".into())
                .spawn(move || heartbeat_loop(writer, events, disconnected, last_activity))
                .map_err(|e| format!("spawn heartbeat thread: {}", e))?;
        }

        Ok((session, event_rx))
    }

    /// 是否已启用协议 v2（reqid 匹配 + 心跳）。
    pub fn proto_v2(&self) -> bool {
        self.proto_v2.load(Ordering::Acquire)
    }

    /// 对端是否已关闭连接。
    pub fn is_disconnected(&self) -> bool {
        self.disconnected.load(Ordering::Acquire)
    }

    /// 端口转发接口。
    pub fn channels(&self) -> &Arc<Channels> {
        &self.channels
    }

    /// 最近一次收到任何入站帧的时刻（毫秒，单调递增即可比较）。
    ///
    /// 用途：上层若要在「空闲等待」里判断链路是否还有活动（CLI 的 EOF linger
    /// 就是这样），轮询这个值即可，不必再为活动信号开一条通道。
    pub fn last_activity_millis(&self) -> u64 {
        self.last_activity.load(Ordering::Acquire)
    }

    /// 阻塞等待 HELLO（或 `proto_hint` 已定案），返回是否启用 v2。
    ///
    /// 引导 OK 行已宣告 proto 时立即返回；否则最多等 `timeout`
    /// （旧服务端不发 HELLO，等满即退回 legacy）。
    pub fn wait_for_hello(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.hello_seen.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        self.proto_v2()
    }

    /// 发送命令并等待应答（见返回的 [`Pending`]）。
    ///
    /// v2 下用 `CMD_TAGGED` 携带新 reqid；legacy 下 reqid 恒为 0
    /// （单槽语义，与旧服务端一致）。
    pub fn send(&self, cmd: &str, kind: ReplyKind) -> Result<Pending, String> {
        let reqid = if self.proto_v2() { self.registry.next_reqid() } else { 0 };
        let rx = self.registry.register(kind, reqid);
        let write_result = {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            if self.proto_v2() {
                write_tagged_cmd(&mut *w, reqid, cmd)
            } else {
                write_frame(&mut *w, FRAME_KIND_CMD, cmd.as_bytes())
            }
        };
        if let Err(e) = write_result {
            self.registry.deregister(reqid);
            return Err(format!("发送失败: {}", e));
        }
        Ok(Pending { reqid, rx })
    }

    /// 发送不期待应答的命令（`trace` / `stalker` / `detach` 等只产生 LOG 帧）。
    ///
    /// 目的与 [`Session::send`] 相同但立即注销占位，避免 stale 表项堆积。
    pub fn send_no_reply(&self, cmd: &str) -> Result<(), String> {
        let pending = self.send(cmd, ReplyKind::Eval)?;
        self.registry.deregister(pending.reqid);
        Ok(())
    }

    /// 发送链路保活探测。
    pub fn ping(&self) -> Result<(), String> {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        write_ping(&mut *w).map_err(|e| format!("发送 PING 失败: {}", e))
    }

    /// 关闭全部端口转发并释放本地监听。
    pub fn shutdown_channels(&self) {
        self.channels.shutdown_all();
    }

    /// 主动断开控制连接（不发送 shutdown 命令，仅关 socket）。
    pub fn close(&self) {
        if let Ok(stream) = self.writer.lock() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// 在会话上直接写一帧（供引导阶段之后的自定义帧使用）。
    pub fn with_writer<T>(&self, f: impl FnOnce(&mut TcpStream) -> T) -> T {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut w)
    }
}

struct ReadContext {
    registry: Arc<Registry>,
    channels: Arc<Channels>,
    events: Sender<Event>,
    disconnected: Arc<AtomicBool>,
    proto_v2: Arc<AtomicBool>,
    hello_seen: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
}

/// 后台接收线程：读帧并按类型分流到应答表 / 事件流。
fn read_loop(mut reader: TcpStream, ctx: ReadContext) {
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                ctx.last_activity.store(now_millis(), Ordering::Release);
                match kind {
                    FRAME_KIND_LOG => {
                        let msg = String::from_utf8_lossy(&payload).into_owned();
                        let msg = msg.strip_suffix('\n').unwrap_or(&msg).to_string();
                        if !msg.is_empty() {
                            let _ = ctx.events.send(Event::Log(msg));
                        }
                    }
                    FRAME_KIND_HELLO => {
                        let hello = String::from_utf8_lossy(&payload);
                        let v2 = hello.contains("proto=2");
                        if v2 {
                            ctx.proto_v2.store(true, Ordering::Release);
                        }
                        ctx.hello_seen.store(true, Ordering::Release);
                        let _ = ctx.events.send(Event::Hello { proto_v2: v2 });
                    }
                    // 结构化事件帧（server 生成）：TSV，`type\tkey=value...`
                    FRAME_KIND_EVENT => {
                        let text = String::from_utf8_lossy(&payload).into_owned();
                        let mut fields = text.split('\t').filter(|f| !f.is_empty());
                        let ty = fields.next().unwrap_or("event").to_string();
                        let rest: Vec<String> = fields.map(|f| f.to_string()).collect();
                        let _ = ctx.events.send(Event::ServerEvent { ty, fields: rest });
                    }
                    // PONG 只用于保活（last_activity 已刷新）
                    FRAME_KIND_PONG => {
                        let _ = ctx.events.send(Event::Pong);
                    }
                    // ── open_channel：本地转发通道 ──
                    FRAME_KIND_CHANNEL_OPENED => {
                        if let Some((id, body)) = split_channel_payload(&payload) {
                            let status = body.first().copied().unwrap_or(1);
                            let message = String::from_utf8_lossy(body.get(1..).unwrap_or(&[])).into_owned();
                            let remote = ctx.channels.on_opened(id, status);
                            let _ = ctx.events.send(Event::ChannelOpened(ChannelOpened {
                                channel_id: id,
                                status,
                                message,
                                remote,
                            }));
                        }
                    }
                    FRAME_KIND_CHANNEL_DATA => {
                        if let Some((id, body)) = split_channel_payload(&payload) {
                            ctx.channels.on_data(id, body);
                            let _ = ctx.events.send(Event::ChannelData {
                                channel_id: id,
                                data: body.to_vec(),
                            });
                        }
                    }
                    FRAME_KIND_CHANNEL_CLOSE => {
                        if let Some((id, _)) = split_channel_payload(&payload) {
                            ctx.channels.on_close(id);
                            let _ = ctx.events.send(Event::ChannelClosed { channel_id: id });
                        }
                    }
                    // ── 协议 v2 tagged 响应：按 reqid 匹配 ──
                    FRAME_KIND_EVAL_OK_TAGGED
                    | FRAME_KIND_EVAL_ERR_TAGGED
                    | FRAME_KIND_RPC_OK_TAGGED
                    | FRAME_KIND_RPC_ERR_TAGGED
                    | FRAME_KIND_COMPLETE_TAGGED => {
                        let Some((reqid, body)) = split_tagged_payload(&payload) else {
                            let _ = ctx.events.send(Event::Log("收到截断的 tagged 响应帧，已丢弃".to_string()));
                            continue;
                        };
                        let text = String::from_utf8_lossy(body).into_owned();
                        deliver_tagged(&ctx, kind, reqid, text);
                    }
                    // ── legacy 响应：reqid 恒为 0 ──
                    FRAME_KIND_EVAL_OK => {
                        deliver_legacy(&ctx, ReplyKind::Eval, Ok(String::from_utf8_lossy(&payload).into_owned()));
                    }
                    FRAME_KIND_EVAL_ERR => {
                        deliver_legacy(&ctx, ReplyKind::Eval, Err(String::from_utf8_lossy(&payload).into_owned()));
                    }
                    FRAME_KIND_RPC_OK => {
                        deliver_legacy(&ctx, ReplyKind::Rpc, Ok(String::from_utf8_lossy(&payload).into_owned()));
                    }
                    FRAME_KIND_RPC_ERR => {
                        deliver_legacy(&ctx, ReplyKind::Rpc, Err(String::from_utf8_lossy(&payload).into_owned()));
                    }
                    // jscomplete 候选：TCP 下未启用动态补全
                    FRAME_KIND_COMPLETE => {}
                    FRAME_KIND_BYE => {
                        ctx.disconnected.store(true, Ordering::Release);
                        let _ = ctx.events.send(Event::Disconnected(Disconnect::Bye));
                        break;
                    }
                    other => {
                        let _ = ctx
                            .events
                            .send(Event::Log(format!("未知帧 kind: {}", other)));
                    }
                }
            }
            Err(e) => {
                ctx.disconnected.store(true, Ordering::Release);
                // 正常 EOF 与真错误都走这里：对端关闭时 read 返回 Ok(0) 被 read_frame
                // 转成 UnexpectedEof，语义上就是「连接结束」，不区分文案。
                let _ = ctx.events.send(Event::Disconnected(Disconnect::Io(e.to_string())));
                break;
            }
        }
    }
}

fn deliver_tagged(ctx: &ReadContext, kind: u8, reqid: u32, text: String) {
    let is_ok = matches!(kind, FRAME_KIND_EVAL_OK_TAGGED | FRAME_KIND_RPC_OK_TAGGED);
    let reply_kind = match kind {
        FRAME_KIND_EVAL_OK_TAGGED | FRAME_KIND_EVAL_ERR_TAGGED => ReplyKind::Eval,
        FRAME_KIND_RPC_OK_TAGGED | FRAME_KIND_RPC_ERR_TAGGED => ReplyKind::Rpc,
        // COMPLETE_TAGGED：jscomplete 候选，TCP 下忽略
        _ => return,
    };
    let result = if is_ok { Ok(text.clone()) } else { Err(text.clone()) };
    if !ctx.registry.deliver(reqid, reply_kind, result) {
        let _ = ctx.events.send(Event::StaleReply {
            reqid,
            kind: reply_kind,
            legacy: false,
            text,
        });
    }
}

fn deliver_legacy(ctx: &ReadContext, reply_kind: ReplyKind, result: Result<String, String>) {
    let stale_text = match &result {
        Ok(t) | Err(t) => t.clone(),
    };
    if !ctx.registry.deliver(0, reply_kind, result) {
        let _ = ctx.events.send(Event::StaleReply {
            reqid: 0,
            kind: reply_kind,
            legacy: true,
            text: stale_text,
        });
    }
}

/// 心跳线程：空闲时探测，超时则上报链路半开。
fn heartbeat_loop(
    writer: Arc<Mutex<TcpStream>>,
    events: Sender<Event>,
    disconnected: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
) {
    loop {
        thread::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        if disconnected.load(Ordering::Acquire) {
            return;
        }
        let idle_ms = now_millis().saturating_sub(last_activity.load(Ordering::Acquire));
        if idle_ms > HEARTBEAT_TIMEOUT_SECS * 1000 {
            disconnected.store(true, Ordering::Release);
            let _ = events.send(Event::Disconnected(Disconnect::HeartbeatTimeout));
            return;
        }
        // 仅在空闲时探测，避免与交互流量叠加
        if idle_ms > HEARTBEAT_INTERVAL_SECS * 1000 / 2 {
            let sent = {
                let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
                write_ping(&mut *w)
            };
            if sent.is_err() {
                return;
            }
        }
    }
}
