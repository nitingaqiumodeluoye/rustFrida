//! 后台工作与状态：连接、一次性查询、事件排空、在途命令。
//!
//! 这个模块**不依赖 egui**：它只通过一个 `Wake` 回调通知 UI 该重绘了。
//! 这样线程与界面之间的边界就是清楚的 —— 线程只写日志缓冲和状态，
//! 从不直接碰界面。

use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;

use rfclient_core::query::{self, Opened, ProcessRow, SessionRow};
use rfclient_core::{Disconnect, Event, Pending, Reply, ReplyKind, Session};

use crate::logbuf::{LogBuf, Tag};

/// 通知 UI 重绘（避免 conn 依赖 egui::Context）。
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// 单条命令的等待上限。
///
/// 比 core 的 IO 超时略长：core 管的是 socket 读写，这里管的是「用户在等应答」，
/// 两者是不同层次的事，不该硬绑在一起。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(35);

/// 一次性查询（list / ps）的超时。
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// 建连超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub enum State {
    /// 未连接。
    Idle,
    /// 正在建连/握手（可能卡在 TCP 上，所以要有可见的中间态）。
    Connecting(String),
    Connected,
    /// 已断开。`true` 表示是链路异常（心跳超时/IO 错误），`false` 表示正常收尾。
    Disconnected { reason: String, abnormal: bool },
}

impl State {
    pub fn label(&self) -> String {
        match self {
            State::Idle => "未连接".to_string(),
            State::Connecting(what) => format!("正在连接 {}", what),
            State::Connected => "已连接".to_string(),
            State::Disconnected { reason, .. } => format!("已断开：{}", reason),
        }
    }

    pub fn color(&self, visuals: &egui::Visuals) -> egui::Color32 {
        match self {
            State::Idle => visuals.weak_text_color(),
            State::Connecting(_) => egui::Color32::from_rgb(230, 180, 60),
            State::Connected => egui::Color32::from_rgb(80, 190, 90),
            State::Disconnected { abnormal, .. } => {
                if *abnormal {
                    egui::Color32::from_rgb(230, 90, 90)
                } else {
                    visuals.weak_text_color()
                }
            }
        }
    }
}

/// 建连线程的结果。
pub enum TaskResult {
    Connected(Box<Opened>, String),
    Failed(String),
}

/// 一次性查询的种类。
enum QueryKind {
    Sessions,
    Processes { filter: String },
}

/// 查询线程的结果。
pub enum QueryResult {
    Sessions(Vec<SessionRow>),
    Processes(Vec<ProcessRow>),
    Failed(String),
}

/// 已发出、还没拿到应答的命令。
struct Inflight {
    label: String,
    pending: Pending,
    started: Instant,
}

/// 一轮 `pump()` 收集到的一切，交给 UI 消化。
#[derive(Default)]
pub struct Pumped {
    pub task: Option<TaskResult>,
    pub query: Option<QueryResult>,
    /// 已到达的应答：`(请求时的标签, 应答)`。
    pub replies: Vec<(String, Reply)>,
}

pub struct Client {
    wake: Wake,
    pub log: LogBuf,
    state: Arc<Mutex<State>>,
    session: Option<Arc<Session>>,
    connect_rx: Option<Receiver<TaskResult>>,
    query_rx: Option<Receiver<QueryResult>>,
    inflight: Vec<Inflight>,
}

impl Client {
    pub fn new(wake: Wake, log: LogBuf) -> Self {
        Client {
            wake,
            log,
            state: Arc::new(Mutex::new(State::Idle)),
            session: None,
            connect_rx: None,
            query_rx: None,
            inflight: Vec::new(),
        }
    }

    pub fn state(&self) -> State {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_state(&self, state: State) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = state;
    }

    pub fn session(&self) -> Option<&Arc<Session>> {
        self.session.as_ref()
    }

    pub fn is_connecting(&self) -> bool {
        self.connect_rx.is_some()
    }

    /// 是否有后台查询在进行（用于禁用按钮，避免连点开出多条连接）。
    pub fn is_querying(&self) -> bool {
        self.query_rx.is_some()
    }

    /// 发起连接：在后台线程里完成握手，避免 UI 卡住最长 10 秒。
    pub fn connect(&mut self, host: String, bootstrap_line: String, token: Option<String>, label: String) {
        if self.connect_rx.is_some() {
            return;
        }
        self.teardown_session();
        self.set_state(State::Connecting(label.clone()));
        self.log.push(Tag::Client, format!("正在连接 {}（{}）", host, label));

        let (tx, rx) = channel();
        let wake = self.wake.clone();
        std::thread::Builder::new()
            .name("rf-gui-connect".into())
            .spawn(move || {
                let result = query::open_session(
                    &host,
                    &bootstrap_line,
                    token.as_deref(),
                    None,
                    CONNECT_TIMEOUT,
                );
                let payload = match result {
                    Ok(opened) => TaskResult::Connected(Box::new(opened), label),
                    Err(e) => TaskResult::Failed(e.to_string()),
                };
                // 接收端可能已销毁（窗口关闭），忽略发送失败。
                let _ = tx.send(payload);
                wake();
            })
            .ok();
        self.connect_rx = Some(rx);
    }

    /// 一次性查询：会话表。
    pub fn refresh_sessions(&mut self, host: String, token: Option<String>) {
        self.spawn_query(host, QueryKind::Sessions, token);
    }

    /// 一次性查询：进程表（需要令牌）。
    pub fn refresh_processes(&mut self, host: String, filter: String, token: Option<String>) {
        self.spawn_query(host, QueryKind::Processes { filter }, token);
    }

    fn spawn_query(&mut self, host: String, kind: QueryKind, token: Option<String>) {
        // 已有查询在跑就忽略这次点击：否则连点会开出一串短连接，
        // 而它们拿回来的结果只会互相覆盖。
        if self.query_rx.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let wake = self.wake.clone();
        std::thread::Builder::new()
            .name("rf-gui-query".into())
            .spawn(move || {
                let result = match &kind {
                    QueryKind::Sessions => {
                        query::list_sessions(&host, token.as_deref(), QUERY_TIMEOUT)
                            .map(QueryResult::Sessions)
                    }
                    QueryKind::Processes { filter } => query::list_processes(
                        &host,
                        Some(filter.as_str()).filter(|f| !f.trim().is_empty()),
                        token.as_deref(),
                        QUERY_TIMEOUT,
                    )
                    .map(QueryResult::Processes),
                };
                let _ = tx.send(result.unwrap_or_else(QueryResult::Failed));
                wake();
            })
            .ok();
        self.query_rx = Some(rx);
    }

    /// 发送命令并记入在途表。应答在后续 `pump()` 里取。
    pub fn send(&mut self, cmd: &str, kind: ReplyKind, label: &str) {
        let Some(session) = self.session.clone() else {
            self.log.push(Tag::Error, "尚未连接");
            return;
        };
        match session.send(cmd, kind) {
            Ok(pending) => self.inflight.push(Inflight {
                label: label.to_string(),
                pending,
                started: Instant::now(),
            }),
            Err(e) => self.log.push(Tag::Error, e),
        }
    }

    /// 发送不需要应答的命令（trace / stalker / detach 等只产生 LOG 帧）。
    pub fn send_no_reply(&mut self, cmd: &str) {
        let Some(session) = self.session.as_ref() else {
            self.log.push(Tag::Error, "尚未连接");
            return;
        };
        if let Err(e) = session.send_no_reply(cmd) {
            self.log.push(Tag::Error, e);
        }
    }

    /// 断开：先停本地转发，再关 socket（否则监听线程会继续 accept 并向死连接写帧）。
    pub fn disconnect(&mut self) {
        if let Some(session) = self.session.as_ref() {
            session.shutdown_channels();
            session.close();
        }
        self.set_state(State::Disconnected {
            reason: "已手动断开".to_string(),
            abnormal: false,
        });
        self.log.push(Tag::Client, "已断开连接");
    }

    fn teardown_session(&mut self) {
        if let Some(session) = self.session.take() {
            session.shutdown_channels();
            session.close();
        }
        self.inflight.clear();
    }

    /// 每帧调用：收建连/查询结果、收应答、推进超时。
    pub fn pump(&mut self) -> Pumped {
        let mut out = Pumped::default();

        if let Some(rx) = self.connect_rx.as_ref() {
            match rx.try_recv() {
                Ok(result) => {
                    self.connect_rx = None;
                    out.task = Some(result);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.connect_rx = None;
                    out.task = Some(TaskResult::Failed("建连线程异常退出".to_string()));
                }
            }
        }

        if let Some(rx) = self.query_rx.as_ref() {
            match rx.try_recv() {
                Ok(result) => {
                    self.query_rx = None;
                    out.query = Some(result);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.query_rx = None;
                    out.query = Some(QueryResult::Failed("查询线程异常退出".to_string()));
                }
            }
        }

        // 一旦判定断开就把会话摘掉：否则界面上的按钮还是可点的，
        // 点下去只会得到「发送失败」，看起来像 bug 而不是「已经断开了」。
        if self.session.is_some() && matches!(self.state(), State::Disconnected { .. }) {
            self.session = None;
            self.inflight.clear();
        }

        // 应答轮询用 try_take 而不是 wait：UI 线程一秒都不能被阻塞。
        let mut index = 0;
        while index < self.inflight.len() {
            let (label, reply, done) = {
                let entry = &self.inflight[index];
                match entry.pending.try_take() {
                    Some(reply) => (entry.label.clone(), reply, true),
                    None if entry.started.elapsed() >= COMMAND_TIMEOUT => (
                        entry.label.clone(),
                        Reply::Timeout,
                        true,
                    ),
                    None => (String::new(), Reply::Timeout, false),
                }
            };
            if done {
                self.inflight.remove(index);
                out.replies.push((label, reply));
            } else {
                index += 1;
            }
        }

        out
    }

    /// 接管一个新建立的会话：起事件排空线程。
    pub fn adopt(&mut self, opened: Opened, label: String) {
        let session = Arc::new(opened.session);
        self.session = Some(session.clone());
        self.set_state(State::Connected);
        self.log.push(Tag::Client, format!("{}（{}）", opened.ok_line, label));

        spawn_event_drain(
            opened.events,
            self.log.clone(),
            self.wake.clone(),
            self.state.clone(),
            session,
        );
    }
}

/// 事件排空线程。
///
/// 必须是独立的常驻线程而不是「渲染帧里 drain 一次」：事件通道是无界的，
/// 窗口最小化或用户不动鼠标时 egui 可能完全不渲染，那时没人排空，
/// 队列就会一直涨（脚本里 console.log 刷屏时涨得很快）。
fn spawn_event_drain(
    events: Receiver<Event>,
    log: LogBuf,
    wake: Wake,
    state: Arc<Mutex<State>>,
    session: Arc<Session>,
) {
    std::thread::Builder::new()
        .name("rf-gui-events".into())
        .spawn(move || {
            for event in events {
                match event {
                    Event::Log(msg) => {
                        // agent 侧捕获的目标进程输出带 `[out] ` 前缀，单独着色。
                        if let Some(rest) = msg.strip_prefix("[out] ") {
                            log.push(Tag::Out, rest);
                        // 服务端镜像日志自带 `[server] ` 前缀（见 server.rs
                        // mirror_log_to_client）。单独一个 Tag，否则会被当成 agent 输出，
                        // 而它其实是服务端为了补充“设备端发生了什么”才发过来的。
                        } else if let Some(rest) = msg.strip_prefix("[server] ") {
                            log.push(Tag::Server, rest);
                        } else {
                            log.push(Tag::Agent, msg);
                        }
                    }
                    Event::Hello { proto_v2 } => {
                        let text = if proto_v2 {
                            "agent 已就绪（协议 v2：reqid 匹配 + 心跳）"
                        } else {
                            "agent 已就绪（协议 v1，对端未宣告 v2）"
                        };
                        log.push(Tag::Client, text);
                    }
                    Event::ServerEvent { ty, fields } => {
                        log.push(Tag::Event, format!("{} {}", ty, fields.join(" ")));
                    }
                    // PONG 只用于保活，core 已经刷新过活动时间，展示出来只是噪声。
                    Event::Pong => {}
                    Event::ChannelOpened(info) => {
                        if info.status != 0 {
                            let remote = info.remote.unwrap_or_else(|| "目标进程".to_string());
                            log.push(
                                Tag::Forward,
                                format!(
                                    "转发目标连接失败（{}，状态码 {}）：{}",
                                    remote,
                                    info.status,
                                    if info.message.is_empty() {
                                        "无详细信息"
                                    } else {
                                        &info.message
                                    }
                                ),
                            );
                        }
                    }
                    // 通道数据与关闭都由 core 的 Channels 直接处理（写本地 socket），
                    // 这里不做任何事 —— 需要在这层干预就说明分层错了。
                    Event::ChannelData { .. } | Event::ChannelClosed { .. } => {}
                    Event::StaleReply { reqid, kind, legacy, .. } => {
                        let what = match kind {
                            ReplyKind::Eval => "eval",
                            ReplyKind::Rpc => "rpc",
                        };
                        if legacy {
                            log.push(Tag::Error, format!("丢弃无主的 {} 响应（legacy）", what));
                        } else {
                            log.push(Tag::Error, format!("丢弃迟到的 {} 响应 (reqid={})", what, reqid));
                        }
                    }
                    Event::Disconnected(reason) => {
                        let (text, abnormal) = match &reason {
                            Disconnect::Bye => ("agent 已断开 (BYE)".to_string(), false),
                            Disconnect::Io(e) => (format!("连接断开: {}", e), true),
                            Disconnect::HeartbeatTimeout => (
                                format!(
                                    "心跳超时（{}s 无响应），链路可能已断开",
                                    rfclient_core::HEARTBEAT_TIMEOUT_SECS
                                ),
                                true,
                            ),
                        };
                        // 断连时顺手停掉本地监听：目标进程已经不可达，
                        // 留着 listener 只会让后续 accept 的连接一直挂着。
                        session.shutdown_channels();
                        log.push(Tag::Error, text.clone());
                        *state.lock().unwrap_or_else(|e| e.into_inner()) = State::Disconnected {
                            reason: text,
                            abnormal,
                        };
                        // 事件通道随读线程结束而关闭，循环自然退出。
                    }
                }
                // 先放开日志锁再唤醒 UI：唤醒会触发渲染，渲染又要读日志缓冲。
                wake();
            }
        })
        .ok();
}
