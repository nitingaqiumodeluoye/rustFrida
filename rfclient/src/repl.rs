//! 交互式 REPL：发送 CMD 帧，读取并展示 agent 帧。
//!
//! 命令面与设备端 rustfrida 对齐（jsinit/jseval/loadjs/jsclean/rpccall/hfl/trace/stalker…）。
//! `jsrepl` 是设备端子 REPL（读设备 stdin），TCP 下不可用，用 jseval 逐行求值替代。
//!
//! ── 协议 v2 ──
//! - 命令带 4B reqid（CMD_TAGGED），响应按 reqid 匹配。超时后被放弃的老响应不会
//!   再被下一条命令误领（legacy 单槽通道的真实缺陷）。
//! - 后台心跳线程定期发 PING，长时间无任何入站帧即判定链路半开并退出。
//! - 对端 HELLO 载荷 `proto=2` 才启用 v2；否则退回 legacy 单槽语义。

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::channel::Channels;
use crate::proto::*;

const EVAL_TIMEOUT_SECS: u64 = 30;
/// 心跳探测间隔：空闲时定期发 PING。
const HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// 心跳超时：超过该时长未收到任何入站帧，判定链路半开。
const HEARTBEAT_TIMEOUT_SECS: u64 = 45;
/// 等待 agent HELLO（协议版本协商）的最长时间。
const HELLO_WAIT_MILLIS: u64 = 1500;

/// 与设备端 repl.rs 一致的 jseval 错误前缀（用于识别格式化后的错误）
const JSEVAL_ERROR_PREFIX: &str = "__RF_JSEVAL_ERROR__:";

const COMMANDS: &[(&str, &str, &str)] = &[
    ("jsinit", "", "初始化 QuickJS 引擎"),
    ("jseval", "<expr>", "求值 JS 表达式并显示结果"),
    ("loadjs", "<file>", "加载本地 JS 脚本文件（自动初始化引擎）"),
    ("jsclean", "", "清理 QuickJS 引擎"),
    (
        "rpccall",
        "<method> [args]",
        "调用 rpc.exports 方法（args 为 JSON 数组）",
    ),
    ("hfl", "<module> <offset>", "Interceptor hook 指定偏移"),
    ("trace", "[tid]", "ptrace 指令追踪"),
    ("stalker", "[tid]", "Frida Stalker 追踪"),
    ("jhook", "", "Java/JNI hooking"),
    ("capture", "<on|off|status>", "捕获目标进程 stdout/stderr"),
    (
        "forward",
        "<local_port> [host:port]",
        "把本机端口转发到目标进程内的服务（open_channel）",
    ),
    ("unforward", "<local_port>", "停止某个本地端口转发"),
    ("forwards", "", "列出进行中的端口转发"),
    ("jslist", "", "列出已加载脚本（id/名称/hook 数）"),
    ("jsdrop", "<id>", "卸载某脚本注册的全部 hook"),
    ("help", "", "显示帮助"),
    ("exit", "", "断开客户端，保留 session（quit 同效）"),
    ("shutdown", "", "安全断开 TCP session，保留目标和 hook"),
];

/// 输出互斥锁：接收线程与 REPL 主线程并发打印时避免交错
static PRINT_LOCK: Mutex<()> = Mutex::new(());
static OUTPUT_FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn configure_output(path: Option<&str>) -> Result<(), String> {
    let file = path
        .map(File::create)
        .transpose()
        .map_err(|e| format!("创建输出文件失败: {}", e))?;
    let mut output = OUTPUT_FILE.lock().unwrap_or_else(|e| e.into_inner());
    *output = file;
    Ok(())
}

pub fn print_line(s: &str) {
    let _g = PRINT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    println!("{}", s);
    let _ = io::stdout().flush();
    if let Some(file) = OUTPUT_FILE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        let _ = writeln!(file, "{}", s);
        let _ = file.flush();
    }
}

/// 响应类型（eval / rpc 分属两条通道，tagged 模式下按 reqid 匹配）。
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ReplyKind {
    Eval,
    Rpc,
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

struct CommandCompleter;

impl Completer for CommandCompleter {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        if before.contains(' ') {
            return Ok((pos, vec![]));
        }
        let candidates: Vec<Pair> = COMMANDS
            .iter()
            .filter(|(cmd, _, _)| cmd.starts_with(before))
            .map(|(cmd, _, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}
impl Hinter for CommandCompleter {
    type Hint = String;
}
impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {}
impl Helper for CommandCompleter {}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 进入交互式 REPL，直到用户退出或连接断开。
///
/// `proto_hint` 是引导 OK 行里服务端宣告的 agent 协议版本：Some(2) 直接启用 v2，
/// 不依赖 HELLO 到达时机；None（旧服务端）则等 HELLO 或退回 legacy。
pub fn run(stream: &mut TcpStream, eof_linger: Duration, proto_hint: Option<u32>) -> Result<(), String> {
    // 清除读/写超时：中继后 agent 可能长时间无输出（日志/交互），不能被之前设置的 30s 超时打断
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);

    let reader = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;
    let writer = Arc::new(Mutex::new(
        stream.try_clone().map_err(|e| format!("clone stream: {}", e))?,
    ));

    let registry = Arc::new(Registry::new());
    let (activity_tx, activity_rx) = sync_channel::<()>(1);
    let disconnected = Arc::new(AtomicBool::new(false));
    let proto_v2 = Arc::new(AtomicBool::new(false));
    let hello_seen = Arc::new(AtomicBool::new(false));
    let last_activity = Arc::new(AtomicU64::new(now_millis()));

    // 本地端口转发（open_channel）：与接收线程共享通道表。
    let channels = Arc::new(Channels::new(writer.clone()));

    let recv_ctx = RecvContext {
        registry: registry.clone(),
        channels: channels.clone(),
        activity_tx,
        disconnected: disconnected.clone(),
        proto_v2: proto_v2.clone(),
        hello_seen: hello_seen.clone(),
        last_activity: last_activity.clone(),
    };
    thread::Builder::new()
        .name("rf-recv".into())
        .spawn(move || receiver_loop(reader, recv_ctx))
        .map_err(|e| format!("spawn recv thread: {}", e))?;

    // 心跳：定期发 PING，长时间无任何入站帧则判定链路半开。
    {
        let writer = writer.clone();
        let disconnected = disconnected.clone();
        let last_activity = last_activity.clone();
        let _ = thread::Builder::new().name("rf-ping".into()).spawn(move || loop {
            thread::sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            if disconnected.load(Ordering::Acquire) {
                return;
            }
            let idle_ms = now_millis().saturating_sub(last_activity.load(Ordering::Acquire));
            if idle_ms > HEARTBEAT_TIMEOUT_SECS * 1000 {
                print_line(&format!(
                    "[client] 心跳超时（{}s 无响应），链路可能已断开",
                    HEARTBEAT_TIMEOUT_SECS
                ));
                disconnected.store(true, Ordering::Release);
                std::process::exit(1);
            }
            // 仅在空闲时探测，避免与交互流量叠加
            if idle_ms > HEARTBEAT_INTERVAL_SECS * 1000 / 2 {
                if let Ok(mut w) = writer.lock() {
                    if write_ping(&mut *w).is_err() {
                        return;
                    }
                }
            }
        });
    }

    // 协议协商：OK 行已宣告 proto 时直接定案；否则等 HELLO（Gadget 路径/旧服务端）。
    if proto_hint == Some(2) {
        proto_v2.store(true, Ordering::Release);
        hello_seen.store(true, Ordering::Release);
    }
    let deadline = Instant::now() + Duration::from_millis(HELLO_WAIT_MILLIS);
    while !hello_seen.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    let v2 = proto_v2.load(Ordering::Acquire);

    let mut rl = Editor::new().map_err(|e| format!("初始化行编辑器失败: {}", e))?;
    rl.set_helper(Some(CommandCompleter));
    let _ = rl.load_history(".rfclient_history");

    if v2 {
        print_line("输入 help 查看命令，exit 退出（协议 v2：reqid 匹配 + 心跳）");
    } else {
        print_line("输入 help 查看命令，exit 退出（协议 v1：对端未宣告 v2）");
    }

    loop {
        if disconnected.load(Ordering::Acquire) {
            print_line("[agent] 连接已断开");
            break;
        }
        match rl.readline("rf> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "exit" || line == "quit" {
                    break;
                }
                if line == "shutdown" {
                    let _ = send_cmd(&writer, &registry, v2, "shutdown", None);
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    while !disconnected.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(50));
                    }
                    break;
                }
                if line == "help" {
                    print_help();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("forward ") {
                    let mut parts = rest.split_whitespace();
                    let port_arg = parts.next().unwrap_or("");
                    let remote = parts.next().unwrap_or("");
                    match port_arg.parse::<u16>() {
                        Ok(port) if port != 0 => {
                            let remote = if remote.is_empty() {
                                port.to_string()
                            } else {
                                remote.to_string()
                            };
                            match channels.forward(port, &remote) {
                                Ok(msg) => print_line(&format!("[forward] {}", msg)),
                                Err(e) => print_line(&format!("[forward] {}", e)),
                            }
                        }
                        _ => print_line("[forward] 用法: forward <local_port> [host:port]（省略 host 视为 127.0.0.1）"),
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("unforward ") {
                    match rest.trim().parse::<u16>() {
                        Ok(port) => print_line(&format!("[forward] {}", channels.unforward(port))),
                        Err(_) => print_line("[forward] 用法: unforward <local_port>"),
                    }
                    continue;
                }
                if line == "forwards" {
                    print_line(&channels.list());
                    continue;
                }
                if line == "jsrepl" {
                    print_line("[jsrepl] 设备端 jsrepl 需要本地 stdin，TCP 下请用 jseval 逐行求值");
                    continue;
                }
                if !is_known_command(&line) {
                    let name = line.split_whitespace().next().unwrap_or("(empty)");
                    print_line(&format!("[rfclient] 无效命令 '{}'，输入 help 查看可用命令", name));
                    continue;
                }

                let (payload, kind) = if let Some(rest) = line.strip_prefix("loadjs ") {
                    // 本地读文件，按 agent 的 loadjs_init [filename]\n<script> 格式发送
                    // （loadjs_init 自动初始化引擎，与设备端 -l 加载路径一致）
                    let path = rest.trim();
                    match std::fs::read_to_string(path) {
                        Ok(content) => {
                            let name = std::path::Path::new(path)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("script.js");
                            (format!("loadjs_init [{}]\n{}", name, content), Some(ReplyKind::Eval))
                        }
                        Err(e) => {
                            print_line(&format!("[loadjs] 读取 '{}' 失败: {}", path, e));
                            continue;
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("jseval ") {
                    // 与设备端一致：包装 jseval 表达式（友好错误提示 + 值字符串化）
                    (format!("jseval {}", wrap_jseval_expr(rest)), Some(ReplyKind::Eval))
                } else if let Some(rest) = line.strip_prefix("rpccall ") {
                    (format!("rpccall {}", rest.trim()), Some(ReplyKind::Rpc))
                } else {
                    let kind = if expects_response(&line) {
                        Some(ReplyKind::Eval)
                    } else {
                        None
                    };
                    (line.clone(), kind)
                };

                // 无响应命令（trace/stalker/__set_verbose__ 等）只产生 LOG 帧，不等待响应
                let Some(kind) = kind else {
                    let _ = send_cmd(&writer, &registry, v2, &payload, None);
                    continue;
                };

                match send_cmd(&writer, &registry, v2, &payload, Some(kind)) {
                    Ok(rx) => match rx.recv_timeout(Duration::from_secs(EVAL_TIMEOUT_SECS)) {
                        Ok(Ok(text)) => {
                            // 设备端包装的错误会以 __RF_JSEVAL_ERROR__: 前缀返回在 EVAL_OK
                            if let Some(err) = text.strip_prefix(JSEVAL_ERROR_PREFIX) {
                                print_line(&format!("[错误] {}", err));
                            } else {
                                print_line(&format!("=> {}", text));
                            }
                        }
                        Ok(Err(e)) => print_line(&format!("[错误] {}", e)),
                        Err(_) => print_line(&format!(
                            "[超时] 等待响应超过 {}s（该 reqid 的迟到响应会被丢弃）",
                            EVAL_TIMEOUT_SECS
                        )),
                    },
                    Err(e) => {
                        eprintln!("发送失败: {}", e);
                        break;
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                print_line("断开客户端，session 保留");
                break;
            }
            Err(ReadlineError::Eof) => {
                if eof_linger.is_zero() {
                    print_line("stdin 已关闭，断开客户端，session 保留");
                } else {
                    print_line(&format!(
                        "stdin 已关闭，继续接收日志；连续 {}s 无新消息后断开",
                        eof_linger.as_secs()
                    ));
                    wait_for_log_idle(&activity_rx, &disconnected, eof_linger);
                    print_line("日志等待结束，断开客户端，session 保留");
                }
                break;
            }
            Err(e) => {
                print_line(&format!("读取输入失败: {}", e));
                break;
            }
        }
    }
    let _ = rl.save_history(".rfclient_history");
    // 断连/退出前停掉本地监听与通道（否则监听线程会继续 accept 并向死连接写帧）。
    channels.shutdown_all();
    Ok(())
}

/// 发送命令。v2 时使用 CMD_TAGGED 并按 reqid 注册等待者；legacy 时 reqid 恒为 0
/// （单槽语义，与旧服务端一致）。
///
/// `kind: None` 表示不等待响应（trace/stalker/__set_verbose__ 等只产生 LOG 帧的命令），
/// 发送后立即注销，迟到响应会按 stale 丢弃。
fn send_cmd(
    writer: &Arc<Mutex<TcpStream>>,
    registry: &Arc<Registry>,
    v2: bool,
    cmd: &str,
    kind: Option<ReplyKind>,
) -> std::io::Result<Receiver<Result<String, String>>> {
    let reqid = if v2 { registry.next_reqid() } else { 0 };
    let rx = registry.register(kind.unwrap_or(ReplyKind::Eval), reqid);
    let mut w = writer.lock().unwrap_or_else(|e| e.into_inner());
    let result = if v2 {
        write_tagged_cmd(&mut *w, reqid, cmd)
    } else {
        write_frame(&mut *w, FRAME_KIND_CMD, cmd.as_bytes())
    };
    drop(w);
    if let Err(e) = result {
        registry.deregister(reqid);
        return Err(e);
    }
    if kind.is_none() {
        registry.deregister(reqid);
    }
    Ok(rx)
}

fn print_help() {
    print_line("命令：");
    for (cmd, args, desc) in COMMANDS {
        print_line(&format!("  {:<12} {:<24} {}", cmd, args, desc));
    }
}

/// 与设备端 repl.rs 的 wrap_jseval_expr 一致：把表达式包装成求值 + 友好错误提示的 JS。
fn wrap_jseval_expr(expr: &str) -> String {
    format!(
        "(() => {{ try {{ return eval({}); }} catch (e) {{ let msg = String((e && e.message) ? ((e.name || 'Error') + ': ' + e.message) : e); let st = ''; try {{ st = (e && e.stack) ? String(e.stack) : ''; }} catch (_) {{}} let s = st ? (st.indexOf(msg) >= 0 ? st : (msg + '\\n' + st)) : msg; return {} + s; }} }})()",
        js_string_literal(expr),
        js_string_literal(JSEVAL_ERROR_PREFIX)
    )
}

fn js_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// 该命令是否会产生 EVAL 响应？无响应命令（trace/stalker/__set_verbose__/detach/shutdown 等）
/// 只输出 LOG 帧，不能等待 eval 响应。
fn expects_response(cmd: &str) -> bool {
    let name = cmd.split_whitespace().next().unwrap_or("");
    !matches!(name, "trace" | "stalker" | "__set_verbose__" | "detach" | "shutdown")
}

fn is_known_command(cmd: &str) -> bool {
    matches!(
        cmd.split_whitespace().next().unwrap_or(""),
        "jsinit"
            | "jseval"
            | "loadjs"
            | "loadjs_init"
            | "jsclean"
            | "jsclean_soft"
            | "rpccall"
            | "hfl"
            | "trace"
            | "stalker"
            | "jhook"
            | "__set_verbose__"
            | "javastealth"
            | "artinit"
            | "javaworker_init"
            | "javaexecutor_cut"
            | "java_loadjs_init"
            | "java_loadjs"
            | "java_jseval"
            | "jsworker_stop"
            | "javainit"
            | "managedcounter"
            | "jscomplete"
            | "recomp"
            | "recomp-release"
            | "recomp-dry"
            | "recomp-list"
            | "capture"
            | "forward"
            | "unforward"
            | "forwards"
            | "jslist"
            | "jsdrop"
            | "detach"
            | "shutdown"
    )
}

/// stdin EOF 后保持连接，每收到一个 agent 帧就重置空闲计时。
fn wait_for_log_idle(activity_rx: &Receiver<()>, disconnected: &AtomicBool, idle: Duration) {
    let mut deadline = std::time::Instant::now() + idle;
    loop {
        if disconnected.load(Ordering::Acquire) {
            break;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        match activity_rx.recv_timeout(deadline - now) {
            Ok(()) => deadline = std::time::Instant::now() + idle,
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

struct RecvContext {
    registry: Arc<Registry>,
    channels: Arc<Channels>,
    activity_tx: SyncSender<()>,
    disconnected: Arc<AtomicBool>,
    proto_v2: Arc<AtomicBool>,
    hello_seen: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
}

/// 后台接收线程：读帧，LOG/HELLO/BYE/EVENT 直接打印；响应帧按 reqid 路由到挂起请求。
fn receiver_loop(mut reader: TcpStream, ctx: RecvContext) {
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                let _ = ctx.activity_tx.try_send(());
                ctx.last_activity.store(now_millis(), Ordering::Release);
                match kind {
                    FRAME_KIND_LOG => {
                        let msg = String::from_utf8_lossy(&payload);
                        let msg = msg.strip_suffix('\n').unwrap_or(&msg);
                        if !msg.is_empty() {
                            print_line(&format!("[agent] {}", msg));
                        }
                    }
                    FRAME_KIND_HELLO => {
                        let hello = String::from_utf8_lossy(&payload);
                        if hello.contains("proto=2") {
                            ctx.proto_v2.store(true, Ordering::Release);
                            print_line("[agent] 已连接（协议 v2：reqid 匹配 + 心跳）");
                        } else {
                            print_line("[agent] 已连接（协议 v1）");
                        }
                        ctx.hello_seen.store(true, Ordering::Release);
                    }
                    // 结构化事件帧（server 生成）：TSV，`type\tkey=value...`
                    FRAME_KIND_EVENT => {
                        let text = String::from_utf8_lossy(&payload);
                        let mut fields = text.split('\t').filter(|f| !f.is_empty());
                        let ty = fields.next().unwrap_or("event");
                        let rest: Vec<&str> = fields.collect();
                        print_line(&format!("[event] {} {}", ty, rest.join(" ")));
                    }
                    // PONG 只用于保活，不打印（last_activity 已刷新）
                    FRAME_KIND_PONG => {}
                    // open_channel：按 channel id 路由到本地转发通道。
                    FRAME_KIND_CHANNEL_OPENED => {
                        if let Some((id, body)) = split_channel_payload(&payload) {
                            let status = body.first().copied().unwrap_or(1);
                            let message = String::from_utf8_lossy(body.get(1..).unwrap_or(&[])).into_owned();
                            ctx.channels.on_opened(id, status, &message);
                        }
                    }
                    FRAME_KIND_CHANNEL_DATA => {
                        if let Some((id, body)) = split_channel_payload(&payload) {
                            ctx.channels.on_data(id, body);
                        }
                    }
                    FRAME_KIND_CHANNEL_CLOSE => {
                        if let Some((id, _)) = split_channel_payload(&payload) {
                            ctx.channels.on_close(id);
                        }
                    }
                    FRAME_KIND_EVAL_OK_TAGGED
                    | FRAME_KIND_EVAL_ERR_TAGGED
                    | FRAME_KIND_RPC_OK_TAGGED
                    | FRAME_KIND_RPC_ERR_TAGGED
                    | FRAME_KIND_COMPLETE_TAGGED => {
                        let Some((reqid, body)) = split_tagged_payload(&payload) else {
                            print_line("[agent] 收到截断的 tagged 响应帧，已丢弃");
                            continue;
                        };
                        let text = String::from_utf8_lossy(body).into_owned();
                        match kind {
                            FRAME_KIND_EVAL_OK_TAGGED => {
                                if !ctx.registry.deliver(reqid, ReplyKind::Eval, Ok(text)) {
                                    print_line(&format!("[stale] 丢弃迟到的 eval 响应 (reqid={})", reqid));
                                }
                            }
                            FRAME_KIND_EVAL_ERR_TAGGED => {
                                if !ctx.registry.deliver(reqid, ReplyKind::Eval, Err(text)) {
                                    print_line(&format!("[stale] 丢弃迟到的 eval 错误 (reqid={})", reqid));
                                }
                            }
                            FRAME_KIND_RPC_OK_TAGGED => {
                                if !ctx.registry.deliver(reqid, ReplyKind::Rpc, Ok(text)) {
                                    print_line(&format!("[stale] 丢弃迟到的 rpc 响应 (reqid={})", reqid));
                                }
                            }
                            FRAME_KIND_RPC_ERR_TAGGED => {
                                if !ctx.registry.deliver(reqid, ReplyKind::Rpc, Err(text)) {
                                    print_line(&format!("[stale] 丢弃迟到的 rpc 错误 (reqid={})", reqid));
                                }
                            }
                            _ => {
                                // jscomplete 候选：TCP REPL 未启用动态补全，忽略
                            }
                        }
                    }
                    FRAME_KIND_EVAL_OK => {
                        if !ctx.registry.deliver(0, ReplyKind::Eval, Ok(String::from_utf8_lossy(&payload).into_owned()))
                        {
                            print_line("[stale] 丢弃无主的 eval 响应（legacy）");
                        }
                    }
                    FRAME_KIND_EVAL_ERR => {
                        if !ctx
                            .registry
                            .deliver(0, ReplyKind::Eval, Err(String::from_utf8_lossy(&payload).into_owned()))
                        {
                            print_line("[stale] 丢弃无主的 eval 错误（legacy）");
                        }
                    }
                    FRAME_KIND_RPC_OK => {
                        if !ctx.registry.deliver(0, ReplyKind::Rpc, Ok(String::from_utf8_lossy(&payload).into_owned()))
                        {
                            print_line("[stale] 丢弃无主的 rpc 响应（legacy）");
                        }
                    }
                    FRAME_KIND_RPC_ERR => {
                        if !ctx
                            .registry
                            .deliver(0, ReplyKind::Rpc, Err(String::from_utf8_lossy(&payload).into_owned()))
                        {
                            print_line("[stale] 丢弃无主的 rpc 错误（legacy）");
                        }
                    }
                    FRAME_KIND_COMPLETE => {
                        // jscomplete 候选：TCP REPL 未启用动态补全，忽略
                    }
                    FRAME_KIND_BYE => {
                        print_line("[agent] 已断开 (BYE)");
                        ctx.channels.shutdown_all();
                        ctx.disconnected.store(true, Ordering::Release);
                        break;
                    }
                    other => {
                        print_line(&format!("[agent] 未知帧 kind: {}", other));
                    }
                }
            }
            Err(e) => {
                print_line(&format!("[agent] 连接断开: {}", e));
                ctx.channels.shutdown_all();
                ctx.disconnected.store(true, Ordering::Release);
                let _ = ctx.activity_tx.try_send(());
                break;
            }
        }
    }

    // `rustyline::readline` is synchronous and cannot be cancelled by the
    // receiver thread. Once the server closes the transport, terminate this
    // standalone CLI so a stale prompt cannot keep the dead session alive.
    std::process::exit(0);
}
