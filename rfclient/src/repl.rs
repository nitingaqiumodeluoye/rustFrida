//! 交互式 REPL：把终端输入变成 core 的命令，把 core 的事件变成终端输出。
//!
//! 本模块只负责**终端呈现**，协议与状态都在 `rfclient_core`：
//! - 命令发送、reqid 匹配、心跳、端口转发 → `rfclient_core::Session`
//! - 日志/事件/断连 → `rfclient_core::Event`
//!
//! 两条通路是分开的：应答有明确请求方（阻塞等待），事件是广播性质
//! （由一个专门的打印线程排空，这样用户停在提示符上时日志照样实时滚动）。
//!
//! ── 协议 v2 ──
//! - 命令带 4B reqid（CMD_TAGGED），响应按 reqid 匹配。超时后被放弃的老响应不会
//!   再被下一条命令误领（legacy 单槽通道的真实缺陷）。
//! - 后台心跳定期发 PING，长时间无任何入站帧即判定链路半开。
//! - 对端 HELLO 载荷 `proto=2` 才启用 v2；否则退回 legacy 单槽语义。

use std::fs::File;
use std::io::{self, Write};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use rfclient_core::event::Disconnect;
use rfclient_core::script::{expects_response, js_string_literal, wrap_jseval_expr, JSEVAL_ERROR_PREFIX};
use rfclient_core::{Event, Reply, ReplyKind, Session, HEARTBEAT_TIMEOUT_SECS};

const EVAL_TIMEOUT_SECS: u64 = 30;

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
    ("jslist", "", "列出已加载脚本（id/名称/hook 数）"),
    ("jsdrop", "<id>", "卸载某脚本注册的全部 hook"),
    ("capture", "<on|off|status>", "捕获目标进程 stdout/stderr"),
    (
        "forward",
        "<local_port> [host:port]",
        "把本机端口转发到目标进程内的服务（open_channel）",
    ),
    ("unforward", "<local_port>", "停止某个本地端口转发"),
    ("forwards", "", "列出进行中的端口转发"),
    ("help", "", "显示帮助"),
    ("exit", "", "断开客户端，保留 session（quit 同效）"),
    ("shutdown", "", "安全断开 TCP session，保留目标和 hook"),
];

/// 输出互斥锁：打印线程与 REPL 主线程并发打印时避免交错
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

/// 进入交互式 REPL，直到用户退出或连接断开。
///
/// `events` 是会话事件流，本函数接管它的排空（起一个打印线程）。
pub fn run(session: &Arc<Session>, events: Receiver<Event>, eof_linger: Duration) -> Result<(), String> {
    let proto_v2 = session.wait_for_hello(Duration::from_millis(rfclient_core::HELLO_WAIT_MILLIS));

    spawn_event_printer(events);

    let mut rl = Editor::new().map_err(|e| format!("初始化行编辑器失败: {}", e))?;
    rl.set_helper(Some(CommandCompleter));
    let _ = rl.load_history(".rfclient_history");

    if proto_v2 {
        print_line("输入 help 查看命令，exit 退出（协议 v2：reqid 匹配 + 心跳）");
    } else {
        print_line("输入 help 查看命令，exit 退出（协议 v1：对端未宣告 v2）");
    }

    loop {
        if session.is_disconnected() {
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
                    let _ = session.send_no_reply("shutdown");
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !session.is_disconnected() && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(50));
                    }
                    break;
                }
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "jsrepl" {
                    print_line("[jsrepl] 设备端 jsrepl 需要本地 stdin，TCP 下请用 jseval 逐行求值");
                    continue;
                }
                // 端口转发完全在本地处理，不进 agent 命令面。
                if let Some(rest) = line.strip_prefix("forward ") {
                    handle_forward(session, rest);
                    continue;
                }
                if let Some(rest) = line.strip_prefix("unforward ") {
                    match rest.trim().parse::<u16>() {
                        Ok(port) => match session.channels().unforward(port) {
                            Ok(closed) => print_line(&format!(
                                "[forward] 已停止转发 127.0.0.1:{}（关闭 {} 个连接）",
                                port, closed
                            )),
                            Err(e) => print_line(&format!("[forward] {}", e)),
                        },
                        Err(_) => print_line("[forward] 用法: unforward <local_port>"),
                    }
                    continue;
                }
                if line == "forwards" {
                    print_forwards(session);
                    continue;
                }
                if !is_known_command(&line) {
                    let name = line.split_whitespace().next().unwrap_or("(empty)");
                    print_line(&format!("[rfclient] 无效命令 '{}'，输入 help 查看可用命令", name));
                    continue;
                }

                // 无响应命令（trace/stalker/__set_verbose__ 等）只产生 LOG 帧，不等待响应
                if !expects_response(&line) {
                    if let Err(e) = session.send_no_reply(&line) {
                        eprintln!("发送失败: {}", e);
                        break;
                    }
                    continue;
                }

                let (payload, kind) = if let Some(rest) = line.strip_prefix("loadjs ") {
                    // 本地读文件，按 agent 的 loadjs_init [filename]\n<script> 格式发送
                    // （loadjs_init 自动初始化引擎，与设备端 -l 加载路径一致）
                    match build_loadjs_payload(rest.trim()) {
                        Ok(payload) => (payload, ReplyKind::Eval),
                        Err(e) => {
                            print_line(&e);
                            continue;
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("jseval ") {
                    // 与设备端一致：包装 jseval 表达式（友好错误提示 + 值字符串化）
                    (format!("jseval {}", wrap_jseval_expr(rest)), ReplyKind::Eval)
                } else if let Some(rest) = line.strip_prefix("rpccall ") {
                    (format!("rpccall {}", rest.trim()), ReplyKind::Rpc)
                } else {
                    (line.clone(), ReplyKind::Eval)
                };

                match session.send(&payload, kind) {
                    Ok(pending) => match pending.wait(Duration::from_secs(EVAL_TIMEOUT_SECS)) {
                        Reply::Ok(text) => {
                            // 设备端包装的错误会以 __RF_JSEVAL_ERROR__: 前缀返回在 EVAL_OK
                            if let Some(err) = text.strip_prefix(JSEVAL_ERROR_PREFIX) {
                                print_line(&format!("[错误] {}", err));
                            } else {
                                print_line(&format!("=> {}", text));
                            }
                        }
                        Reply::Err(e) => print_line(&format!("[错误] {}", e)),
                        Reply::Timeout => print_line(&format!(
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
                    wait_for_log_idle(session, eof_linger);
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
    // 断开/退出前停掉本地监听与通道（否则监听线程会继续 accept 并向死连接写帧）。
    session.shutdown_channels();
    Ok(())
}

/// 起一个专门的线程排空事件流并打印。
///
/// 必须独立成线程：`rustyline::readline` 是阻塞调用，主线程停在提示符上时
/// 无法消费事件 —— 那样日志要等用户敲下一行才显示。
///
/// 断开时**终止进程**：readline 无法被取消，若只置标志，主线程会卡在提示符上，
/// 用户看不到任何反馈（这是既有 CLI 行为，保持不变；GUI 不应照抄这一条）。
fn spawn_event_printer(events: Receiver<Event>) {
    let _ = thread::Builder::new().name("rf-print".into()).spawn(move || {
        for event in events {
            match event {
                // 服务端镜像日志自带 `[server] ` 前缀（见 server.rs mirror_log_to_client），
                // 此时不再叠 `[agent] `，否则会渲染成 `[agent] [server] ...`，
                // 读起来像是 agent 报的，其实是服务端报的。
                Event::Log(msg) => {
                    if msg.starts_with("[server] ") {
                        print_line(&msg)
                    } else {
                        print_line(&format!("[agent] {}", msg))
                    }
                }
                Event::Hello { proto_v2 } => {
                    if proto_v2 {
                        print_line("[agent] 已连接（协议 v2：reqid 匹配 + 心跳）");
                    } else {
                        print_line("[agent] 已连接（协议 v1）");
                    }
                }
                Event::ServerEvent { ty, fields } => {
                    print_line(&format!("[event] {} {}", ty, fields.join(" ")));
                }
                // PONG 只用于保活，不打印（活动时间已由 core 刷新）
                Event::Pong => {}
                Event::ChannelOpened(info) => {
                    if info.status != 0 {
                        let remote = info.remote.as_deref().unwrap_or("目标进程");
                        let detail = if info.message.is_empty() {
                            "无详细信息"
                        } else {
                            &info.message
                        };
                        print_line(&format!(
                            "[forward] 目标进程连接失败 ({}): {}（状态码 {}）",
                            remote, detail, info.status
                        ));
                    }
                }
                // 数据/关闭已由 core 的 Channels 直接处理（写入本地 socket）
                Event::ChannelData { .. } | Event::ChannelClosed { .. } => {}
                Event::StaleReply {
                    reqid,
                    kind,
                    legacy,
                    ..
                } => {
                    let what = match kind {
                        ReplyKind::Eval => "eval",
                        ReplyKind::Rpc => "rpc",
                    };
                    if legacy {
                        print_line(&format!("[stale] 丢弃无主的 {} 响应（legacy）", what));
                    } else {
                        print_line(&format!("[stale] 丢弃迟到的 {} 响应 (reqid={})", what, reqid));
                    }
                }
                Event::Disconnected(reason) => {
                    match reason {
                        Disconnect::Bye => {
                            print_line("[agent] 已断开 (BYE)");
                            std::process::exit(0);
                        }
                        Disconnect::Io(e) => {
                            print_line(&format!("[agent] 连接断开: {}", e));
                            std::process::exit(0);
                        }
                        Disconnect::HeartbeatTimeout => {
                            print_line(&format!(
                                "[client] 心跳超时（{}s 无响应），链路可能已断开",
                                HEARTBEAT_TIMEOUT_SECS
                            ));
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    });
}

/// 读本地脚本并拼成 `loadjs_init [filename]\n<内容>`。
fn build_loadjs_payload(path: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("[loadjs] 读取 '{}' 失败: {}", path, e))?;
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("script.js");
    Ok(format!("loadjs_init [{}]\n{}", name, content))
}

fn handle_forward(session: &Arc<Session>, rest: &str) {
    let mut parts = rest.split_whitespace();
    let port_arg = parts.next().unwrap_or("");
    let remote = parts.next().unwrap_or("");
    match port_arg.parse::<u16>() {
        Ok(port) if port != 0 => {
            // 省略 host 时视为目标进程内的 127.0.0.1:<同端口>
            let remote = if remote.is_empty() {
                port.to_string()
            } else {
                remote.to_string()
            };
            match session.channels().forward(port, &remote) {
                Ok(bound) => print_line(&format!(
                    "[forward] 转发已启动: 127.0.0.1:{} -> {}（在目标进程内连接）",
                    bound, remote
                )),
                Err(e) => print_line(&format!("[forward] {}", e)),
            }
        }
        _ => print_line("[forward] 用法: forward <local_port> [host:port]（省略 host 视为 127.0.0.1）"),
    }
}

fn print_forwards(session: &Arc<Session>) {
    let forwards = session.channels().list();
    if forwards.is_empty() {
        print_line("没有正在进行的端口转发");
        return;
    }
    print_line("本地转发：");
    for f in forwards {
        print_line(&format!(
            "  127.0.0.1:{} -> {}（活跃连接 {}）",
            f.local_port, f.remote, f.active_connections
        ));
    }
}

fn print_help() {
    print_line("命令：");
    for (cmd, args, desc) in COMMANDS {
        print_line(&format!("  {:<12} {:<24} {}", cmd, args, desc));
    }
}

/// 该命令名是否已知（用于给出比「命令被送进 JS 求值」更清晰的报错）。
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
            | "jslist"
            | "jsdrop"
            | "capture"
            | "forward"
            | "unforward"
            | "forwards"
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
            | "detach"
            | "shutdown"
    )
}

/// stdin EOF 后保持连接，只要有入站帧就把空闲计时重置。
///
/// 用轮询 `last_activity_millis` 而不是事件通道：事件通道已被打印线程独占，
/// 这里只需知道「有没有活动」，一个时间戳就够。
fn wait_for_log_idle(session: &Arc<Session>, idle: Duration) {
    let mut last_seen = session.last_activity_millis();
    let mut deadline = Instant::now() + idle;
    loop {
        if session.is_disconnected() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        thread::sleep(remaining.min(Duration::from_millis(50)));
        let current = session.last_activity_millis();
        if current != last_seen {
            last_seen = current;
            deadline = Instant::now() + idle;
        }
    }
}

/// 供测试/调试：把 jseval 包装结果暴露出来（与设备端保持一致性的断言点）。
#[allow(dead_code)]
pub fn wrap_jseval_for_test(expr: &str) -> String {
    wrap_jseval_expr(expr)
}

#[allow(dead_code)]
pub fn js_literal_for_test(value: &str) -> String {
    js_string_literal(value)
}
