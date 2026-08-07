//! 交互式 REPL：发送 CMD 帧，读取并展示 agent 帧。
//!
//! 命令面与设备端 rustfrida 对齐（jsinit/jseval/loadjs/jsclean/rpccall/hfl/trace/stalker…）。
//! `jsrepl` 是设备端子 REPL（读设备 stdin），TCP 下不可用，用 jseval 逐行求值替代。

use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::proto::*;

const EVAL_TIMEOUT_SECS: u64 = 30;

/// 与设备端 repl.rs 一致的 jseval 错误前缀（用于识别格式化后的错误）
const JSEVAL_ERROR_PREFIX: &str = "__RF_JSEVAL_ERROR__:";

const COMMANDS: &[(&str, &str, &str)] = &[
    ("jsinit", "", "初始化 QuickJS 引擎"),
    ("jseval", "<expr>", "求值 JS 表达式并显示结果"),
    ("loadjs", "<file>", "加载本地 JS 脚本文件（自动初始化引擎）"),
    ("jsclean", "", "清理 QuickJS 引擎"),
    ("rpccall", "<method> [args]", "调用 rpc.exports 方法（args 为 JSON 数组）"),
    ("hfl", "<module> <offset>", "Interceptor hook 指定偏移"),
    ("trace", "[tid]", "ptrace 指令追踪"),
    ("stalker", "[tid]", "Frida Stalker 追踪"),
    ("jhook", "", "Java/JNI hooking"),
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
    if let Some(file) = OUTPUT_FILE.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        let _ = writeln!(file, "{}", s);
        let _ = file.flush();
    }
}

/// 后台读线程送到主线程的入站消息
enum Incoming {
    Eval(Result<String, String>),
    Rpc(Result<String, String>),
    /// jscomplete 补全候选（当前版本未启用 jsrepl，保留供后续使用）
    #[allow(dead_code)]
    Complete(Vec<String>),
}

#[derive(Clone, Copy, PartialEq)]
enum IncomingKind {
    Eval,
    Rpc,
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
pub fn run(stream: &mut TcpStream, eof_linger: Duration) -> Result<(), String> {
    // 清除读/写超时：中继后 agent 可能长时间无输出（日志/交互），不能被之前设置的 30s 超时打断
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);

    let reader = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;
    let (tx, rx) = channel::<Incoming>();
    let (activity_tx, activity_rx) = sync_channel::<()>(1);
    let disconnected = Arc::new(AtomicBool::new(false));

    let disconnected_reader = disconnected.clone();
    thread::Builder::new()
        .name("rf-recv".into())
        .spawn(move || receiver_loop(reader, tx, activity_tx, disconnected_reader))
        .map_err(|e| format!("spawn recv thread: {}", e))?;

    let mut writer = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;

    let mut rl = Editor::new().map_err(|e| format!("初始化行编辑器失败: {}", e))?;
    rl.set_helper(Some(CommandCompleter));
    let _ = rl.load_history(".rfclient_history");

    print_line("输入 help 查看命令，exit 退出");

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
                    let _ = send_cmd(&mut writer, "shutdown");
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
                if line == "jsrepl" {
                    print_line("[jsrepl] 设备端 jsrepl 需要本地 stdin，TCP 下请用 jseval 逐行求值");
                    continue;
                }
                if !is_known_command(&line) {
                    let name = line.split_whitespace().next().unwrap_or("(empty)");
                    print_line(&format!(
                        "[rfclient] 无效命令 '{}'，输入 help 查看可用命令",
                        name
                    ));
                    continue;
                }

                let (is_eval, is_rpc) = if let Some(rest) = line.strip_prefix("loadjs ") {
                    // 本地读文件，按 agent 的 loadjs_init [filename]\n<script> 格式发送
                    // （loadjs_init 自动初始化引擎，与设备端 -l 加载路径一致）
                    let path = rest.trim();
                    match std::fs::read_to_string(path) {
                        Ok(content) => {
                            let name = std::path::Path::new(path)
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("script.js");
                            let cmd = format!("loadjs_init [{}]\n{}", name, content);
                            if let Err(e) = send_cmd(&mut writer, &cmd) {
                                eprintln!("发送失败: {}", e);
                                break;
                            }
                            (true, false)
                        }
                        Err(e) => {
                            print_line(&format!("[loadjs] 读取 '{}' 失败: {}", path, e));
                            continue;
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("jseval ") {
                    // 与设备端一致：包装 jseval 表达式（友好错误提示 + 值字符串化）
                    let cmd = format!("jseval {}", wrap_jseval_expr(rest));
                    if let Err(e) = send_cmd(&mut writer, &cmd) {
                        eprintln!("发送失败: {}", e);
                        break;
                    }
                    (true, false)
                } else if let Some(rest) = line.strip_prefix("rpccall ") {
                    let cmd = format!("rpccall {}", rest.trim());
                    if let Err(e) = send_cmd(&mut writer, &cmd) {
                        eprintln!("发送失败: {}", e);
                        break;
                    }
                    (false, true)
                } else {
                    if let Err(e) = send_cmd(&mut writer, &line) {
                        eprintln!("发送失败: {}", e);
                        break;
                    }
                    (expects_response(&line), false)
                };

                // 无响应命令（trace/stalker/__set_verbose__ 等）只产生 LOG 帧，不等待 eval
                if !is_eval && !is_rpc {
                    continue;
                }
                let kind = if is_rpc { IncomingKind::Rpc } else { IncomingKind::Eval };
                match wait_response(&rx, kind, EVAL_TIMEOUT_SECS) {
                    Some(Ok(text)) => {
                        // 设备端包装的错误会以 __RF_JSEVAL_ERROR__: 前缀返回在 EVAL_OK
                        if let Some(err) = text.strip_prefix(JSEVAL_ERROR_PREFIX) {
                            print_line(&format!("[错误] {}", err));
                        } else {
                            print_line(&format!("=> {}", text));
                        }
                    }
                    Some(Err(e)) => print_line(&format!("[错误] {}", e)),
                    None => print_line(&format!("[超时] 等待响应超过 {}s", EVAL_TIMEOUT_SECS)),
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
    Ok(())
}

fn print_help() {
    print_line("命令：");
    for (cmd, args, desc) in COMMANDS {
        print_line(&format!("  {:<12} {:<24} {}", cmd, args, desc));
    }
}

fn send_cmd(stream: &mut TcpStream, cmd: &str) -> std::io::Result<()> {
    write_frame(stream, FRAME_KIND_CMD, cmd.as_bytes())
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
            | "detach"
            | "shutdown"
    )
}

/// 等待指定类型的响应；忽略其他类型（如 LOG 已由接收线程打印，不会进 channel）。
fn wait_response(
    rx: &Receiver<Incoming>,
    kind: IncomingKind,
    timeout_secs: u64,
) -> Option<Result<String, String>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return None;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(Incoming::Eval(r)) => {
                if kind == IncomingKind::Eval {
                    return Some(r);
                }
            }
            Ok(Incoming::Rpc(r)) => {
                if kind == IncomingKind::Rpc {
                    return Some(r);
                }
            }
            Ok(Incoming::Complete(_)) => {}
            Err(_) => return None,
        }
    }
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

/// 后台接收线程：读帧，LOG/HELLO/BYE 直接打印，EVAL/RPC/COMPLETE 送入 channel。
fn receiver_loop(
    mut reader: TcpStream,
    tx: Sender<Incoming>,
    activity_tx: SyncSender<()>,
    disconnected: Arc<AtomicBool>,
) {
    loop {
        match read_frame(&mut reader) {
            Ok((kind, payload)) => {
                let _ = activity_tx.try_send(());
                match kind {
                    FRAME_KIND_LOG => {
                        let msg = String::from_utf8_lossy(&payload);
                        let msg = msg.strip_suffix('\n').unwrap_or(&msg);
                        if !msg.is_empty() {
                            print_line(&format!("[agent] {}", msg));
                        }
                    }
                    FRAME_KIND_HELLO => {
                        print_line("[agent] 已连接");
                    }
                    FRAME_KIND_EVAL_OK => {
                        let _ = tx.send(Incoming::Eval(Ok(String::from_utf8_lossy(&payload).into_owned())));
                    }
                    FRAME_KIND_EVAL_ERR => {
                        let _ = tx.send(Incoming::Eval(Err(String::from_utf8_lossy(&payload).into_owned())));
                    }
                    FRAME_KIND_RPC_OK => {
                        let _ = tx.send(Incoming::Rpc(Ok(String::from_utf8_lossy(&payload).into_owned())));
                    }
                    FRAME_KIND_RPC_ERR => {
                        let _ = tx.send(Incoming::Rpc(Err(String::from_utf8_lossy(&payload).into_owned())));
                    }
                    FRAME_KIND_COMPLETE => {
                        let text = String::from_utf8_lossy(&payload);
                        let candidates: Vec<String> = text
                            .split('\t')
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                        let _ = tx.send(Incoming::Complete(candidates));
                    }
                    FRAME_KIND_BYE => {
                        print_line("[agent] 已断开 (BYE)");
                        disconnected.store(true, Ordering::Release);
                        break;
                    }
                    other => {
                        print_line(&format!("[agent] 未知帧 kind: {}", other));
                    }
                }
            }
            Err(e) => {
                print_line(&format!("[agent] 连接断开: {}", e));
                disconnected.store(true, Ordering::Release);
                let _ = activity_tx.try_send(());
                break;
            }
        }
    }
}
