#![cfg(all(target_os = "android", target_arch = "aarch64"))]

//! Server daemon 模式：多 session 并发 spawn/inject，--profile 持续生效。
//!
//! 两层 REPL:
//!   server>          — 管理命令 (spawn/attach/list/use/detach/help/exit)
//!   rustfrida#N>     — session 命令 (jsinit/loadjs/jsrepl/..., back 返回)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Editor, Helper};

use crate::args::{Args, DEFAULT_LISTEN_ADDR};
use crate::communication::{
    read_frame, send_command, start_socketpair_handler, start_tcp_relay, FRAME_KIND_BOOTSTRAP_SCRIPT,
};
use crate::injection::{cleanup_remote_loader_mappings, inject_via_bootstrapper, LoaderCleanupInfo};
use crate::process::find_pid_by_name;
use crate::repl::{
    cut_pre_resume_java_executor_hook, ensure_java_worker_ready, ensure_java_worker_ready_after_resume, pre_resume_art_init,
    preconfigure_java_stealth_if_declared, print_eval_result, print_help, rewrite_jseval_for_agent, run_js_repl,
    script_uses_java_api, try_jseval_on_main_thread_if_java_or_dsl, try_loadjs_on_main_thread_if_java,
    try_managedcounter_on_main_thread, EVAL_DEFAULT_TIMEOUT_SECS, EVAL_JAVA_TIMEOUT_SECS, EVAL_RECOMP_TIMEOUT_SECS,
    LOAD_DEFAULT_TIMEOUT_SECS, LOAD_JAVA_TIMEOUT_SECS, LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS,
    LOAD_STOP_WORKER_TIMEOUT_SECS,
};
use crate::session::{Session, SessionManager};
use crate::spawn;
use crate::{log_error, log_info, log_success, log_warn};

const SESSION_CONNECT_TIMEOUT_SECS: u64 = 10;
const TCP_BOOTSTRAP_TIMEOUT_SECS: u64 = 15;
/// 注入结果等待超时：注入可能含 pre-resume 脚本加载，给足余量
const TCP_INJECT_WAIT_TIMEOUT_SECS: u64 = 60;
const MAX_TCP_BOOTSTRAP_LINE_BYTES: usize = 8 * 1024;
/// Optional fallback for KPM builds that still have a fork/PTE race. The normal
/// path keeps Frida-style pre-resume script timing; set this variable only when
/// a target kernel needs the post-resume delay.
const WXSHADOW_SPAWN_SETTLE_MS: u64 = 1000;
const WXSHADOW_SAFE_DELAY_ENV: &str = "RF_WXSHADOW_SAFE_DELAY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptLoadState {
    Loaded { needs_post_resume_java_worker: bool },
    Failed,
}

/// A script may originate from the device-side REPL or from the host-side
/// rfclient. Host scripts are transferred over the control connection and are
/// never resolved against the device filesystem.
#[derive(Clone)]
enum ScriptSource {
    DevicePath(String),
    HostText { filename: String, content: String },
}

impl ScriptLoadState {
    fn failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    fn needs_post_resume_java_worker(&self) -> bool {
        match self {
            Self::Loaded {
                needs_post_resume_java_worker,
            } => *needs_post_resume_java_worker,
            Self::Failed => false,
        }
    }
}

// ────────────────────────── Server 命令补全 ──────────────────────────

const SERVER_CMDS: &[(&str, &str, &str)] = &[
    ("spawn", "<package> [-l script.js]", "Spawn 模式注入 App"),
    ("attach", "<pid|name> [-l script.js]", "按 PID 或进程名注入"),
    ("list", "", "列出所有 session"),
    ("sessions", "", "列出所有 session（同 list）"),
    ("use", "<id>", "进入指定 session 的交互模式"),
    ("detach", "<id>", "断开指定 session"),
    ("detachall", "", "断开所有 session"),
    ("help", "", "显示帮助"),
    ("exit", "", "退出 server（quit 同效）"),
];

struct ServerCompleter;

impl Completer for ServerCompleter {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        if before.contains(' ') {
            return Ok((pos, vec![]));
        }
        let candidates: Vec<Pair> = SERVER_CMDS
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
impl Hinter for ServerCompleter {
    type Hint = String;
}
impl Highlighter for ServerCompleter {}
impl Validator for ServerCompleter {}
impl Helper for ServerCompleter {}

// ────────────────────────── Session 命令补全 ──────────────────────────

/// Session 模式补全器：在 CommandCompleter 基础上追加 back 命令
struct SessionModeCompleter;

impl SessionModeCompleter {
    fn new() -> Self {
        SessionModeCompleter
    }
}

impl Completer for SessionModeCompleter {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before = &line[..pos];
        if before.contains(' ') {
            return Ok((pos, vec![]));
        }
        let extra = ["back", "server"];
        let candidates: Vec<Pair> = crate::repl::commands()
            .iter()
            .map(|(cmd, _, _)| *cmd)
            .chain(extra.iter().copied())
            .filter(|cmd| cmd.starts_with(before))
            .map(|cmd| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}
impl Hinter for SessionModeCompleter {
    type Hint = String;
}
impl Highlighter for SessionModeCompleter {}
impl Validator for SessionModeCompleter {}
impl Helper for SessionModeCompleter {}

// ────────────────────────── 辅助函数 ──────────────────────────

/// 解析 spawn/attach 行中的 -l <script> 参数
fn parse_script_flag(parts: &[&str]) -> (Vec<String>, Option<String>) {
    let mut positional = vec![];
    let mut script = None;
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == "-l" && i + 1 < parts.len() {
            script = Some(parts[i + 1].to_string());
            i += 2;
        } else {
            positional.push(parts[i].to_string());
            i += 1;
        }
    }
    (positional, script)
}

/// Detect the public WXSHADOW mode in a script before spawn resumes the child.
/// The marker check is deliberately limited to the public API spellings used by
/// the current scripts; it is not a general-purpose JavaScript parser.
fn script_declares_wxshadow(source: &ScriptSource) -> bool {
    let script = match source {
        ScriptSource::DevicePath(path) => match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(_) => return false,
        },
        ScriptSource::HostText { content, .. } => content.clone(),
    };

    [
        "Hook.WXSHADOW",
        "Hook[\"WXSHADOW\"]",
        "Hook['WXSHADOW']",
        "Java.WXSHADOW",
    ]
    .iter()
    .any(|marker| script.contains(marker))
}

/// 在目标进程暂停期间加载脚本（用于 spawn 模式）
fn load_script_on_session(session: &Session, source: &ScriptSource, stop_worker_after_load: bool) -> ScriptLoadState {
    if session.get_sender().is_none() {
        log_error!("[#{}] agent 未连接，无法加载脚本", session.id);
        return ScriptLoadState::Failed;
    }
    let (script_name, script) = match source {
        ScriptSource::DevicePath(path) => match std::fs::read_to_string(path) {
            Ok(s) => (
                std::path::Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("script.js")
                    .to_string(),
                s,
            ),
            Err(e) => {
                log_error!("[#{}] 读取脚本 '{}' 失败: {}", session.id, path, e);
                return ScriptLoadState::Failed;
            }
        },
        ScriptSource::HostText { filename, content } => (filename.clone(), content.clone()),
    };

    if script.is_empty() {
        log_info!("[#{}] 脚本为空，跳过加载: {}", session.id, script_name);
        return ScriptLoadState::Loaded {
            needs_post_resume_java_worker: false,
        };
    }

    if let Err(e) = preconfigure_java_stealth_if_declared(session, &script) {
        log_error!("[#{}] {}", session.id, e);
        return ScriptLoadState::Failed;
    }

    let uses_java_api = script_uses_java_api(&script);
    let deferred_pre_resume_java =
        uses_java_api && stop_worker_after_load && !session.java_worker_ready.load(Ordering::Acquire);
    if deferred_pre_resume_java {
        log_info!(
            "[#{}] 检测到 pre-resume Java 脚本，先发送到 raw clone TLS JS worker 执行",
            session.id
        );
    } else if uses_java_api {
        log_info!("[#{}] 检测到 Java 脚本，发送到 Java worker 执行", session.id);
    } else {
        log_info!("[#{}] 脚本发送到 raw clone TLS JS worker 执行", session.id);
    }
    session.eval_state.clear();
    let filename = script_name;
    let load_result = if uses_java_api {
        if deferred_pre_resume_java {
            match session.get_sender() {
                Some(sender) => {
                    send_command(sender, format!("loadjs_init [{}]\n{}", filename, script)).map_err(|e| e.to_string())
                }
                None => Err("agent 未连接".to_string()),
            }
        } else {
            match ensure_java_worker_ready(session) {
                Ok(()) => {
                    crate::process::thaw_cgroup_freezer(session.pid.load(Ordering::Acquire));
                    session.eval_state.clear();
                    match session.get_sender() {
                        Some(sender) => send_command(sender, format!("java_loadjs [{}]\n{}", filename, script))
                            .map_err(|e| e.to_string()),
                        None => Err("agent 未连接".to_string()),
                    }
                }
                Err(e) => Err(e),
            }
        }
    } else {
        match session.get_sender() {
            Some(sender) => {
                send_command(sender, format!("loadjs_init [{}]\n{}", filename, script)).map_err(|e| e.to_string())
            }
            None => Err("agent 未连接".to_string()),
        }
    };
    match load_result {
        Ok(()) => {
            if deferred_pre_resume_java {
                match session
                    .eval_state
                    .recv_timeout(std::time::Duration::from_secs(LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS))
                {
                    None => {
                        log_error!(
                            "[#{}] pre-resume Java 脚本执行超时({}s)，未恢复子进程以避免错过早期 Java hook",
                            session.id,
                            LOAD_PRE_RESUME_JAVA_TIMEOUT_SECS
                        );
                        return ScriptLoadState::Failed;
                    }
                    Some(Err(e)) => {
                        log_error!("[#{}] pre-resume Java 脚本执行失败: {}", session.id, e);
                        return ScriptLoadState::Failed;
                    }
                    Some(Ok(out)) => {
                        if !out.is_empty() {
                            log_success!("[#{}] => {}", session.id, out);
                        }
                    }
                }
                if let Err(e) = cut_pre_resume_java_executor_hook(session) {
                    log_error!("[#{}] pre-resume Java executor hook 切断失败: {}", session.id, e);
                    return ScriptLoadState::Failed;
                }
                return ScriptLoadState::Loaded {
                    needs_post_resume_java_worker: true,
                };
            }
            match session
                .eval_state
                .recv_timeout(std::time::Duration::from_secs(if stop_worker_after_load {
                    LOAD_STOP_WORKER_TIMEOUT_SECS
                } else if uses_java_api {
                    LOAD_JAVA_TIMEOUT_SECS
                } else {
                    LOAD_DEFAULT_TIMEOUT_SECS
                })) {
                None => log_warn!("[#{}] 脚本加载超时", session.id),
                Some(Err(e)) => log_error!("[#{}] 脚本执行失败: {}", session.id, e),
                Some(Ok(out)) => {
                    if !out.is_empty() {
                        log_success!("[#{}] => {}", session.id, out);
                    }
                }
            }
        }
        Err(e) => log_error!("[#{}] 主线程加载脚本失败: {}", session.id, e),
    }
    ScriptLoadState::Loaded {
        needs_post_resume_java_worker: uses_java_api,
    }
}

/// 发送 shutdown 并等待 agent 断连
fn shutdown_session(session: &Session) {
    if !session.disconnected.load(Ordering::Acquire) {
        let sender = match session.get_sender() {
            Some(s) => s,
            None => return,
        };
        session.shutdown_requested.store(true, Ordering::Release);
        let _ = send_command(sender, "shutdown");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !session.disconnected.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    if session.disconnected.load(Ordering::Acquire) {
        cleanup_remote_loader_mappings(session.pid.load(Ordering::Acquire), session.loader_cleanup_info());
    } else {
        log_warn!("[#{}] Agent 未在清理窗口内断开，保留目标资源避免并发破坏", session.id);
    }
}

// ────────────────────────── TCP 控制服务器（主机端 rfclient 接入）──────────────────────────

/// 启动 TCP 控制服务器：接受主机端 rfclient 连接，执行引导请求后进入帧级中继。
///
/// 引导协议（文本行，\n 结尾）：
///   list                          → 每行 `id\tpid\tlabel\tstatus`，空行结束
///   attach <pid|name> [-l script] → `OK sid=<id> pid=<pid>` / `ERR <msg>`
///   spawn <package> [-l script]   → 同上
///   use <session_id>              → `OK sid=<id> pid=<pid>` / `ERR <msg>`
///   exit                          → 关闭连接
pub(crate) fn run_tcp_server(
    mgr: Arc<SessionManager>,
    bind_addr: &str,
    string_overrides: HashMap<String, String>,
    verbose: bool,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind_addr).map_err(|e| format!("TCP bind {} 失败: {}", bind_addr, e))?;
    let actual = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind_addr.to_string());
    log_success!("TCP 控制服务器监听 {}", actual);
    log_info!("  rfclient -H {} list / attach <pid> / spawn <pkg> / use <sid>", actual);

    thread::Builder::new()
        .name("wwb-tcpacc".into())
        .spawn(move || tcp_accept_loop(listener, mgr, string_overrides, verbose))
        .map_err(|e| format!("spawn wwb-tcpacc 失败: {}", e))?;
    Ok(())
}

fn tcp_accept_loop(
    listener: TcpListener,
    mgr: Arc<SessionManager>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
) {
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let mgr = mgr.clone();
                let overrides = string_overrides.clone();
                let _ = thread::Builder::new().name("wwb-tcpconn".into()).spawn(move || {
                    if let Err(e) = handle_tcp_client(s, mgr, overrides, verbose) {
                        log_error!("TCP 客户端处理失败: {}", e);
                    }
                });
            }
            Err(e) => {
                log_error!("TCP accept 失败: {}", e);
            }
        }
    }
}

/// 处理单个 TCP 客户端：读引导请求 → 建会话/注入 → 回复 → 进入帧级中继。
fn handle_tcp_client(
    mut stream: TcpStream,
    mgr: Arc<SessionManager>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(TCP_BOOTSTRAP_TIMEOUT_SECS)))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(TCP_BOOTSTRAP_TIMEOUT_SECS)))
        .map_err(|e| format!("set_write_timeout: {}", e))?;

    let write_stream = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;

    // Read exactly one bootstrap line. A buffered reader is unsafe here because
    // the following protocol is binary framed on this same TCP connection.
    let line = match read_tcp_bootstrap_line(&mut stream)? {
        Some(line) => line,
        None => return Ok(()), // 客户端直接断开
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        write_line(&write_stream, "ERR empty request")?;
        return Ok(());
    }

    match parts[0] {
        "list" => {
            let sessions = mgr.list_sessions();
            let mut out = String::new();
            for (id, pid, label, status, _active) in &sessions {
                out.push_str(&format!("{}\t{}\t{}\t{}\n", id, pid, label, status));
            }
            out.push('\n'); // 空行结束
            write_all(&write_stream, out.as_bytes())?;
            Ok(())
        }
        "attach" | "spawn" => {
            let (positional, script) = parse_script_flag(&parts[1..]);
            if positional.is_empty() {
                write_line(
                    &write_stream,
                    "ERR 用法: attach <pid|name> [-l script] 或 spawn <package> [-l script]",
                )?;
                return Ok(());
            }
            let target = &positional[0];
            let script = match script {
                Some(path) if path == "-" => match read_host_script_frame(&mut stream) {
                    Ok(source) => Some(source),
                    Err(e) => {
                        write_line(&write_stream, &format!("ERR {}", e))?;
                        return Ok(());
                    }
                },
                Some(path) => Some(ScriptSource::DevicePath(path)),
                None => None,
            };

            let session = mgr.create_session(target.clone());
            session.mark_tcp_owned();
            // Do not emit binary frames before the client has read its textual
            // OK response. Agent output is retained and flushed by start_tcp_relay.
            session.prepare_relay();
            let (tx, rx) = channel();
            if parts[0] == "spawn" {
                log_info!("[#{}] TCP spawn {}...", session.id, target);
                do_spawn(
                    session.clone(),
                    target.clone(),
                    script,
                    string_overrides,
                    verbose,
                    Some(tx),
                );
            } else {
                // attach: 数字 → PID，否则按进程名查找
                let (pid, label) = if let Ok(p) = target.parse::<i32>() {
                    (p, format!("PID:{}", p))
                } else {
                    match find_pid_by_name(target) {
                        Ok(p) => (p, target.clone()),
                        Err(e) => {
                            session.clear_relay();
                            mgr.remove_session(session.id);
                            write_line(&write_stream, &format!("ERR {}", e))?;
                            return Ok(());
                        }
                    }
                };
                log_info!("[#{}] TCP attach {} (PID: {})...", session.id, label, pid);
                do_attach(session.clone(), pid, label, script, string_overrides, verbose, Some(tx));
            }

            // 等待注入结果（注入可能含 pre-resume 脚本加载，给足超时）
            match rx.recv_timeout(Duration::from_secs(TCP_INJECT_WAIT_TIMEOUT_SECS)) {
                Ok(Ok(pid)) => {
                    if let Err(e) = write_line(&write_stream, &format!("OK sid={} pid={}", session.id, pid)) {
                        session.clear_relay();
                        log_info!(
                            "[#{}] TCP 客户端在 bootstrap 完成前断开，session 保留；可用 use {} 重新连接",
                            session.id,
                            session.id
                        );
                        return Err(e);
                    }
                    // 清除超时：进入中继后 TCP 可能长时间空闲（日志/交互），不能被 15s 读超时打断
                    let _ = stream.set_read_timeout(None);
                    let _ = stream.set_write_timeout(None);
                    // 进入帧级中继。TCP 连接只是控制面，断开时保留 session，
                    // 避免把 WXSHADOW 的内核补丁释放绑定到电脑端进程退出时刻。
                    let sid = session.id;
                    start_tcp_relay(
                        stream,
                        session,
                        Some(Box::new(move || {
                            log_info!("[#{}] TCP 客户端断开，session 保留；可用 use {} 重新连接", sid, sid);
                        })),
                    );
                    Ok(())
                }
                Ok(Err(e)) => {
                    write_line(&write_stream, &format!("ERR {}", e))?;
                    session.clear_relay();
                    mgr.remove_session(session.id);
                    Ok(())
                }
                Err(_) => {
                    // 注入超时或通道断开
                    write_line(&write_stream, "ERR 注入超时")?;
                    session.clear_relay();
                    mgr.remove_session(session.id);
                    Ok(())
                }
            }
        }
        "use" => {
            if parts.len() < 2 {
                write_line(&write_stream, "ERR 用法: use <session_id>")?;
                return Ok(());
            }
            let id: u32 = match parts[1].parse() {
                Ok(id) => id,
                Err(_) => {
                    write_line(&write_stream, &format!("ERR 无效 session id: {}", parts[1]))?;
                    return Ok(());
                }
            };
            let session = match mgr.get_session(id) {
                Some(s) => s,
                None => {
                    write_line(&write_stream, &format!("ERR session #{} 不存在", id))?;
                    return Ok(());
                }
            };
            if !session.is_connected() {
                write_line(
                    &write_stream,
                    &format!("ERR session #{} 未连接 (status: {})", id, session.status()),
                )?;
                return Ok(());
            }
            if session.has_active_relay() {
                write_line(&write_stream, &format!("ERR session #{} 已由其他 TCP 客户端控制", id))?;
                return Ok(());
            }
            session.mark_tcp_owned();
            write_line(
                &write_stream,
                &format!("OK sid={} pid={}", id, session.pid.load(Ordering::Relaxed)),
            )?;
            // 复用已有会话：只中继，不 shutdown（会话归属其创建者）
            let _ = stream.set_read_timeout(None);
            let _ = stream.set_write_timeout(None);
            start_tcp_relay(stream, session, None);
            Ok(())
        }
        "exit" | "quit" => Ok(()),
        other => {
            write_line(&write_stream, &format!("ERR 未知命令: {}", other))?;
            Ok(())
        }
    }
}

fn read_tcp_bootstrap_line(stream: &mut TcpStream) -> Result<Option<String>, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|e| format!("read bootstrap line: {}", e))?;
        if n == 0 {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() == MAX_TCP_BOOTSTRAP_LINE_BYTES {
            return Err(format!(
                "bootstrap request exceeds {} bytes",
                MAX_TCP_BOOTSTRAP_LINE_BYTES
            ));
        }
        line.push(byte[0]);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map(Some)
        .map_err(|_| "bootstrap request is not valid UTF-8".to_string())
}

fn read_host_script_frame(stream: &mut TcpStream) -> Result<ScriptSource, String> {
    let (kind, payload) = read_frame(stream).map_err(|e| format!("read host script frame: {}", e))?;
    if kind != FRAME_KIND_BOOTSTRAP_SCRIPT {
        return Err(format!("unexpected bootstrap frame kind: {}", kind));
    }
    if payload.len() < 4 {
        return Err("host script frame is truncated".to_string());
    }
    let filename_len = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
    if filename_len == 0 || filename_len > 256 || 4 + filename_len > payload.len() {
        return Err("invalid host script filename".to_string());
    }
    let filename = String::from_utf8(payload[4..4 + filename_len].to_vec())
        .map_err(|_| "host script filename is not valid UTF-8".to_string())?;
    let content = String::from_utf8(payload[4 + filename_len..].to_vec())
        .map_err(|_| "host script is not valid UTF-8".to_string())?;
    Ok(ScriptSource::HostText { filename, content })
}

fn write_line(stream: &TcpStream, s: &str) -> Result<(), String> {
    let mut s = s.to_string();
    s.push('\n');
    write_all(stream, s.as_bytes())
}

fn write_all(stream: &TcpStream, data: &[u8]) -> Result<(), String> {
    let mut st = stream.try_clone().map_err(|e| format!("clone stream: {}", e))?;
    st.write_all(data).map_err(|e| format!("write: {}", e))
}

// ────────────────────────── 后台 spawn/inject ──────────────────────────

fn do_spawn(
    session: Arc<Session>,
    package: String,
    script: Option<ScriptSource>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
    result: Option<Sender<Result<u32, String>>>,
) {
    let sid = session.id;
    std::thread::Builder::new()
        .name("wwb-spawn".into())
        .spawn(move || {
            // ensure_zymbiote_loaded 内部有幂等保护，并发安全
            match spawn::spawn_and_inject(&package, &string_overrides) {
                Ok((pid, injection)) => {
                    session.pid.store(pid, Ordering::Relaxed);
                    session.set_remote_agent_info(injection.loader_ctx_addr, injection.agent_current_thread_eval_impl);
                    session.set_loader_cleanup_info(LoaderCleanupInfo::from(&injection));
                    let _handle = start_socketpair_handler(injection.host_fd, session.clone());

                    if !session.wait_connected(SESSION_CONNECT_TIMEOUT_SECS) {
                        log_error!("[#{}] 等待 agent 连接超时", sid);
                        session.failed.store(true, Ordering::Release);
                        // 尝试恢复子进程
                        let _ = spawn::resume_child(pid as u32);
                        if let Some(tx) = &result {
                            let _ = tx.send(Err(format!("[#{}] 等待 agent 连接超时", sid)));
                        }
                        return;
                    }

                    // 传递 verbose 标志
                    if verbose {
                        if let Some(sender) = session.get_sender() {
                            let _ = send_command(sender, "__set_verbose__");
                        }
                    }

                    // 默认在 spawn 停止态完成脚本加载，保持 Frida 语义并捕获
                    // 最早期的 RegisterNatives。KPM 已修正 fork pause 的状态竞态；
                    // 如目标内核仍有旧版 PTE 问题，可通过环境变量显式启用延后模式。
                    let mut post_resume_java_worker_needed = false;
                    let defer_wxshadow_script = script.as_ref().map(script_declares_wxshadow).unwrap_or(false)
                        && std::env::var_os(WXSHADOW_SAFE_DELAY_ENV).is_some();
                    if defer_wxshadow_script {
                        log_warn!(
                            "[#{}] 检测到 {}，Hook.WXSHADOW 延后到 spawn 恢复后加载（{}ms）",
                            sid,
                            WXSHADOW_SAFE_DELAY_ENV,
                            WXSHADOW_SPAWN_SETTLE_MS
                        );
                    }
                    if let Some(ref script_source) = script {
                        if !defer_wxshadow_script {
                            let load_state = load_script_on_session(&session, script_source, true);
                            if load_state.failed() {
                                session.failed.store(true, Ordering::Release);
                                spawn::abort_pending_children_and_cleanup_zygote_patches();
                                if let Some(tx) = &result {
                                    let _ = tx.send(Err(format!("[#{}] 脚本执行失败", sid)));
                                }
                                return;
                            }
                            post_resume_java_worker_needed |= load_state.needs_post_resume_java_worker();
                        }
                    }

                    // 方案 A: 进程仍处于暂停态 (SIGSTOP), 此刻安装 artController 拦截矩阵零竞态。
                    // 旧版在 resume 后由 hook 安装路径触发矩阵安装, 与 onCreate 反射热点路径竞态,
                    // 导致主线程自旋卡死 16-29s。这里提前到暂停态预装, 从根上消除该竞态。
                    if post_resume_java_worker_needed {
                        if let Err(e) = pre_resume_art_init(&session) {
                            log_warn!("[#{}] pre-resume artController 预装失败 (回退到 resume 后按需安装): {}", sid, e);
                        }
                    }
                    // resume 子进程
                    if let Err(e) = spawn::resume_child(pid as u32) {
                        log_error!("[#{}] 恢复子进程失败: {}", sid, e);
                    }

                    if defer_wxshadow_script {
                        std::thread::sleep(std::time::Duration::from_millis(WXSHADOW_SPAWN_SETTLE_MS));
                        if let Some(ref script_source) = script {
                            if load_script_on_session(&session, script_source, false).failed() {
                                session.failed.store(true, Ordering::Release);
                                if let Some(tx) = &result {
                                    let _ = tx.send(Err(format!("[#{}] WXSHADOW 脚本执行失败", sid)));
                                }
                                return;
                            }
                        }
                    }
                    if let Err(e) = ensure_java_worker_ready_after_resume(&session, post_resume_java_worker_needed) {
                        log_warn!(
                            "[#{}] Java worker 启动失败，后续 Java 操作需要重新初始化 worker: {}",
                            sid,
                            e
                        );
                    }

                    log_success!("[#{}] {} 已就绪 (PID: {})", sid, package, pid);
                    if let Some(tx) = &result {
                        let _ = tx.send(Ok(pid as u32));
                    }
                }
                Err(e) => {
                    log_error!("[#{}] Spawn {} 失败: {}", sid, package, e);
                    session.failed.store(true, Ordering::Release);
                    if let Some(tx) = &result {
                        let _ = tx.send(Err(format!("spawn {} 失败: {}", package, e)));
                    }
                }
            }
        })
        .expect("spawn wwb-spawn thread");
}

fn do_attach(
    session: Arc<Session>,
    pid: i32,
    label: String,
    script: Option<ScriptSource>,
    string_overrides: HashMap<String, String>,
    verbose: bool,
    result: Option<Sender<Result<u32, String>>>,
) {
    let sid = session.id;
    std::thread::Builder::new()
        .name("wwb-attach".into())
        .spawn(move || {
            match inject_via_bootstrapper(pid, &string_overrides) {
                Ok(injection) => {
                    session.pid.store(pid, Ordering::Relaxed);
                    session.set_remote_agent_info(injection.loader_ctx_addr, injection.agent_current_thread_eval_impl);
                    session.set_loader_cleanup_info(LoaderCleanupInfo::from(&injection));
                    let _handle = start_socketpair_handler(injection.host_fd, session.clone());

                    if !session.wait_connected(SESSION_CONNECT_TIMEOUT_SECS) {
                        log_error!("[#{}] 等待 agent 连接超时", sid);
                        session.failed.store(true, Ordering::Release);
                        if let Some(tx) = &result {
                            let _ = tx.send(Err(format!("[#{}] 等待 agent 连接超时", sid)));
                        }
                        return;
                    }

                    if verbose {
                        if let Some(sender) = session.get_sender() {
                            let _ = send_command(sender, "__set_verbose__");
                        }
                    }

                    // 非 spawn 模式：先连接再加载脚本
                    if let Some(ref script_source) = script {
                        if load_script_on_session(&session, script_source, false).failed() {
                            session.failed.store(true, Ordering::Release);
                            if let Some(tx) = &result {
                                let _ = tx.send(Err(format!("[#{}] 脚本执行失败", sid)));
                            }
                            return;
                        }
                    }

                    log_success!("[#{}] {} 已就绪 (PID: {})", sid, label, pid);
                    if let Some(tx) = &result {
                        let _ = tx.send(Ok(pid as u32));
                    }
                }
                Err(e) => {
                    log_error!("[#{}] 注入 {} 失败: {}", sid, label, e);
                    session.failed.store(true, Ordering::Release);
                    if let Some(tx) = &result {
                        let _ = tx.send(Err(format!("注入 {} 失败: {}", label, e)));
                    }
                }
            }
        })
        .expect("spawn wwb-attach thread");
}

// ────────────────────────── Session REPL ──────────────────────────

/// 进入 session 交互模式，输入 back 返回 server REPL
/// 返回 true 表示 session 已 exit/shutdown，应从 manager 移除
fn run_session_repl(session: &Arc<Session>) -> bool {
    use crate::logger::{DIM, RESET};

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            return false;
        }
    };
    rl.set_helper(Some(SessionModeCompleter::new()));

    let label = session.label.lock().unwrap().clone();
    let prompt = format!("rustfrida#{}> ", session.id);
    println!(
        "  {DIM}[#{}] {} (PID: {}) — 输入 back 返回 server, help 查看命令{RESET}",
        session.id,
        label,
        session.pid.load(Ordering::Relaxed)
    );

    let send_shutdown = |s: &Session| {
        if let Some(sender) = s.get_sender() {
            s.shutdown_requested.store(true, Ordering::Release);
            if let Err(e) = send_command(sender, "shutdown") {
                log_error!("发送 shutdown 失败: {}", e);
            } else {
                log_info!("已发送 shutdown，等待 agent 主动断开连接...");
            }
        }
    };

    let mut should_remove = false;

    loop {
        if session.disconnected.load(Ordering::Acquire) {
            log_error!("[#{}] Agent 连接已断开", session.id);
            should_remove = true;
            break;
        }

        match rl.readline(&prompt) {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);

                if line == "back" || line == "server" {
                    break;
                }
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("[#{}] 断开 session", session.id);
                    send_shutdown(session);
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(session);
                    continue;
                }

                // hfl 参数校验
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl")) && parts.len() < 3 {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }

                let is_recomp = line.starts_with("recomp");
                let is_eval_cmd = line.starts_with("jseval ")
                    || line.starts_with("loadjs ")
                    || line == "jsinit"
                    || line == "jsclean"
                    || line.starts_with("managedcounter ")
                    || is_recomp;

                if is_eval_cmd {
                    session.eval_state.clear();
                }

                let sender = match session.get_sender() {
                    Some(s) => s,
                    None => {
                        log_error!("agent 未连接");
                        should_remove = true;
                        break;
                    }
                };
                let handled_by_main_thread = match try_managedcounter_on_main_thread(session, &line)
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_loadjs_on_main_thread_if_java(session, &line)
                        }
                    })
                    .and_then(|handled| {
                        if handled {
                            Ok(true)
                        } else {
                            try_jseval_on_main_thread_if_java_or_dsl(session, &line)
                        }
                    }) {
                    Ok(v) => v,
                    Err(e) => {
                        log_error!("{}", e);
                        continue;
                    }
                };
                if !handled_by_main_thread {
                    let command = rewrite_jseval_for_agent(&line).unwrap_or_else(|| line.clone());
                    match send_command(sender, &command) {
                        Ok(_) => {}
                        Err(e) => {
                            log_error!("发送命令失败: {}", e);
                            should_remove = true;
                            break;
                        }
                    }
                }

                if is_eval_cmd {
                    let timeout = if is_recomp {
                        EVAL_RECOMP_TIMEOUT_SECS
                    } else if script_uses_java_api(&line) {
                        EVAL_JAVA_TIMEOUT_SECS
                    } else {
                        EVAL_DEFAULT_TIMEOUT_SECS
                    };
                    print_eval_result(session, timeout);
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    should_remove
}

// ────────────────────────── Server REPL ──────────────────────────

fn print_server_help() {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW};
    println!("\n{BOLD}{CYAN}Server 命令:{RESET}");
    println!("{DIM}  {:<12} {:<28} {}{RESET}", "命令", "参数", "说明");
    println!("{DIM}  {:-<12} {:-<28} {:-<20}{RESET}", "", "", "");
    for (cmd, args, desc) in SERVER_CMDS {
        println!("  {BOLD}{GREEN}{:<12}{RESET} {YELLOW}{:<28}{RESET} {}", cmd, args, desc);
    }
    println!();
    println!("{DIM}  进入 session 后可使用全部 agent 命令 (jsinit/loadjs/jsrepl/hook 等){RESET}");
    println!("{DIM}  spawn/attach 在后台运行，可以同时发起多个注入{RESET}");
    println!();
}

fn print_sessions(mgr: &SessionManager) {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
    let sessions = mgr.list_sessions();
    if sessions.is_empty() {
        println!("{DIM}  无活跃 session{RESET}");
        return;
    }
    println!("\n{BOLD}{CYAN}Sessions:{RESET}");
    for (id, pid, label, status, active) in &sessions {
        let marker = if *active { " *" } else { "  " };
        let status_color = match *status {
            "connected" => GREEN,
            "connecting" => YELLOW,
            _ => RED,
        };
        println!(
            "{marker} {BOLD}#{:<3}{RESET} {:<30} PID:{:<8} {status_color}[{}]{RESET}",
            id, label, pid, status,
        );
    }
    println!();
}

/// Server daemon 主入口
pub(crate) fn run_server(args: &Args) {
    use crate::logger::{BOLD, CYAN, DIM, RESET};

    let mgr = Arc::new(SessionManager::new());

    // 注册信号处理（Ctrl+C 触发清理）
    spawn::register_cleanup_handler();

    // 收集 string_overrides（全局复用）
    let string_overrides: HashMap<String, String> = {
        let mut map = HashMap::new();
        let available_names = crate::types::get_string_table_names();
        for s in &args.strings {
            if let Some((name, value)) = s.split_once('=') {
                if available_names.contains(&name) {
                    map.insert(name.to_string(), value.to_string());
                } else {
                    log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
                }
            }
        }
        map
    };

    // 先绑定控制端口。Zygote 只在收到实际 spawn 请求时按需注入；server 启动本身
    // 不应修改 Zygote 的系统代码映射，否则即使没有 attach 目标也会留下 COW 页。
    let listen_arg = args.listen.as_deref().unwrap_or(DEFAULT_LISTEN_ADDR);
    let bind = crate::parse_rpc_bind(listen_arg);
    if let Err(e) = run_tcp_server(mgr.clone(), &bind, string_overrides.clone(), args.verbose) {
        log_error!("TCP server 启动失败: {}", e);
        std::process::exit(1);
    }

    // ── RPC HTTP 服务器（如启用）──
    if let Some(ref rpc_arg) = args.rpc_port {
        let bind = crate::parse_rpc_bind(rpc_arg);
        if let Err(e) = crate::http_rpc::start(mgr.clone(), &bind) {
            log_error!("{}", e);
        }
    }

    println!("\n  {BOLD}{CYAN}Server 模式已启动{RESET} {DIM}— 输入 help 查看命令, spawn/attach 开始注入{RESET}");
    if args.profile.is_some() {
        log_info!("属性 profile 已加载，spawn 的进程将自动应用");
    }
    println!();

    if args.server || args.listen.is_some() {
        // TCP server mode is a daemon: its lifetime is controlled by signals,
        // not by the stdin handle inherited from adb/nohup.
        log_info!("TCP server daemon 已脱离 stdin，等待终止信号...");
        while !spawn::signal_received() {
            thread::sleep(Duration::from_secs(1));
        }
        log_info!("收到终止信号，正在退出...");
    } else {
        let mut rl = match Editor::new() {
            Ok(e) => e,
            Err(e) => {
                log_error!("初始化行编辑器失败: {}", e);
                return;
            }
        };
        rl.set_helper(Some(ServerCompleter));
        let _ = rl.load_history(".rustfrida_server_history");

        loop {
            // 信号检查
            if spawn::signal_received() {
                log_info!("收到终止信号，正在退出...");
                break;
            }

            match rl.readline("server> ") {
                Ok(line) => {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }
                    let _ = rl.add_history_entry(&line);
                    let parts: Vec<&str> = line.split_whitespace().collect();

                    match parts[0] {
                        // ── spawn <package> [-l script.js] ──
                        "spawn" => {
                            if parts.len() < 2 {
                                log_warn!("用法: spawn <package> [-l script.js]");
                                continue;
                            }
                            let (positional, script) = parse_script_flag(&parts[1..]);
                            if positional.is_empty() {
                                log_warn!("用法: spawn <package> [-l script.js]");
                                continue;
                            }
                            let package = &positional[0];
                            let session = mgr.create_session(package.clone());
                            log_info!("[#{}] 正在 spawn {}...", session.id, package);
                            let script = script.map(ScriptSource::DevicePath);
                            do_spawn(
                                session,
                                package.clone(),
                                script,
                                string_overrides.clone(),
                                args.verbose,
                                None,
                            );
                        }

                        // ── attach <pid|name> [-l script.js] ──
                        "attach" => {
                            if parts.len() < 2 {
                                log_warn!("用法: attach <pid|name> [-l script.js]");
                                continue;
                            }
                            let (positional, script) = parse_script_flag(&parts[1..]);
                            if positional.is_empty() {
                                log_warn!("用法: attach <pid|name> [-l script.js]");
                                continue;
                            }
                            let target = &positional[0];
                            // 自动判断: 纯数字 → PID，否则 → 进程名
                            let (pid, label) = if let Ok(p) = target.parse::<i32>() {
                                (p, format!("PID:{}", p))
                            } else {
                                match find_pid_by_name(target) {
                                    Ok(p) => {
                                        log_success!("按名称 '{}' 找到进程 PID: {}", target, p);
                                        (p, target.to_string())
                                    }
                                    Err(e) => {
                                        log_error!("{}", e);
                                        continue;
                                    }
                                }
                            };
                            let session = mgr.create_session(label.clone());
                            log_info!("[#{}] 正在注入 {} (PID: {})...", session.id, label, pid);
                            let script = script.map(ScriptSource::DevicePath);
                            do_attach(
                                session,
                                pid,
                                label,
                                script,
                                string_overrides.clone(),
                                args.verbose,
                                None,
                            );
                        }

                        // ── list / sessions ──
                        "list" | "sessions" => {
                            print_sessions(&mgr);
                        }

                        // ── use <id> ──
                        "use" => {
                            if parts.len() < 2 {
                                log_warn!("用法: use <session_id>");
                                continue;
                            }
                            let id = match parts[1].parse::<u32>() {
                                Ok(id) => id,
                                Err(_) => {
                                    log_error!("无效的 session ID: {}", parts[1]);
                                    continue;
                                }
                            };
                            match mgr.get_session(id) {
                                None => {
                                    log_error!("Session #{} 不存在", id);
                                }
                                Some(session) => {
                                    if !session.is_connected() {
                                        let status = session.status();
                                        if status == "disconnected" || status == "failed" {
                                            log_warn!("Session #{} 已断开，正在清理", id);
                                            mgr.remove_session(id);
                                        } else {
                                            log_warn!("Session #{} 当前状态: {} — 请等待连接就绪", id, status);
                                        }
                                        continue;
                                    }
                                    mgr.set_active(Some(id));
                                    let should_remove = run_session_repl(&session);
                                    mgr.set_active(None);
                                    if should_remove {
                                        mgr.remove_session(id);
                                    }
                                }
                            }
                        }

                        // ── detach <id> ──
                        "detach" => {
                            if parts.len() < 2 {
                                log_warn!("用法: detach <session_id>");
                                continue;
                            }
                            let id = match parts[1].parse::<u32>() {
                                Ok(id) => id,
                                Err(_) => {
                                    log_error!("无效的 session ID: {}", parts[1]);
                                    continue;
                                }
                            };
                            match mgr.remove_session(id) {
                                None => {
                                    log_error!("Session #{} 不存在", id);
                                }
                                Some(session) => {
                                    shutdown_session(&session);
                                    log_success!("[#{}] 已断开", id);
                                }
                            }
                        }

                        // ── detachall ──
                        "detachall" => {
                            let sessions = mgr.all_sessions();
                            for session in &sessions {
                                let id = session.id;
                                shutdown_session(session);
                                mgr.remove_session(id);
                                log_success!("[#{}] 已断开", id);
                            }
                        }

                        // ── help ──
                        "help" => {
                            print_server_help();
                        }

                        // ── exit / quit ──
                        "exit" | "quit" => {
                            log_info!("正在退出 server...");
                            break;
                        }

                        other => {
                            log_warn!("未知命令: {} — 输入 help 查看可用命令", other);
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // Ctrl+C: 不立即退出，提示用户
                    println!();
                    log_info!("按 Ctrl+C 收到中断 — 输入 exit 退出 server");
                }
                Err(ReadlineError::Eof) => {
                    log_info!("正在退出 server...");
                    break;
                }
                Err(e) => {
                    log_error!("读取输入失败: {}", e);
                    break;
                }
            }
        }

        let _ = rl.save_history(".rustfrida_server_history");
    }

    // 清理所有 session
    log_info!("清理所有 session...");
    let sessions = mgr.all_sessions();
    for session in &sessions {
        shutdown_session(session);
    }

    // 还原 Zygote patch
    spawn::cleanup_zygote_patches();

    log_success!("Server 已退出");
}
