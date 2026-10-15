use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// 全局 verbose 开关（由 --verbose 标志控制）
pub static VERBOSE: AtomicBool = AtomicBool::new(false);
static LOG_FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// 日志镜像开关（将服务端日志同步给主机端客户端）。
///
/// 取值来自环境变量 `RF_SYNC_LOG`：
///   - 未设置 / `errors`：只镜像警告+错误（`log_warn!` / `log_error!`）
///   - `all`：连普通信息/步骤/verbose 一起镜像
///   - `off` / `0` / `none`：完全不镜像
static MIRROR_MODE: OnceLock<MirrorMode> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MirrorMode {
    Off,
    ErrorsOnly,
    All,
}

/// 镜像回调：由服务端注册（logger 不能反向依赖 server，否则循环依赖）。
/// 参数是已去 ANSI 的纯文本行。
pub type MirrorFn = fn(&str);
static MIRROR_SINK: OnceLock<MirrorFn> = OnceLock::new();

thread_local! {
    /// 防重入：镜像动作本身可能触发日志（如 relay 写失败），
    /// 若无此标记会无限递归，或在持锁路径上自死锁。
    static IN_MIRROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// 主动抑制镜像：用于那些**本就会直接送达客户端**的本地重打。
    /// 典型场景：服务端把 agent 发来的日志同时打到本地终端，在
    /// `RF_SYNC_LOG=all` 下若不抑制，客户端会收到两份同样的日志。
    static SUPPRESS_MIRROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// 在闭包执行期间抑制日志镜像。用于打印“已由其它通道送达”的内容。
pub fn with_mirror_suppressed<R>(f: impl FnOnce() -> R) -> R {
    SUPPRESS_MIRROR.with(|flag| {
        let prev = flag.get();
        flag.set(true);
        // 即使 f panic 也要恢复，否则本线程后续日志会静默丢镜像。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        flag.set(prev);
        match result {
            Ok(v) => v,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

pub fn mirror_mode() -> MirrorMode {
    *MIRROR_MODE.get_or_init(|| match std::env::var("RF_SYNC_LOG").ok().as_deref() {
        Some("all") | Some("ALL") => MirrorMode::All,
        Some("off") | Some("OFF") | Some("0") | Some("none") => MirrorMode::Off,
        // 默认：只给用户看真正需要注意的东西
        _ => MirrorMode::ErrorsOnly,
    })
}

/// 由服务端启动时注册一次。重复注册忽略（OnceLock 语义）。
pub fn set_mirror_sink(sink: MirrorFn) {
    let _ = MIRROR_SINK.set(sink);
}

/// 把一行日志（已去 ANSI）镜像给主机端。
///
/// 本函数自身**绝不能**向外抛日志：由 IN_MIRROR 防重入。
fn mirror_line(plain: &str, is_warn_or_error: bool) {
    let mode = mirror_mode();
    let wanted = match mode {
        MirrorMode::Off => return,
        MirrorMode::All => true,
        MirrorMode::ErrorsOnly => is_warn_or_error,
    };
    if !wanted {
        return;
    }
    let Some(sink) = MIRROR_SINK.get() else {
        return;
    };
    IN_MIRROR.with(|flag| {
        if flag.get() {
            return;
        }
        if SUPPRESS_MIRROR.with(|f| f.get()) {
            return;
        }
        flag.set(true);
        // 镜像过程中请勿 panic：sink 内部已用 try_lock，不向调用者抛错。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink(plain)));
        let _ = result;
        flag.set(false);
    });
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn init_output_file(path: &str) -> std::io::Result<()> {
    let file = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    let _ = LOG_FILE.set(Mutex::new(file));
    Ok(())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn write_log_line(line: &str) {
    if let Some(file) = LOG_FILE.get() {
        let mut guard = file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(guard, "{} {}", format_ts_now(), strip_ansi(line));
        let _ = guard.flush();
    }
}

/// 本地时刻 "HH:MM:SS.mmm"（依赖系统时区偏移由外部换算，无外部 crate 依赖）
pub fn format_ts_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs() % 86400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60,
        d.subsec_millis()
    )
}

pub fn stdout_line(colored: &str, plain: &str) {
    let ts = format_ts_now();
    println!("[{}] {}", ts, colored);
    write_log_line(&format!("{} {}", ts, plain));
    mirror_line(plain, false);
}

pub fn stderr_line(colored: &str, plain: &str) {
    let ts = format_ts_now();
    eprintln!("[{}] {}", ts, colored);
    write_log_line(&format!("{} {}", ts, plain));
    // stderr 出口 = log_warn! / log_error!，默认镜像给客户端。
    mirror_line(plain, true);
}

/// ANSI 颜色常量
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

/// 256 色扩展常量（rustyline Highlighter 专用）
pub const GRAY: &str = "\x1b[38;5;245m";
pub const HIGHLIGHT_BG: &str = "\x1b[48;5;238m";
pub const HIGHLIGHT_FG: &str = "\x1b[38;5;255m";

/// [*] 蓝色前缀 - 通用信息
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [*]{} {}", $crate::logger::BOLD, $crate::logger::BLUE, $crate::logger::RESET, msg),
            &format!("[*] {}", msg),
        );
    }};
}

/// [✓] 绿色前缀 - 成功操作
#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [✓]{} {}", $crate::logger::BOLD, $crate::logger::GREEN, $crate::logger::RESET, msg),
            &format!("[✓] {}", msg),
        );
    }};
}

/// [!] 黄色前缀 - 警告
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stderr_line(
            &format!("{}{} [!]{} {}", $crate::logger::BOLD, $crate::logger::YELLOW, $crate::logger::RESET, msg),
            &format!("[!] {}", msg),
        );
    }};
}

/// [!] 黄色前缀 - **内部诊断**警告（不进日志镜像）
///
/// 输出与 `log_warn!` 完全相同，唯一区别是不发客户端。判断标准两条全中才用它：
///
/// 1. 纯实现细节：页还原安全门、PC 范围探测、重试轮询内部状态之类 —— 用户既不能
///    据此改脚本，也不能据此判断脚本有没有生效；
/// 2. 会在循环里重复：同一子进程可刷十几条完全相同的文本，在客户端上会把脚本
///    自己的 `console.log` 冲散。
///
/// 反例（**不要**降级）：`[#N] 脚本加载超时`、`[#N] 脚本执行失败`、
/// `[#N] Agent 连接已断开` —— 这些正是用户需要立刻知道的。
/// 全量排查仍可直接看设备端 `/data/local/tmp/rustfrida.log`。
#[macro_export]
macro_rules! log_diag_warn {
    ($($arg:tt)*) => {{
        $crate::logger::with_mirror_suppressed(|| {
            $crate::log_warn!($($arg)*);
        });
    }};
}

/// [✗] 红色前缀 - 错误（输出到 stderr）
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stderr_line(
            &format!("{}{} [✗]{} {}", $crate::logger::BOLD, $crate::logger::RED, $crate::logger::RESET, msg),
            &format!("[✗] {}", msg),
        );
    }};
}

/// [→] 青色前缀 - 步骤/详细信息
#[macro_export]
macro_rules! log_step {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, msg),
            &format!("[→] {}", msg),
        );
    }};
}

/// 地址显示 - 带缩进的地址格式化
#[macro_export]
macro_rules! log_addr {
    ($label:expr, $addr:expr) => {{
        let plain = format!("     {}: 0x{:x}", $label, $addr);
        $crate::logger::stdout_line(
            &format!(
                "     {}: {}0x{:x}{}",
                $label,
                $crate::logger::DIM,
                $addr,
                $crate::logger::RESET
            ),
            &plain,
        );
    }};
}

/// [→] 仅 --verbose 时输出的详细步骤信息
#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {{
        if $crate::logger::is_verbose() {
            let msg = format!($($arg)*);
            $crate::logger::stdout_line(
                &format!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, msg),
                &format!("[→] {}", msg),
            );
        }
    }};
}

/// 地址显示 - 仅 --verbose 时输出
#[macro_export]
macro_rules! log_verbose_addr {
    ($label:expr, $addr:expr) => {{
        if $crate::logger::is_verbose() {
            let plain = format!("     {}: 0x{:x}", $label, $addr);
            $crate::logger::stdout_line(
                &format!(
                    "     {}: {}0x{:x}{}",
                    $label,
                    $crate::logger::DIM,
                    $addr,
                    $crate::logger::RESET
                ),
                &plain,
            );
        }
    }};
}

/// [agent] 紫色前缀 - 来自 agent 的消息
#[macro_export]
macro_rules! log_agent {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        $crate::logger::stdout_line(
            &format!("{}{} [agent]{} {}", $crate::logger::BOLD, $crate::logger::MAGENTA, $crate::logger::RESET, msg),
            &format!("[agent] {}", msg),
        );
    }};
}

/// 打印 banner
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    stdout_line(
        &format!(
            "\n {BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}\n \
             {BOLD}{CYAN}║{RESET}  {BOLD}      rustFrida v{version:<17} {RESET}{BOLD}{CYAN}║{RESET}\n \
             {BOLD}{CYAN}║{RESET}  {DIM}  ARM64 Dynamic Instrumentation    {RESET}{BOLD}{CYAN}║{RESET}\n \
             {BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}\n"
        ),
        &format!(
            "\n ╔══════════════════════════════════════╗\n \
             ║        rustFrida v{version:<17} ║\n \
             ║    ARM64 Dynamic Instrumentation    ║\n \
             ╚══════════════════════════════════════╝\n"
        ),
    );
}
