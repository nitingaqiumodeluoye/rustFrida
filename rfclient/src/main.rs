//! rfclient — rustFrida 主机端命令行客户端。
//!
//! 协议与会话逻辑在 `rfclient_core`；本文件只做三件事：
//! 1. 命令行解析（clap）；
//! 2. 连接建立（直连 TCP / 经 ADB 转发 / Gadget 竞态重试）；
//! 3. 终端呈现（见 `repl`）。

mod repl;

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use rfclient_core::adb::{self, AdbForward, DEFAULT_USB_DEVICE_PORT};
use rfclient_core::query::{self, OpenError, ProcessRow, SessionRow};

const CONNECT_TIMEOUT_SECS: u64 = 10;
const PROBE_TIMEOUT_SECS: u64 = 2;
const GADGET_WAIT_SECS: u64 = 20;
const GADGET_RETRY_MILLIS: u64 = 100;
/// Gadget 重试期间的建连超时：应用刚启动时端口可能刚 listen，短超时能更快进入下一轮。
const GADGET_CONNECT_TIMEOUT_MILLIS: u64 = 500;
const DEFAULT_LOG_LINGER_SECS: u64 = 5;
const DEFAULT_HOST: &str = "127.0.0.1:15819";

#[derive(Parser, Debug)]
#[command(
    name = "rfclient",
    version,
    about = "rustFrida 主机端客户端：连接设备上 rustfrida --server --listen 的 TCP 控制服务器"
)]
struct Args {
    /// 服务器地址，默认 127.0.0.1:15819；不能与 -U 同时使用
    #[arg(short = 'H', long = "host", value_name = "HOST:PORT", conflicts_with = "usb")]
    host: Option<String>,

    /// 通过 ADB 连接 USB/无线 ADB 设备，自动建立临时端口转发
    #[arg(short = 'U', long = "usb", conflicts_with = "host")]
    usb: bool,

    /// ADB 设备序列号；未指定时使用第一个 online 设备
    #[arg(short = 's', long = "serial", requires = "usb")]
    serial: Option<String>,

    /// 设备端 rustfrida 服务器要求的认证令牌（服务端以 --token 启动时必填）
    #[arg(long = "token", value_name = "TOKEN", env = "RFCLIENT_TOKEN")]
    token: Option<String>,

    /// -U 模式下设备端 rustfrida TCP 服务器端口
    #[arg(long = "device-port", default_value_t = DEFAULT_USB_DEVICE_PORT, requires = "usb")]
    device_port: u16,

    /// Frida 风格：启动应用并注入（等价于 spawn <package>）
    #[arg(short = 'f', long = "file", value_name = "PACKAGE")]
    spawn: Option<String>,

    /// Frida 风格顶层脚本参数，与 -f/--file 配合使用
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    load_script: Option<String>,

    /// 将终端输出同时写入文件
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    /// stdin 关闭后继续接收日志，直到连续空闲指定秒数；0 表示立即断开
    #[arg(long = "linger", value_name = "SECONDS", default_value_t = DEFAULT_LOG_LINGER_SECS)]
    linger: u64,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 列出所有 session（输出 id/pid/label/status）
    List,
    /// 枚举设备上可注入的进程（可给名字片段过滤）
    Ps { filter: Option<String> },
    /// 注入已运行进程（PID 或进程名）
    Attach {
        target: String,
        #[arg(short = 'l', long = "load-script")]
        script: Option<String>,
    },
    /// 启动应用并注入（-l 脚本在 resume 前由设备端加载）
    Spawn {
        package: String,
        #[arg(short = 'l', long = "load-script")]
        script: Option<String>,
    },
    /// 复用已有 session
    Use { session_id: u32 },
    /// 连接目标进程内的 rsfrida Gadget
    #[command(visible_alias = "Gadget")]
    Gadget {
        #[arg(short = 'l', long = "load-script")]
        script: Option<String>,
    },
}

fn main() {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(args: &Args) -> Result<i32, String> {
    repl::configure_output(args.output.as_deref())?;

    if args.usb && args.spawn.is_some() {
        if args.cmd.is_some() {
            return Err("-f/--file 不能与子命令同时使用".to_string());
        }
        return run_usb_spawn(args);
    }

    // -U 模式下临时建立 adb forward，退出时由 AdbForward 的 Drop 清理。
    let forward = if args.usb {
        Some(AdbForward::open(args.serial.as_deref(), args.device_port)?)
    } else {
        None
    };
    let host = forward
        .as_ref()
        .map(AdbForward::local_address)
        .unwrap_or_else(|| args.host.as_deref().unwrap_or(DEFAULT_HOST).to_string());
    let result = run_connected(args, &host);
    drop(forward);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UsbEndpointKind {
    Server,
    Gadget,
}

/// `-U -f <pkg>`：先看设备上是否已有 server，有就走 server spawn；
/// 否则重启应用并等它内部的 Gadget 就绪。
fn run_usb_spawn(args: &Args) -> Result<i32, String> {
    let package = args.spawn.as_deref().expect("spawn checked by caller");
    let forward = AdbForward::open(args.serial.as_deref(), args.device_port)?;
    let host = forward.local_address();

    match probe_usb_endpoint(&host)? {
        Some(UsbEndpointKind::Server) => {
            eprintln!("[usb] 检测到 rustfrida-server，使用 server spawn");
            run_connected(args, &host)
        }
        Some(UsbEndpointKind::Gadget) => {
            eprintln!("[usb] 检测到 rsfrida Gadget，重新启动 {}", package);
            adb::launch_android_package(&forward.serial, package)?;
            wait_for_gadget(args, &host, package)
        }
        None => {
            eprintln!("[usb] 未检测到 rustfrida-server，启动 {} 并等待 Gadget", package);
            adb::launch_android_package(&forward.serial, package)?;
            wait_for_gadget(args, &host, package)
        }
    }
}

/// 探测设备端端点类型。
///
/// 判据是 `list` 响应里的 label 列：Gadget 会话的 label 固定为 `karina`
/// （Gadget 模式没有真实包名可报）。探不通就返回 `None`，由调用方决定退路。
fn probe_usb_endpoint(host: &str) -> Result<Option<UsbEndpointKind>, String> {
    let rows = match query::list_sessions(host, None, Duration::from_secs(PROBE_TIMEOUT_SECS)) {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let is_gadget = rows.iter().any(|row| row.label == "karina");
    Ok(Some(if is_gadget {
        UsbEndpointKind::Gadget
    } else {
        UsbEndpointKind::Server
    }))
}

/// 反复尝试连接，直到 Gadget 起好（应用启动到 Gadget 加载有延迟）。
fn wait_for_gadget(args: &Args, host: &str, package: &str) -> Result<i32, String> {
    let deadline = Instant::now() + Duration::from_secs(GADGET_WAIT_SECS);
    let mut last_error = String::new();
    let line = if args.load_script.is_some() {
        "gadget -l -"
    } else {
        "gadget"
    };
    while Instant::now() < deadline {
        let connect_timeout = Duration::from_millis(GADGET_CONNECT_TIMEOUT_MILLIS);
        match open_interactive(host, line, args, args.load_script.as_deref(), connect_timeout) {
            Ok(code) => return Ok(code),
            // 建连/握手失败都当作「还没起好」继续等；只有超时才真正报错。
            Err(error) => last_error = error,
        }
        std::thread::sleep(Duration::from_millis(GADGET_RETRY_MILLIS));
    }
    Err(format!(
        "等待应用 {} 内的 rsfrida Gadget 启动超时（{}s）: {}",
        package, GADGET_WAIT_SECS, last_error
    ))
}

fn run_connected(args: &Args, host: &str) -> Result<i32, String> {
    if let Some(package) = args.spawn.as_ref() {
        if args.cmd.is_some() {
            return Err("-f/--file 不能与子命令同时使用".to_string());
        }
        let line = if args.load_script.is_some() {
            format!("spawn {} -l -", package)
        } else {
            format!("spawn {}", package)
        };
        return open_interactive(
            host,
            &line,
            args,
            args.load_script.as_deref(),
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
        );
    }

    let Some(cmd) = args.cmd.as_ref() else {
        eprintln!("[client] 未指定 -f/--file 或子命令，尝试连接已运行的 Gadget");
        return open_interactive(
            host,
            "gadget",
            args,
            args.load_script.as_deref(),
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
        );
    };

    let connect_timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);
    match cmd {
        // list / ps 是「问一句就走」的查询：连一次、读表格、不建会话。
        Cmd::List => {
            let rows = query::list_sessions(host, args.token.as_deref(), connect_timeout)?;
            print_session_rows(&rows);
            Ok(0)
        }
        Cmd::Ps { filter } => {
            let rows = query::list_processes(host, filter.as_deref(), args.token.as_deref(), connect_timeout)?;
            print_process_rows(&rows);
            Ok(0)
        }
        Cmd::Attach { target, script } => {
            let line = if script.is_some() {
                format!("attach {} -l -", target)
            } else {
                format!("attach {}", target)
            };
            open_interactive(host, &line, args, script.as_deref(), connect_timeout)
        }
        Cmd::Spawn { package, script } => {
            let line = if script.is_some() {
                format!("spawn {} -l -", package)
            } else {
                format!("spawn {}", package)
            };
            open_interactive(host, &line, args, script.as_deref(), connect_timeout)
        }
        Cmd::Use { session_id } => open_interactive(
            host,
            &format!("use {}", session_id),
            args,
            None,
            connect_timeout,
        ),
        Cmd::Gadget { script } => {
            let line = if script.is_some() {
                "gadget -l -"
            } else {
                "gadget"
            };
            open_interactive(host, &line, args, script.as_deref(), connect_timeout)
        }
    }
}

/// 引导 + 建会话 + 进 REPL，返回进程退出码。
///
/// 三类结果分开处置，与重构前逐字一致：
/// - 成功 → 打印 OK 行，进 REPL；
/// - 服务端拒绝（非 OK 行）→ 原样打印该行，退出码 1（不是 Err，避免被
///   Gadget 重试循环当成「没起好」而无休止重试）；
/// - 链路失败 → Err，由调用方决定是重试还是上报。
fn open_interactive(
    host: &str,
    line: &str,
    args: &Args,
    script_path: Option<&str>,
    connect_timeout: Duration,
) -> Result<i32, String> {
    match query::open_session(host, line, args.token.as_deref(), script_path, connect_timeout) {
        Ok(opened) => {
            repl::print_line(&opened.ok_line);
            let session = Arc::new(opened.session);
            repl::run(&session, opened.events, Duration::from_secs(args.linger))?;
            Ok(0)
        }
        Err(OpenError::Rejected(reason)) => {
            repl::print_line(&reason);
            Ok(1)
        }
        Err(OpenError::Transport(e)) => Err(e),
    }
}

fn print_session_rows(rows: &[SessionRow]) {
    if rows.is_empty() {
        repl::print_line("(无会话)");
        return;
    }
    repl::print_line("ID\tPID\tLABEL\tSTATUS");
    for row in rows {
        repl::print_line(&row.to_line());
    }
}

fn print_process_rows(rows: &[ProcessRow]) {
    if rows.is_empty() {
        repl::print_line("(无匹配进程)");
        return;
    }
    repl::print_line("PID\tNAME");
    for row in rows {
        repl::print_line(&row.to_line());
    }
}
