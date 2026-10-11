//! rfclient — rustFrida 主机端命令行客户端。
//!
//! 协议与会话逻辑在 `rfclient_core`；本文件只做三件事：
//! 1. 命令行解析（clap）；
//! 2. 连接建立（直连 TCP / 经 ADB 转发 / Gadget 探测）；
//! 3. 终端呈现（见 `repl`）。

mod repl;

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use rfclient_core::adb::{self, AdbForward, DEFAULT_USB_DEVICE_PORT};
use rfclient_core::bootstrap;
use rfclient_core::Session;

const CONNECT_TIMEOUT_SECS: u64 = 10;
const PROBE_TIMEOUT_SECS: u64 = 2;
const GADGET_WAIT_SECS: u64 = 20;
const GADGET_RETRY_MILLIS: u64 = 100;
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
    let mut stream = match connect_tcp(host, Duration::from_secs(PROBE_TIMEOUT_SECS)) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };
    configure_stream(&stream, Duration::from_secs(PROBE_TIMEOUT_SECS))?;
    if stream.write_all(b"list\n").is_err() {
        return Ok(None);
    }
    let lines = match bootstrap::read_response_lines(&mut stream) {
        Ok(lines) => lines,
        Err(_) => return Ok(None),
    };
    let is_gadget = lines
        .iter()
        .any(|line| line.split('\t').nth(2) == Some("karina"));
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
    while Instant::now() < deadline {
        match connect_tcp(host, Duration::from_millis(500)) {
            Ok(stream) => {
                configure_stream(&stream, Duration::from_secs(30))?;
                let line = if args.load_script.is_some() {
                    "gadget -l -"
                } else {
                    "gadget"
                };
                let line = bootstrap::with_token(line, args.token.as_deref());
                match run_interactive(stream, &line, args.load_script.as_deref(), args.linger) {
                    Ok(code) => return Ok(code),
                    Err(error) => last_error = error,
                }
            }
            Err(error) => last_error = error,
        }
        std::thread::sleep(Duration::from_millis(GADGET_RETRY_MILLIS));
    }
    Err(format!(
        "等待应用 {} 内的 rsfrida Gadget 启动超时（{}s）: {}",
        package, GADGET_WAIT_SECS, last_error
    ))
}

fn connect_tcp(host: &str, timeout: Duration) -> Result<TcpStream, String> {
    let address = host
        .parse()
        .map_err(|_| format!("无效地址 '{}'（应为 host:port）", host))?;
    TcpStream::connect_timeout(&address, timeout).map_err(|e| format!("连接 {} 失败: {}", host, e))
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set_write_timeout: {}", e))?;
    Ok(())
}

fn run_connected(args: &Args, host: &str) -> Result<i32, String> {
    let mut stream = connect_tcp(host, Duration::from_secs(CONNECT_TIMEOUT_SECS))?;
    configure_stream(&stream, Duration::from_secs(30))?;

    if let Some(package) = args.spawn.as_ref() {
        if args.cmd.is_some() {
            return Err("-f/--file 不能与子命令同时使用".to_string());
        }
        let line = if args.load_script.is_some() {
            format!("spawn {} -l -", package)
        } else {
            format!("spawn {}", package)
        };
        let line = bootstrap::with_token(&line, args.token.as_deref());
        return run_interactive(stream, &line, args.load_script.as_deref(), args.linger);
    }

    let Some(cmd) = args.cmd.as_ref() else {
        let line = if args.load_script.is_some() {
            "gadget -l -".to_string()
        } else {
            "gadget".to_string()
        };
        let line = bootstrap::with_token(&line, args.token.as_deref());
        eprintln!("[client] 未指定 -f/--file 或子命令，尝试连接已运行的 Gadget");
        return run_interactive(stream, &line, args.load_script.as_deref(), args.linger);
    };

    match cmd {
        Cmd::List => {
            send_query(&mut stream, "list", args.token.as_deref(), "ID\tPID\tLABEL\tSTATUS", "(无会话)")
        }
        Cmd::Ps { filter } => {
            let line = match filter {
                Some(f) if !f.is_empty() => format!("ps {}", f),
                _ => "ps".to_string(),
            };
            send_query(&mut stream, &line, args.token.as_deref(), "PID\tNAME", "(无匹配进程)")
        }
        Cmd::Attach { target, script } => {
            let line = if script.is_some() {
                format!("attach {} -l -", target)
            } else {
                format!("attach {}", target)
            };
            let line = bootstrap::with_token(&line, args.token.as_deref());
            run_interactive(stream, &line, script.as_deref(), args.linger)
        }
        Cmd::Spawn { package, script } => {
            let line = if script.is_some() {
                format!("spawn {} -l -", package)
            } else {
                format!("spawn {}", package)
            };
            let line = bootstrap::with_token(&line, args.token.as_deref());
            run_interactive(stream, &line, script.as_deref(), args.linger)
        }
        Cmd::Use { session_id } => {
            let line = bootstrap::with_token(&format!("use {}", session_id), args.token.as_deref());
            run_interactive(stream, &line, None, args.linger)
        }
        Cmd::Gadget { script } => {
            let line = if script.is_some() {
                "gadget -l -".to_string()
            } else {
                "gadget".to_string()
            };
            let line = bootstrap::with_token(&line, args.token.as_deref());
            run_interactive(stream, &line, script.as_deref(), args.linger)
        }
    }
}

/// `list` / `ps`：发一行、读多行直到空行，然后按表格打印。
fn send_query(
    stream: &mut TcpStream,
    line: &str,
    token: Option<&str>,
    header: &str,
    empty_hint: &str,
) -> Result<i32, String> {
    let line = bootstrap::with_token(line, token);
    bootstrap::send_bootstrap(stream, &line, None)?;
    let lines = bootstrap::read_response_lines(stream)?;
    if lines.is_empty() {
        repl::print_line(empty_hint);
    } else {
        repl::print_line(header);
        for l in &lines {
            repl::print_line(l);
        }
    }
    Ok(0)
}

/// 发送引导请求，校验 OK 后进入 REPL；返回进程退出码。
fn run_interactive(
    stream: TcpStream,
    line: &str,
    script_path: Option<&str>,
    linger_secs: u64,
) -> Result<i32, String> {
    let mut stream = stream;
    bootstrap::send_bootstrap(&mut stream, line, script_path)?;
    let response = bootstrap::read_response_line(&mut stream)?;
    if !response.starts_with("OK") {
        repl::print_line(&response);
        return Ok(1);
    }
    repl::print_line(&response);
    // 服务端/Gadget 在 OK 行宣告 agent 协议版本（proto=N）；
    // 拿不到时（旧服务端）交给 Session 等 HELLO 或退回 legacy。
    let proto_hint = bootstrap::parse_proto_hint(&response);
    let (session, events) = Session::connect(stream, proto_hint)?;
    repl::run(&Arc::new(session), events, Duration::from_secs(linger_secs))?;
    Ok(0)
}
