//! rfclient：rustFrida 主机端客户端。
//!
//! 连接设备上 `rustfrida --server --listen <addr>` 的 TCP 控制服务器，
//! 发送引导请求（list/attach/spawn/use），随后进入帧级 REPL。
//!
//! 典型用法（配合 adb forward）：
//!   adb forward tcp:15819 tcp:15819
//!   rfclient -H 127.0.0.1:15819 list
//!   rfclient -H 127.0.0.1:15819 attach <pid>
//!   rfclient -H 127.0.0.1:15819 spawn com.example.app -l script.js
//!   rfclient -H 127.0.0.1:15819 use 1
//!   rfclient -U list
//!   rfclient -U -f com.example.app -l script.js
//!   rfclient -U Gadget -l script.js
//!   rfclient -U -l script.js              # 连接已唤醒的 Gadget

mod proto;
mod repl;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use crate::proto::write_bootstrap_script;

const CONNECT_TIMEOUT_SECS: u64 = 10;
const PROBE_TIMEOUT_SECS: u64 = 2;
const GADGET_WAIT_SECS: u64 = 20;
const GADGET_RETRY_MILLIS: u64 = 100;
const DEFAULT_LOG_LINGER_SECS: u64 = 5;
const DEFAULT_HOST: &str = "127.0.0.1:15819";
const DEFAULT_USB_DEVICE_PORT: u16 = 15819;

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
            launch_android_package(&forward.serial, package)?;
            wait_for_gadget(args, &host, package)
        }
        None => {
            eprintln!("[usb] 未检测到 rustfrida-server，启动 {} 并等待 Gadget", package);
            launch_android_package(&forward.serial, package)?;
            wait_for_gadget(args, &host, package)
        }
    }
}

fn probe_usb_endpoint(host: &str) -> Result<Option<UsbEndpointKind>, String> {
    let mut stream = match connect_tcp(host, Duration::from_secs(PROBE_TIMEOUT_SECS)) {
        Ok(stream) => stream,
        Err(_) => return Ok(None),
    };
    configure_stream(&stream, Duration::from_secs(PROBE_TIMEOUT_SECS))?;
    if stream.write_all(b"list\n").is_err() {
        return Ok(None);
    }
    let lines = match read_response_lines(&mut stream) {
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

fn launch_android_package(serial: &str, package: &str) -> Result<(), String> {
    if package.is_empty()
        || !package
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'))
    {
        return Err(format!("无效 Android 包名 '{}'", package));
    }

    let force_stop = Command::new("adb")
        .args(["-s", serial, "shell", "am", "force-stop", package])
        .output()
        .map_err(|e| format!("停止应用 {} 失败: {}", package, e))?;
    if !force_stop.status.success() {
        return Err(format!(
            "停止应用 {} 失败: {}",
            package,
            String::from_utf8_lossy(&force_stop.stderr).trim()
        ));
    }

    let resolved = Command::new("adb")
        .args([
            "-s",
            serial,
            "shell",
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            package,
        ])
        .output()
        .map_err(|e| format!("解析应用 {} 启动 Activity 失败: {}", package, e))?;
    if !resolved.status.success() {
        return Err(format!(
            "解析应用 {} 启动 Activity 失败: {}",
            package,
            String::from_utf8_lossy(&resolved.stderr).trim()
        ));
    }
    let component = String::from_utf8_lossy(&resolved.stdout)
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.contains('/'))
        .ok_or_else(|| format!("应用 {} 没有可启动的 Activity", package))?
        .to_string();

    let started = Command::new("adb")
        .args([
            "-s",
            serial,
            "shell",
            "am",
            "start",
            "--user",
            "current",
            "-n",
            component.as_str(),
        ])
        .output()
        .map_err(|e| format!("启动应用 {} 失败: {}", package, e))?;
    if !started.status.success() {
        return Err(format!(
            "启动应用 {} 失败: {}{}",
            package,
            String::from_utf8_lossy(&started.stdout).trim(),
            String::from_utf8_lossy(&started.stderr).trim()
        ));
    }
    Ok(())
}

fn wait_for_gadget(args: &Args, host: &str, package: &str) -> Result<i32, String> {
    let deadline = Instant::now() + Duration::from_secs(GADGET_WAIT_SECS);
    let mut last_error = String::new();
    while Instant::now() < deadline {
        match connect_tcp(host, Duration::from_millis(500)) {
            Ok(mut stream) => {
                configure_stream(&stream, Duration::from_secs(30))?;
                let line = if args.load_script.is_some() {
                    "gadget -l -"
                } else {
                    "gadget"
                };
                match run_interactive(&mut stream, line, args.load_script.as_deref(), args.linger) {
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
        return run_interactive(&mut stream, &line, args.load_script.as_deref(), args.linger);
    }

    let Some(cmd) = args.cmd.as_ref() else {
        let line = if args.load_script.is_some() {
            "gadget -l -"
        } else {
            "gadget"
        };
        eprintln!("[client] 未指定 -f/--file 或子命令，尝试连接已运行的 Gadget");
        return run_interactive(&mut stream, line, args.load_script.as_deref(), args.linger);
    };

    match cmd {
        Cmd::List => {
            send_bootstrap(&mut stream, "list", None)?;
            let lines = read_response_lines(&mut stream)?;
            if lines.is_empty() {
                repl::print_line("(无会话)");
            } else {
                repl::print_line("ID\tPID\tLABEL\tSTATUS");
                for line in &lines {
                    repl::print_line(line);
                }
            }
            Ok(0)
        }
        Cmd::Attach { target, script } => {
            let line = if script.is_some() {
                format!("attach {} -l -", target)
            } else {
                format!("attach {}", target)
            };
            run_interactive(&mut stream, &line, script.as_deref(), args.linger)
        }
        Cmd::Spawn { package, script } => {
            let line = if script.is_some() {
                format!("spawn {} -l -", package)
            } else {
                format!("spawn {}", package)
            };
            run_interactive(&mut stream, &line, script.as_deref(), args.linger)
        }
        Cmd::Use { session_id } => {
            let line = format!("use {}", session_id);
            run_interactive(&mut stream, &line, None, args.linger)
        }
        Cmd::Gadget { script } => {
            let line = if script.is_some() {
                "gadget -l -"
            } else {
                "gadget"
            };
            run_interactive(&mut stream, line, script.as_deref(), args.linger)
        }
    }
}

/// Frida 的 Android USB provider 通过 ADB 设备跟踪后打开设备控制通道。
/// 这里使用 adb 命令完成等价的设备选择和临时 TCP forward，服务器协议本身不变。
struct AdbForward {
    serial: String,
    local_port: u16,
}

impl AdbForward {
    fn open(requested_serial: Option<&str>, device_port: u16) -> Result<Self, String> {
        let serial = select_adb_device(requested_serial)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("为 ADB forward 分配本地端口失败: {}", e))?;
        let local_port = listener
            .local_addr()
            .map_err(|e| format!("读取本地临时端口失败: {}", e))?
            .port();
        drop(listener);

        let local = format!("tcp:{}", local_port);
        let remote = format!("tcp:{}", device_port);
        let output = Command::new("adb")
            .args(["-s", serial.as_str(), "forward", local.as_str(), remote.as_str()])
            .output()
            .map_err(|e| format!("执行 adb forward 失败: {}（请确认 adb 在 PATH 中）", e))?;
        if !output.status.success() {
            return Err(format!(
                "adb forward {} -> {} 失败: {}",
                local,
                remote,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        eprintln!("[adb] {} -> 127.0.0.1:{}", serial, device_port);
        Ok(Self { serial, local_port })
    }

    fn local_address(&self) -> String {
        format!("127.0.0.1:{}", self.local_port)
    }
}

impl Drop for AdbForward {
    fn drop(&mut self) {
        let local = format!("tcp:{}", self.local_port);
        let _ = Command::new("adb")
            .args([
                "-s",
                self.serial.as_str(),
                "forward",
                "--remove",
                local.as_str(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn select_adb_device(requested_serial: Option<&str>) -> Result<String, String> {
    let output = Command::new("adb")
        .arg("devices")
        .output()
        .map_err(|e| format!("执行 adb devices 失败: {}（请确认 adb 在 PATH 中）", e))?;
    if !output.status.success() {
        return Err(format!(
            "adb devices 失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut online = Vec::new();
    let mut statuses = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let Some(serial) = fields.next() else { continue };
        let Some(status) = fields.next() else { continue };
        if serial == "List" && status == "of" {
            continue;
        }
        statuses.push((serial.to_string(), status.to_string()));
        if status == "device" {
            online.push(serial.to_string());
        }
    }

    if let Some(requested) = requested_serial {
        if online.iter().any(|serial| serial == requested) {
            return Ok(requested.to_string());
        }
        let status = statuses
            .iter()
            .find(|(serial, _)| serial == requested)
            .map(|(_, status)| status.as_str())
            .unwrap_or("not found");
        return Err(format!("ADB 设备 '{}' 不可用（状态: {}）", requested, status));
    }

    match online.as_slice() {
        [] => Err("没有 online 的 ADB 设备".to_string()),
        [serial] => Ok(serial.clone()),
        [first, ..] => {
            eprintln!("[adb] 检测到多个 online 设备，使用第一个: {}", first);
            Ok(first.clone())
        }
    }
}

/// 发送引导请求，校验 OK 后进入 REPL；返回进程退出码。
fn run_interactive(
    stream: &mut TcpStream,
    line: &str,
    script_path: Option<&str>,
    linger_secs: u64,
) -> Result<i32, String> {
    send_bootstrap(stream, line, script_path)?;
    let response = read_response_line(stream)?;
    if !response.starts_with("OK") {
        repl::print_line(&response);
        return Ok(1);
    }
    repl::print_line(&response);
    repl::run(stream, Duration::from_secs(linger_secs))?;
    Ok(0)
}

fn send_bootstrap(stream: &mut TcpStream, line: &str, script_path: Option<&str>) -> Result<(), String> {
    let script = match script_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("读取本地脚本 '{}' 失败: {}", path, e))?;
            let filename = std::path::Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("script.js")
                .to_string();
            Some((filename, content))
        }
        None => None,
    };
    let mut data = line.to_string();
    data.push('\n');
    stream
        .write_all(data.as_bytes())
        .map_err(|e| format!("发送引导请求失败: {}", e))?;
    if let Some((filename, content)) = script {
        write_bootstrap_script(stream, &filename, &content)
            .map_err(|e| format!("发送本地脚本失败: {}", e))?;
    }
    Ok(())
}

/// 读一行响应（逐字节，避免 BufReader 缓冲吞掉后续帧）。
fn read_response_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|e| format!("读引导响应失败: {}", e))?;
        if n == 0 {
            if line.is_empty() {
                return Err("服务器关闭了连接".to_string());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&line).trim_end_matches('\r').to_string())
}

/// 读多行响应直到空行（用于 list）。
fn read_response_lines(stream: &mut TcpStream) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    loop {
        let line = read_response_line(stream)?;
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    Ok(lines)
}
