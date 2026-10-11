//! ADB 设备发现与端口转发（Frida 的 Android USB provider 的等价实现）。
//!
//! 这里用 `adb` 命令完成设备选择和临时 TCP forward，**服务器协议本身不变**：
//! Frida 通过 ADB 设备跟踪后打开设备控制通道，本模块用 `adb forward` 达到同样效果。
//! 这样可以复用设备端已有的 `rustfrida --server --listen`，不必实现 ADB 协议。

use std::net::TcpListener;
use std::process::{Command, Stdio};

/// `-U` 模式下的设备端默认端口。
pub const DEFAULT_USB_DEVICE_PORT: u16 = 15819;

/// 一条临时 adb forward；Drop 时自动 `--remove`。
pub struct AdbForward {
    pub serial: String,
    pub local_port: u16,
}

impl AdbForward {
    /// 选设备 + 分配本地临时端口 + 建立 forward。
    pub fn open(requested_serial: Option<&str>, device_port: u16) -> Result<Self, String> {
        let serial = select_adb_device(requested_serial)?;
        // 先 bind 一个临时端口再立刻释放，让内核分配（避免与其他实例撞端口）。
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
        Ok(Self { serial, local_port })
    }

    /// 本机侧地址，交给 TCP 连接使用。
    pub fn local_address(&self) -> String {
        format!("127.0.0.1:{}", self.local_port)
    }
}

impl Drop for AdbForward {
    fn drop(&mut self) {
        let local = format!("tcp:{}", self.local_port);
        let _ = Command::new("adb")
            .args(["-s", self.serial.as_str(), "forward", "--remove", local.as_str()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// 选择目标设备：指定 serial 时必须是 online；否则取第一个 online。
pub fn select_adb_device(requested_serial: Option<&str>) -> Result<String, String> {
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
        // 跳过 "List of devices attached" 表头
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
        [first, ..] => Ok(first.clone()),
    }
}

/// 强制重启应用，用于让 `-U -f <pkg>` 走 Gadget 路径时拿到干净的加载时机。
///
/// 包名做了字符白名单校验（仅 `[A-Za-z0-9._]`）：参数会直接进 adb 命令行，
/// 虽然这里不经过 shell，但拒绝异常输入比事后排查更省事。
pub fn launch_android_package(serial: &str, package: &str) -> Result<(), String> {
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
