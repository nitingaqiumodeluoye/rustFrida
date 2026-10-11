//! 引导阶段（bootstrap）的文本行读写。
//!
//! 控制连接建立后、进入帧协议之前，服务端先收一行文本命令并回一行文本结果
//! （如 `spawn com.example.app -l -` → `OK sid=1 pid=1234 proto=2`）。
//! `list` / `ps` 这类查询还会回多行、以空行结束。

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::proto::write_bootstrap_script;

/// 把认证令牌拼进引导行：服务端从引导行的 `token=<值>` 字段读取。
///
/// 设备端以 `--token` 启动时，除 `list` 外的引导请求都必须携带。
pub fn with_token(line: &str, token: Option<&str>) -> String {
    match token {
        Some(t) if !t.is_empty() => format!("{} token={}", line, t),
        _ => line.to_string(),
    }
}

/// 从 `OK sid=1 pid=123 proto=2` 中提取协议版本。
///
/// 服务端/Gadget 在 OK 行宣告 agent 协议版本；拿不到时（旧服务端）返回 `None`，
/// 由上层等 HELLO 或退回 legacy 语义。
pub fn parse_proto_hint(response: &str) -> Option<u32> {
    response
        .split_whitespace()
        .find_map(|f| f.strip_prefix("proto="))
        .and_then(|v| v.parse().ok())
}

/// 发送引导请求（可选附带本地脚本文件）。
///
/// `script_path` 给出时，按 `filename\n<script>` 的格式额外发一个
/// `FRAME_KIND_BOOTSTRAP_SCRIPT` 帧 —— 脚本从**主机**读，设备上不需要该文件。
pub fn send_bootstrap(stream: &mut TcpStream, line: &str, script_path: Option<&str>) -> Result<(), String> {
    let script = match script_path {
        Some(path) => {
            let content =
                std::fs::read_to_string(path).map_err(|e| format!("读取本地脚本 '{}' 失败: {}", path, e))?;
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
        write_bootstrap_script(stream, &filename, &content).map_err(|e| format!("发送本地脚本失败: {}", e))?;
    }
    Ok(())
}

/// 读一行响应（逐字节，避免缓冲吞掉后续的帧数据）。
pub fn read_response_line(stream: &mut TcpStream) -> Result<String, String> {
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

/// 读多行响应直到空行（`list` / `ps` 用）。
pub fn read_response_lines(stream: &mut TcpStream) -> Result<Vec<String>, String> {
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
