//! 一次性查询与「连接并进入会话」的握手。
//!
//! 这里放的是 CLI 与 GUI **都要走**的几条固定流程，抽出来是为了让两边不必各写
//! 一遍 TCP 建立、超时设置与响应解析：
//!
//! - [`list_sessions`] / [`list_processes`]：连一次、发一行、读多行、关闭。
//!   属于「问一句就走」的查询，**不建立 Session**（没有帧、没有心跳）。
//! - [`open_session`]：发引导行 → 读 OK 行 → 建立 [`Session`]。
//!   引导行可以是 `attach <pid>` / `spawn <pkg>` / `use <id>` / `gadget`。
//!
//! 一条 TCP 连接只承载一个会话 —— 想换目标就得重连，这也解释了为什么
//! `open_session` 每次都要重新 connect，而不是复用已有连接。

use std::net::TcpStream;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::bootstrap;
use crate::event::Event;
use crate::session::Session;

/// 交互会话的读写超时。
///
/// 30s 是**单条命令**的等待上限（脚本里睡几秒很常见，不能设太小）；
/// 更长的挂起由心跳负责发现，不靠这里的超时。
pub const IO_TIMEOUT_SECS: u64 = 30;

/// 会话表的一行（对应服务端 `list` 的 `id\tpid\tlabel\tstatus`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRow {
    pub id: u32,
    pub pid: u32,
    pub label: String,
    pub status: String,
}

/// `jslist` 应答里的一项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptEntry {
    pub id: u64,
    pub name: String,
    pub native_hooks: usize,
    pub java_hooks: usize,
    pub bytes: usize,
}

impl ScriptEntry {
    /// 脚本持有的 hook 总数（卸载前想知道「会拆掉多少东西」）。
    pub fn hook_count(&self) -> usize {
        self.native_hooks + self.java_hooks
    }
}

/// 解析 agent `jslist` 的文本应答。
///
/// 格式（见 agent/src/quickjs_loader.rs::execute_jslist）：
/// ```text
/// script#1 name.js\tnative=1 java=0 bytes=1234
/// ```
/// 空表回的是 `no scripts loaded`。
///
/// 解析放在 core 而不是 GUI 里：这是**协议格式知识**，CLI 与 GUI 都有权依赖，
/// 各自再写一遍就迟早会不一致。
///
/// 容错取向：认不出的行跳过（而不是报错）—— 多出一个字段总比整张表打不开好。
pub fn parse_script_list(text: &str) -> Vec<ScriptEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        let Some(rest) = line.strip_prefix("script#") else {
            continue;
        };
        // "1 name.js\tnative=1 java=0 bytes=1234"
        let (id_part, tail) = match rest.split_once(char::is_whitespace) {
            Some(parts) => parts,
            None => (rest, ""),
        };
        let Ok(id) = id_part.parse::<u64>() else {
            continue;
        };
        let (name, stats) = match tail.split_once('\t') {
            Some((name, stats)) => (name.to_string(), stats),
            // 没有制表符时整个 tail 就是名字，统计字段全部缺省。
            None => (tail.to_string(), ""),
        };
        let mut entry = ScriptEntry {
            id,
            name,
            native_hooks: 0,
            java_hooks: 0,
            bytes: 0,
        };
        for field in stats.split_whitespace() {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            let Ok(value) = value.parse::<usize>() else {
                continue;
            };
            match key {
                "native" => entry.native_hooks = value,
                "java" => entry.java_hooks = value,
                "bytes" => entry.bytes = value,
                _ => {}
            }
        }
        out.push(entry);
    }
    out
}

impl SessionRow {
    /// 还原成服务端的原始行，保证 CLI 输出与重构前逐字节一致。
    pub fn to_line(&self) -> String {
        format!("{}\t{}\t{}\t{}", self.id, self.pid, self.label, self.status)
    }
}

/// 进程表的一行（对应服务端 `ps` 的 `pid\tname`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRow {
    pub pid: u32,
    pub name: String,
}

impl ProcessRow {
    pub fn to_line(&self) -> String {
        format!("{}\t{}", self.pid, self.name)
    }
}

/// 引导被服务端拒绝，或链路层失败。
///
/// 分开建模是因为上层处置不同：`Rejected` 的正文就是服务端原话
/// （用法错误 / token 错误 / 目标不存在），应当原样呈现给用户；
/// `Transport` 是连不上、读超时之类的链路问题，通常要带上「连接失败」的上下文，
/// 并且**可以被重试**（Gadget 启动竞态就是靠重试跨过去的）。
#[derive(Debug, Clone)]
pub enum OpenError {
    /// 服务端回了非 OK 行（原文）。
    Rejected(String),
    /// 连接/读写层面的失败。
    Transport(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Rejected(line) => write!(f, "{}", line),
            OpenError::Transport(e) => write!(f, "{}", e),
        }
    }
}

/// 建好的会话 + 事件流 + 服务端 OK 行。
pub struct Opened {
    /// 服务端那一行 `OK sid=N pid=M proto=K`，调用方通常要原样显示。
    pub ok_line: String,
    pub session: Session,
    pub events: Receiver<Event>,
}

/// 建立 TCP 连接（纯连接，不做握手）。
pub fn connect(host: &str, timeout: Duration) -> Result<TcpStream, String> {
    let address = host
        .parse()
        .map_err(|_| format!("无效地址 '{}'（应为 host:port）", host))?;
    TcpStream::connect_timeout(&address, timeout).map_err(|e| format!("连接 {} 失败: {}", host, e))
}

/// 设置读写超时。
///
/// 握手阶段必须有超时：服务端在慢启动或已被占用时可能长时间不回字，
/// 没有超时就会永久挂在这里。
pub fn configure(stream: &TcpStream, timeout: Duration) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("set_read_timeout: {}", e))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("set_write_timeout: {}", e))?;
    Ok(())
}

/// 列会话（服务端 `list`）。
pub fn list_sessions(host: &str, token: Option<&str>, timeout: Duration) -> Result<Vec<SessionRow>, String> {
    let lines = query(host, "list", token, timeout)?;
    Ok(lines.iter().map(|line| parse_session_row(line)).collect())
}

/// 枚举进程（服务端 `ps`，需要 token）。
pub fn list_processes(
    host: &str,
    filter: Option<&str>,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Vec<ProcessRow>, String> {
    let line = match filter {
        Some(f) if !f.trim().is_empty() => format!("ps {}", f.trim()),
        _ => "ps".to_string(),
    };
    let lines = query(host, &line, token, timeout)?;
    Ok(lines.iter().map(|l| parse_process_row(l)).collect())
}

/// 连一次、发一行、读到空行为止、关闭。查询类命令共用这条路径。
fn query(host: &str, line: &str, token: Option<&str>, timeout: Duration) -> Result<Vec<String>, String> {
    let mut stream = connect(host, timeout)?;
    configure(&stream, timeout)?;
    let line = bootstrap::with_token(line, token);
    bootstrap::send_bootstrap(&mut stream, &line, None)?;
    bootstrap::read_response_lines(&mut stream)
}

/// `id\tpid\tlabel\tstatus` → 结构体。
///
/// 用 `splitn(4)` 而不是 `split('\t')`：label 里若混进制表符，多出来的部分
/// 会落到 status 而不是把行拆散 —— 协议本身没有转义机制，能做的就是别丢字段。
fn parse_session_row(line: &str) -> SessionRow {
    let mut parts = line.splitn(4, '\t');
    SessionRow {
        id: parts.next().unwrap_or("").trim().parse().unwrap_or(0),
        pid: parts.next().unwrap_or("").trim().parse().unwrap_or(0),
        label: parts.next().unwrap_or("").to_string(),
        status: parts.next().unwrap_or("").to_string(),
    }
}

/// `pid\tname` → 结构体。分割规则同上。
fn parse_process_row(line: &str) -> ProcessRow {
    let mut parts = line.splitn(2, '\t');
    ProcessRow {
        pid: parts.next().unwrap_or("").trim().parse().unwrap_or(0),
        name: parts.next().unwrap_or("").to_string(),
    }
}

/// 发引导行并建立会话。
///
/// `connect_timeout` 只作用于**建连**；握手与后续会话固定用 [`IO_TIMEOUT_SECS`]，
/// 否则 Gadget 竞态重试时的小连接超时会把正常响应也一起掐掉。
pub fn open_session(
    host: &str,
    bootstrap_line: &str,
    token: Option<&str>,
    script: Option<&str>,
    connect_timeout: Duration,
) -> Result<Opened, OpenError> {
    let stream = connect(host, connect_timeout).map_err(OpenError::Transport)?;
    let io_timeout = Duration::from_secs(IO_TIMEOUT_SECS);
    configure(&stream, io_timeout).map_err(OpenError::Transport)?;

    let mut stream = stream;
    let line = bootstrap::with_token(bootstrap_line, token);
    bootstrap::send_bootstrap(&mut stream, &line, script).map_err(OpenError::Transport)?;
    let ok_line = bootstrap::read_response_line(&mut stream).map_err(OpenError::Transport)?;
    if !ok_line.starts_with("OK") {
        return Err(OpenError::Rejected(ok_line));
    }

    // 服务端/Gadget 在 OK 行里宣告 agent 协议版本；旧服务端没有 proto=，
    // 这时交给 Session 等 HELLO 再定案，等不到就退回 legacy。
    let proto_hint = bootstrap::parse_proto_hint(&ok_line);
    let (session, events) = Session::connect(stream, proto_hint).map_err(OpenError::Transport)?;
    Ok(Opened {
        ok_line,
        session,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 空表返回空列表() {
        assert!(parse_script_list("no scripts loaded").is_empty());
        assert!(parse_script_list("").is_empty());
    }

    #[test]
    fn 解析正常条目() {
        let entries = parse_script_list("script#7 hook.js\tnative=3 java=2 bytes=1024\n");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.id, 7);
        assert_eq!(e.name, "hook.js");
        assert_eq!(e.native_hooks, 3);
        assert_eq!(e.java_hooks, 2);
        assert_eq!(e.bytes, 1024);
        assert_eq!(e.hook_count(), 5);
    }

    #[test]
    fn 文件名带空格时整段归名字() {
        // 制表符才是名字与统计字段的分界，名字里的空格不能被当成分隔。
        let entries = parse_script_list("script#1 my script.js\tnative=0 java=0 bytes=8\n");
        assert_eq!(entries[0].name, "my script.js");
        assert_eq!(entries[0].hook_count(), 0);
    }

    #[test]
    fn 多行与混合内容() {
        let text = "script#1 a.js\tnative=1 java=0 bytes=10\n\
                    script#2 b.js\tnative=0 java=4 bytes=20\n";
        let entries = parse_script_list(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 1);
        assert_eq!(entries[1].id, 2);
        assert_eq!(entries[1].java_hooks, 4);
    }

    #[test]
    fn 无法识别的行被跳过而不是整体失败() {
        // 目标是「多一个字段也比整张表打不开好」：坏行跳过，好行照收。
        let text = "not a script line\nscript#3 c.js\tnative=9 java=9 bytes=9\n";
        let entries = parse_script_list(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 3);
    }

    #[test]
    fn 缺少统计字段时只填名字() {
        // 没有制表符 ⇒ 整段都是名字，统计字段保持 0（而不是把名字丢掉）。
        let entries = parse_script_list("script#5 bare.js");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 5);
        assert_eq!(entries[0].name, "bare.js");
        assert_eq!(entries[0].bytes, 0);
        assert_eq!(entries[0].hook_count(), 0);
    }

    #[test]
    fn 会话行与进程行可往返() {
        let row = parse_session_row("3\t1234\tcom.example\tactive");
        assert_eq!(row.to_line(), "3\t1234\tcom.example\tactive");
        let proc = parse_process_row("4242\tcom.example");
        assert_eq!(proc.to_line(), "4242\tcom.example");
    }

    #[test]
    fn 标签里混进制表符时不丢字段() {
        // 协议没有转义机制；用 splitn 保证余下部分并入 status 而不是把行拆散。
        let row = parse_session_row("1\t2\tweird\tlabel\tactive");
        assert_eq!(row.id, 1);
        assert_eq!(row.pid, 2);
        assert_eq!(row.label, "weird");
        assert_eq!(row.status, "label\tactive");
    }
}
