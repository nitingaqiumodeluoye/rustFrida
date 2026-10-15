//! 共享日志环形缓冲。
//!
//! 为什么是环形缓冲而不是 `Vec`：控制连接的 LOG 帧**无节流**，脚本里
//! `console.log` 刷屏时可达上万帧/秒，而 GUI 可能整夜开着。只追加不截断
//! 就只是把内存问题从事件队列搬到 UI 列表里 —— 所以这里固定上限，
//! 超出的从头部丢。
//!
//! 缓冲是 `Arc<Mutex<..>>`：写入方是后台排空线程，读取方是渲染帧。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use eframe::egui;

/// 最多保留的行数。20k 行 × 约 80 字节 ≈ 1.6 MB，够翻很久又不会失控。
pub const MAX_LINES: usize = 20_000;

/// 日志来源，决定前缀与颜色。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// 本客户端的提示（连接中、断开、转发状态…）。
    Client,
    /// agent 日志（`console.log`、内部 log_msg）。
    Agent,
    /// 目标进程 stdout/stderr 捕获（agent 的 `[out] ` 前缀）。
    Out,
    /// 服务端镜像日志（服务端自己打的 `[server] ` 前缀）。
    ///
    /// 与 `Agent` 区分开：`Agent` 是目标进程里脚本的 `console.log`，
    /// 而本类容是服务端在设备侧发生的事（注入失败、脚本加载超时…）。
    Server,
    /// 服务端结构化事件（detach / replay 等）。
    Event,
    /// 命令应答（`=> ...`）。
    Reply,
    /// 错误与超时。
    Error,
    /// 端口转发相关。
    Forward,
}

impl Tag {
    pub fn prefix(self) -> &'static str {
        match self {
            Tag::Client => "[client] ",
            Tag::Agent => "[agent] ",
            Tag::Out => "[out] ",
            Tag::Server => "[server] ",
            Tag::Event => "[event] ",
            Tag::Reply => "=> ",
            Tag::Error => "[错误] ",
            Tag::Forward => "[forward] ",
        }
    }

    pub fn color(self, visuals: &egui::Visuals) -> egui::Color32 {
        let dark = visuals.dark_mode;
        match self {
            // 客户端提示：用弱化的前景色，避免和 agent 的真实输出抢注意力。
            Tag::Client => visuals.weak_text_color(),
            Tag::Agent => visuals.text_color(),
            // 捕获输出用青色：它和目标进程的日志混在一起时必须能一眼分开。
            Tag::Out => {
                if dark {
                    egui::Color32::from_rgb(120, 200, 210)
                } else {
                    egui::Color32::from_rgb(20, 110, 120)
                }
            }
            Tag::Event => {
                if dark {
                    egui::Color32::from_rgb(200, 170, 255)
                } else {
                    egui::Color32::from_rgb(110, 60, 180)
                }
            }
            // 服务端镜像：中性石板色。文本自带 `[!]` / `[✗]` 已说明严重程度，
            // 这里不再用红/黄抢注意力，但要与 `Agent` 的正文色分开。
            Tag::Server => {
                if dark {
                    egui::Color32::from_rgb(150, 165, 190)
                } else {
                    egui::Color32::from_rgb(75, 90, 115)
                }
            }
            Tag::Reply => {
                if dark {
                    egui::Color32::from_rgb(150, 220, 150)
                } else {
                    egui::Color32::from_rgb(30, 120, 40)
                }
            }
            Tag::Error => {
                if dark {
                    egui::Color32::from_rgb(255, 130, 130)
                } else {
                    egui::Color32::from_rgb(190, 40, 40)
                }
            }
            Tag::Forward => {
                if dark {
                    egui::Color32::from_rgb(255, 200, 120)
                } else {
                    egui::Color32::from_rgb(150, 100, 20)
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub tag: Tag,
    pub text: String,
}

/// 多行文本按行拆开，避免一条 3000 行的应答把行高算崩。
fn push_lines(buf: &mut VecDeque<LogLine>, tag: Tag, text: &str) {
    let mut any = false;
    for line in text.lines() {
        buf.push_back(LogLine {
            tag,
            text: line.to_string(),
        });
        any = true;
    }
    // 全是空白（或空串）时也要留一条，否则用户看不到「命令执行了」。
    if !any {
        buf.push_back(LogLine {
            tag,
            text: String::new(),
        });
    }
    while buf.len() > MAX_LINES {
        buf.pop_front();
    }
}

#[derive(Clone)]
pub struct LogBuf(Arc<Mutex<VecDeque<LogLine>>>);

impl Default for LogBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl LogBuf {
    pub fn new() -> Self {
        LogBuf(Arc::new(Mutex::new(VecDeque::new())))
    }

    /// 追加（后台线程与 UI 线程都会调用）。
    pub fn push(&self, tag: Tag, text: impl AsRef<str>) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        push_lines(&mut guard, tag, text.as_ref());
    }

    pub fn clear(&self) {
        let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        guard.clear();
    }

    /// 只读取，不克隆 —— 渲染时按可见行范围取，避免每帧复制整个缓冲。
    pub fn read<R>(&self, f: impl FnOnce(&VecDeque<LogLine>) -> R) -> R {
        let guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&guard)
    }
}

/// 标签页选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Scripts,
    Eval,
    Forward,
    Capture,
}

impl Tab {
    pub const ALL: [(Tab, &'static str); 4] = [
        (Tab::Scripts, "脚本"),
        (Tab::Eval, "求值 / 命令"),
        (Tab::Forward, "端口转发"),
        (Tab::Capture, "输出捕获"),
    ];
}
