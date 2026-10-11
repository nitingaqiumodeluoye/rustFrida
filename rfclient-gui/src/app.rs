//! 主界面：把 core 的会话能力铺成一块调试面板。
//!
//! 界面分层（左→右）：目标选择（进程/会话/spawn）｜ 操作台（脚本/求值/转发/捕获），
//! 顶部是连接状态，底部是常驻日志。这样做的理由是调试工作流的实际顺序：
//! 先选目标，再下发操作，同时**眼睛一直盯着一路滚的日志** —— 所以日志不放在
//! 需要切换的标签页里。
//!
//! 本模块只做「呈现 + 把点击翻译成 [`Client`] 调用」，不碰协议细节。

use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use rfclient_core::query::{ScriptEntry, SessionRow};
use rfclient_core::{ForwardInfo, Reply, ReplyKind, Session};
use rfclient_core::query::ProcessRow;

use crate::conn::{Client, Pumped, QueryResult, TaskResult, Wake};
use crate::logbuf::{LogBuf, Tag, Tab};

/// 顶部提示的停留时长。
const NOTICE_TTL: Duration = Duration::from_secs(8);

/// 进程表 / 会话表的最大高度（避免把左栏挤爆，各自可滚）。
const TABLE_MAX_HEIGHT: f32 = 200.0;

pub struct App {
    host: String,
    token: String,
    client: Client,
    log: LogBuf,

    // —— 目标表 ——
    sessions: Vec<SessionRow>,
    processes: Vec<ProcessRow>,
    ps_filter: String,
    spawn_pkg: String,

    // —— 操作台 ——
    tab: Tab,
    scripts: Vec<ScriptEntry>,
    script_name: String,
    script_src: String,
    jseval_input: String,
    raw_input: String,
    fwd_local: String,
    fwd_remote: String,

    // —— 日志 ——
    log_filter: String,
    auto_scroll: bool,

    /// 最近一次操作的反馈：(文本, 是否为错误, 设置时刻)。
    notice: Option<(String, bool, Instant)>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let log = LogBuf::new();
        log.push(Tag::Client, "就绪。填好地址与令牌后，用左侧按钮连接目标。");
        log.push(
            Tag::Client,
            "提示：端口转发与脚本卸载都只影响目标进程，不会断开控制连接。",
        );
        // Wake 只做一件事：告诉 egui 可以重绘了。后台线程从不直接操作界面。
        let ctx = cc.egui_ctx.clone();
        let wake: Wake = Arc::new(move || ctx.request_repaint());
        let client = Client::new(wake, log.clone());

        App {
            host: "127.0.0.1:15819".to_string(),
            token: String::new(),
            client,
            log,
            sessions: Vec::new(),
            processes: Vec::new(),
            ps_filter: String::new(),
            spawn_pkg: String::new(),
            tab: Tab::Scripts,
            scripts: Vec::new(),
            script_name: "script.js".to_string(),
            script_src: String::new(),
            jseval_input: String::new(),
            raw_input: String::new(),
            fwd_local: String::new(),
            fwd_remote: String::new(),
            log_filter: String::new(),
            auto_scroll: true,
            notice: None,
        }
    }

    fn token(&self) -> Option<String> {
        let trimmed = self.token.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.notice = Some((text.into(), error, Instant::now()));
    }

    /// 连接目标，`bootstrap_line` 是服务端的引导命令。
    fn connect_to(&mut self, bootstrap_line: String, label: String) {
        if self.host.trim().is_empty() {
            self.notify("请先填写服务器地址", true);
            return;
        }
        if self.client.is_connecting() {
            self.notify("上一次连接还在进行中", true);
            return;
        }
        self.client.connect(
            self.host.trim().to_string(),
            bootstrap_line,
            self.token(),
            label,
        );
    }

    /// 处理后台线程的结果。必须在画界面之前调用，否则本帧看到的是上一帧的旧数据。
    fn poll(&mut self) {
        let Pumped {
            task,
            query,
            replies,
        } = self.client.pump();

        match task {
            Some(TaskResult::Connected(opened, label)) => {
                self.client.adopt(*opened, label);
                self.notify("连接成功", false);
                // 连上后立刻拉一次脚本表，省掉用户一次点击。
                self.client.send("jslist", ReplyKind::Eval, "jslist");
            }
            Some(TaskResult::Failed(e)) => {
                self.client
                    .log
                    .push(Tag::Error, format!("连接失败: {}", e));
                self.notify("连接失败，详见日志", true);
            }
            None => {}
        }

        match query {
            Some(QueryResult::Sessions(rows)) => {
                let count = rows.len();
                self.sessions = rows;
                self.notify(format!("会话表已更新（{} 条）", count), false);
            }
            Some(QueryResult::Processes(rows)) => {
                let count = rows.len();
                self.processes = rows;
                self.notify(format!("进程表已更新（{} 条）", count), false);
            }
            Some(QueryResult::Failed(e)) => {
                self.client.log.push(Tag::Error, e.clone());
                self.notify(e, true);
            }
            None => {}
        }

        for (label, reply) in replies {
            self.handle_reply(&label, reply);
        }

        // 顶栏提示到期自动消失，免得用户以为它是常驻状态。
        if let Some((_, _, at)) = &self.notice {
            if at.elapsed() > NOTICE_TTL {
                self.notice = None;
            }
        }
    }

    fn handle_reply(&mut self, label: &str, reply: Reply) {
        // jslist 的应答是一张表，解析出来放进界面，比塞进日志可读得多。
        if label == "jslist" {
            match &reply {
                Reply::Ok(text) => {
                    self.scripts = rfclient_core::parse_script_list(text);
                    return;
                }
                Reply::Err(e) => {
                    self.client.log.push(Tag::Error, format!("jslist 失败: {}", e));
                    return;
                }
                Reply::Timeout => {
                    self.client.log.push(Tag::Error, "jslist 超时");
                    return;
                }
            }
        }
        // 其余命令统一进日志：多行应答按行展开（LogBuf 负责）。
        match reply {
            Reply::Ok(text) => self.client.log.push(Tag::Reply, text),
            Reply::Err(e) => self.client.log.push(Tag::Error, e),
            Reply::Timeout => self
                .client
                .log
                .push(Tag::Error, format!("[{}] 等待应答超时", label)),
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();

        egui::Panel::top("rf-top").show(ui, |ui| self.top_bar(ui));
        // 日志常驻底部：调试时它是主要信息面，不该藏在标签页后面。
        egui::Panel::bottom("rf-log")
            .resizable(true)
            .default_size(260.0)
            .show(ui, |ui| self.log_panel(ui));
        egui::Panel::left("rf-targets")
            .resizable(true)
            .default_size(360.0)
            .show(ui, |ui| self.targets_panel(ui));
        egui::CentralPanel::default_margins().show(ui, |ui| self.workbench(ui));
    }
}

impl App {
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("服务器");
            ui.add(
                egui::TextEdit::singleline(&mut self.host)
                    .desired_width(170.0)
                    .hint_text("127.0.0.1:15819"),
            );
            ui.label("令牌");
            ui.add(
                egui::TextEdit::singleline(&mut self.token)
                    .desired_width(120.0)
                    .password(true)
                    .hint_text("服务端 --token"),
            );

            let state = self.client.state();
            ui.colored_label(state.color(ui.visuals()), format!("● {}", state.label()));
            // 建连是后台线程在跑，给个明确的「还在忙」信号，
            // 否则用户会以为按钮没反应而反复点。
            if self.client.is_connecting() {
                ui.spinner();
            }

            ui.separator();
            let busy = self.client.is_querying();
            if ui
                .add_enabled(!busy, egui::Button::new("刷新会话"))
                .clicked()
            {
                let host = self.host.trim().to_string();
                self.client.refresh_sessions(host, self.token());
            }
            if ui
                .add_enabled(!busy, egui::Button::new("刷新进程"))
                .clicked()
            {
                let host = self.host.trim().to_string();
                let filter = self.ps_filter.clone();
                self.client.refresh_processes(host, filter, self.token());
            }

            let connected = self.client.session().is_some();
            if ui.add_enabled(connected, egui::Button::new("断开")).clicked() {
                self.client.disconnect();
                self.notify("已断开", false);
            }
        });

        if let Some((text, error, _)) = &self.notice {
            let color = if *error {
                ui.visuals().error_fg_color
            } else {
                ui.visuals().weak_text_color()
            };
            ui.colored_label(color, text);
        }
    }

    fn targets_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("进程");
            ui.label("过滤");
            ui.add(
                egui::TextEdit::singleline(&mut self.ps_filter)
                    .desired_width(110.0)
                    .hint_text("名字片段"),
            );
        });

        let mut attach_target: Option<String> = None;
        if self.processes.is_empty() {
            ui.weak("（尚未获取，点顶部「刷新进程」）");
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .max_scroll_height(TABLE_MAX_HEIGHT)
                .column(Column::exact(70.0))
                .column(Column::remainder())
                .column(Column::exact(56.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("PID");
                    });
                    header.col(|ui| {
                        ui.strong("名称");
                    });
                    header.col(|_ui| {});
                })
                .body(|mut body| {
                    for row in &self.processes {
                        body.row(18.0, |mut tr| {
                            tr.col(|ui| {
                                ui.monospace(row.pid.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(&row.name);
                            });
                            tr.col(|ui| {
                                if ui.small_button("注入").clicked() {
                                    attach_target = Some(row.pid.to_string());
                                }
                            });
                        });
                    }
                });
        }

        ui.separator();
        ui.heading("会话");
        let mut use_target: Option<u32> = None;
        if self.sessions.is_empty() {
            ui.weak("（尚未获取，点顶部「刷新会话」）");
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .max_scroll_height(TABLE_MAX_HEIGHT)
                .column(Column::exact(38.0))
                .column(Column::exact(70.0))
                .column(Column::remainder())
                .column(Column::exact(56.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("ID");
                    });
                    header.col(|ui| {
                        ui.strong("PID");
                    });
                    header.col(|ui| {
                        ui.strong("标签");
                    });
                    header.col(|_ui| {});
                })
                .body(|mut body| {
                    for row in &self.sessions {
                        body.row(18.0, |mut tr| {
                            tr.col(|ui| {
                                ui.monospace(row.id.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(row.pid.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(&row.label);
                            });
                            tr.col(|ui| {
                                if ui.small_button("接入").clicked() {
                                    use_target = Some(row.id);
                                }
                            });
                        });
                    }
                });
        }

        ui.separator();
        ui.heading("启动并注入");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.spawn_pkg)
                    .desired_width(200.0)
                    .hint_text("com.example.app"),
            );
            if ui.button("spawn").clicked() {
                let pkg = self.spawn_pkg.trim().to_string();
                if pkg.is_empty() {
                    self.notify("请填写包名", true);
                } else {
                    self.connect_to(format!("spawn {}", pkg), format!("spawn {}", pkg));
                }
            }
        });
        if ui.button("连接已运行的 Gadget").clicked() {
            self.connect_to("gadget".to_string(), "gadget".to_string());
        }

        // 表格里的按钮收集到这里再执行：闭包里借不到 &mut self。
        if let Some(pid) = attach_target {
            self.connect_to(format!("attach {}", pid), format!("attach {}", pid));
        }
        if let Some(id) = use_target {
            self.connect_to(format!("use {}", id), format!("use {}", id));
        }
    }

    fn workbench(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (tab, name) in Tab::ALL {
                ui.selectable_value(&mut self.tab, tab, name);
            }
        });
        ui.separator();

        match self.tab {
            Tab::Scripts => self.scripts_tab(ui),
            Tab::Eval => self.eval_tab(ui),
            Tab::Forward => self.forward_tab(ui),
            Tab::Capture => self.capture_tab(ui),
        }
    }

    fn scripts_tab(&mut self, ui: &mut egui::Ui) {
        let connected = self.client.session().is_some();
        ui.horizontal(|ui| {
            ui.label("文件名");
            ui.add(
                egui::TextEdit::singleline(&mut self.script_name)
                    .desired_width(180.0)
                    .hint_text("script.js"),
            );
            if ui.button("选择文件…").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("JavaScript", &["js", "ts"])
                    .set_title("选择要注入的脚本")
                    .pick_file()
                {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            // 文件名跟着走，否则脚本报错时定位不到是哪个文件。
                            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                                self.script_name = name.to_string();
                            }
                            self.script_src = text;
                            self.notify(format!("已读取 {}", path.display()), false);
                        }
                        Err(e) => self.notify(format!("读取失败: {}", e), true),
                    }
                }
            }
        });

        ui.add(
            egui::TextEdit::multiline(&mut self.script_src)
                .code_editor()
                .desired_rows(14)
                .desired_width(f32::INFINITY)
                .hint_text("// 脚本内容；加载时以 loadjs_init [文件名] 发送"),
        );

        ui.horizontal(|ui| {
            if ui
                .add_enabled(connected, egui::Button::new("加载脚本"))
                .clicked()
            {
                self.load_script();
            }
            if ui
                .add_enabled(connected, egui::Button::new("刷新列表"))
                .clicked()
            {
                self.client.send("jslist", ReplyKind::Eval, "jslist");
            }
            if ui
                .add_enabled(connected, egui::Button::new("清空引擎"))
                .on_hover_text("jsclean：清掉全部 JS 状态与 hook")
                .clicked()
            {
                self.client.send("jsclean", ReplyKind::Eval, "jsclean");
                self.scripts.clear();
            }
        });

        ui.separator();
        ui.label("已加载脚本（jslist）");
        let mut drop_id: Option<u64> = None;
        if self.scripts.is_empty() {
            ui.weak("（无，或尚未刷新）");
        } else {
            TableBuilder::new(ui)
                .striped(true)
                .max_scroll_height(TABLE_MAX_HEIGHT)
                .column(Column::exact(46.0))
                .column(Column::remainder())
                .column(Column::exact(60.0))
                .column(Column::exact(60.0))
                .column(Column::exact(84.0))
                .column(Column::exact(56.0))
                .header(20.0, |mut header| {
                    for title in ["ID", "名称", "native", "java", "字节", ""] {
                        header.col(|ui| {
                            if !title.is_empty() {
                                ui.strong(title);
                            }
                        });
                    }
                })
                .body(|mut body| {
                    for entry in &self.scripts {
                        body.row(18.0, |mut tr| {
                            tr.col(|ui| {
                                ui.monospace(entry.id.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(&entry.name);
                            });
                            tr.col(|ui| {
                                ui.monospace(entry.native_hooks.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(entry.java_hooks.to_string());
                            });
                            tr.col(|ui| {
                                ui.monospace(entry.bytes.to_string());
                            });
                            tr.col(|ui| {
                                if ui
                                    .small_button("卸载")
                                    .on_hover_text("只卸载该脚本注册的 hook；它写过的全局变量不会被清理")
                                    .clicked()
                                {
                                    drop_id = Some(entry.id);
                                }
                            });
                        });
                    }
                });
        }

        if let Some(id) = drop_id {
            self.client
                .send(&format!("jsdrop {}", id), ReplyKind::Eval, "jsdrop");
            // 卸载后立刻重拉一次，列表不刷新会让人以为没生效。
            self.client.send("jslist", ReplyKind::Eval, "jslist");
        }
    }

    /// 发送脚本：`loadjs_init [文件名]` + 换行 + 正文。
    ///
    /// 用 `loadjs_init` 而不是 `loadjs`：前者会自动初始化引擎，且带上文件名，
    /// 报错时能定位到 `文件名:行:列`。
    fn load_script(&mut self) {
        if self.script_src.trim().is_empty() {
            self.notify("脚本内容为空", true);
            return;
        }
        let name = if self.script_name.trim().is_empty() {
            "script.js"
        } else {
            self.script_name.trim()
        };
        let payload = format!("loadjs_init [{}]\n{}", name, self.script_src);
        self.client.send(&payload, ReplyKind::Eval, "loadjs");
        // 加载完重拉脚本表，让新脚本立刻出现在列表里。
        self.client.send("jslist", ReplyKind::Eval, "jslist");
    }

    fn eval_tab(&mut self, ui: &mut egui::Ui) {
        let connected = self.client.session().is_some();

        ui.label("JS 表达式（jseval）");
        let submitted = ui
            .horizontal(|ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.jseval_input)
                        .desired_width(f32::INFINITY)
                        .hint_text("例：Java.available ? Object.keys(Java).length : 0"),
                );
                // 回车即执行 —— 求值窗口不回车就没意义。
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.add_enabled(connected, egui::Button::new("执行")).clicked() || enter {
                    self.run_jseval();
                    true
                } else {
                    false
                }
            })
            .inner;
        if submitted {
            ui.ctx().request_repaint();
        }

        ui.separator();
        ui.label("原始命令（发给 agent 的一行文本）");
        ui.weak(
            "用于 capture / hfl / trace / stalker / jhook / jsinit / jslist / jsdrop 等；\
             无应答的命令不会出现在日志里，其输出走 agent 日志。",
        );
        let submitted = ui
            .horizontal(|ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.raw_input)
                        .desired_width(f32::INFINITY)
                        .hint_text("例：capture on"),
                );
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.add_enabled(connected, egui::Button::new("发送")).clicked() || enter {
                    let cmd = self.raw_input.trim().to_string();
                    if !cmd.is_empty() {
                        // 只产生 LOG 帧的命令不该挂着一个等不来的应答；
                        // 判断逻辑与 CLI 共用 core 的 expects_response。
                        if rfclient_core::script::expects_response(&cmd) {
                            self.client.send(&cmd, ReplyKind::Eval, "cmd");
                        } else {
                            self.client.send_no_reply(&cmd);
                            self.client.log.push(Tag::Client, format!("已发送（无应答）: {}", cmd));
                        }
                    }
                    self.raw_input.clear();
                    true
                } else {
                    false
                }
            })
            .inner;
        if submitted {
            ui.ctx().request_repaint();
        }
    }

    fn run_jseval(&mut self) {
        let expr = self.jseval_input.trim().to_string();
        if expr.is_empty() {
            return;
        }
        // 与 CLI / 设备端一致：包装后发送，错误与结果都走同一条应答通道。
        let payload = format!("jseval {}", rfclient_core::script::wrap_jseval_expr(&expr));
        self.client.send(&payload, ReplyKind::Eval, "jseval");
        self.jseval_input.clear();
    }

    fn forward_tab(&mut self, ui: &mut egui::Ui) {
        let connected = self.client.session().is_some();
        ui.label("把本机端口转发到目标进程内的服务（open_channel）");
        ui.weak(
            "远端地址在目标进程的网络命名空间里解释；只填端口号时等同 127.0.0.1:<端口>。",
        );
        ui.horizontal(|ui| {
            ui.label("本机端口");
            ui.add(
                egui::TextEdit::singleline(&mut self.fwd_local)
                    .desired_width(70.0)
                    .hint_text("8080"),
            );
            ui.label("远端");
            ui.add(
                egui::TextEdit::singleline(&mut self.fwd_remote)
                    .desired_width(150.0)
                    .hint_text("80 或 host:port"),
            );
            if ui.add_enabled(connected, egui::Button::new("建立转发")).clicked() {
                self.start_forward();
            }
        });

        ui.separator();
        ui.label("进行中的转发");
        let forwards = self.current_forwards();
        if forwards.is_empty() {
            ui.weak("（无）");
        } else {
            let mut stop: Option<u16> = None;
            TableBuilder::new(ui)
                .striped(true)
                .max_scroll_height(TABLE_MAX_HEIGHT)
                .column(Column::exact(90.0))
                .column(Column::remainder())
                .column(Column::exact(90.0))
                .column(Column::exact(56.0))
                .header(20.0, |mut header| {
                    for title in ["本机", "远端（目标进程内）", "活跃连接", ""] {
                        header.col(|ui| {
                            if !title.is_empty() {
                                ui.strong(title);
                            }
                        });
                    }
                })
                .body(|mut body| {
                    for info in &forwards {
                        body.row(18.0, |mut tr| {
                            tr.col(|ui| {
                                ui.monospace(format!("127.0.0.1:{}", info.local_port));
                            });
                            tr.col(|ui| {
                                ui.monospace(&info.remote);
                            });
                            tr.col(|ui| {
                                ui.monospace(info.active_connections.to_string());
                            });
                            tr.col(|ui| {
                                if ui.small_button("停止").clicked() {
                                    stop = Some(info.local_port);
                                }
                            });
                        });
                    }
                });
            if let Some(port) = stop {
                self.stop_forward(port);
            }
        }
    }

    fn current_forwards(&self) -> Vec<ForwardInfo> {
        self.client
            .session()
            .map(|s| s.channels().list())
            .unwrap_or_default()
    }

    fn start_forward(&mut self) {
        let Ok(local) = self.fwd_local.trim().parse::<u16>() else {
            self.notify("本机端口必须是 1-65535", true);
            return;
        };
        if local == 0 {
            self.notify("本机端口不能为 0", true);
            return;
        }
        let remote = self.fwd_remote.trim();
        // 省略 host 时等同于目标进程内的 127.0.0.1:<同端口>，与 CLI 一致。
        let remote = if remote.is_empty() {
            local.to_string()
        } else {
            remote.to_string()
        };
        let Some(session) = self.client.session().cloned() else {
            self.notify("尚未连接", true);
            return;
        };
        match session.channels().forward(local, &remote) {
            Ok(bound) => {
                self.notify(format!("已建立转发 127.0.0.1:{} → {}", bound, remote), false);
                self.client.log.push(
                    Tag::Forward,
                    format!("转发已启动: 127.0.0.1:{} → {}", bound, remote),
                );
            }
            Err(e) => {
                self.client.log.push(Tag::Error, e.clone());
                self.notify(e, true);
            }
        }
    }

    fn stop_forward(&mut self, port: u16) {
        let Some(session) = self.client.session().cloned() else {
            return;
        };
        match session.channels().unforward(port) {
            Ok(closed) => {
                self.client.log.push(
                    Tag::Forward,
                    format!("已停止转发 127.0.0.1:{}（关闭 {} 个连接）", port, closed),
                );
            }
            Err(e) => self.client.log.push(Tag::Error, e),
        }
    }

    fn capture_tab(&mut self, ui: &mut egui::Ui) {
        let connected = self.client.session().is_some();
        ui.label("目标进程 stdout/stderr 捕获");
        ui.weak(
            "agent 把 fd 1/2 重定向到一个管道，读到的内容以 [out] 前缀回到本客户端。\
             两路合并为一路（等价于 2>&1）。",
        );
        ui.horizontal(|ui| {
            for (label, cmd) in [("开启", "capture on"), ("关闭", "capture off"), ("查询状态", "capture status")] {
                if ui.add_enabled(connected, egui::Button::new(label)).clicked() {
                    self.client.send(cmd, ReplyKind::Eval, "capture");
                }
            }
        });
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("日志");
            ui.checkbox(&mut self.auto_scroll, "自动滚动");
            ui.label("过滤");
            ui.add(
                egui::TextEdit::singleline(&mut self.log_filter)
                    .desired_width(160.0)
                    .hint_text("子串"),
            );
            if ui.button("清空").clicked() {
                self.log.clear();
            }
        });

        let filter = self.log_filter.trim().to_lowercase();
        let visuals = ui.visuals().clone();
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
        let auto_scroll = self.auto_scroll;

        self.log.read(|lines| {
            // 先算出通过过滤的**索引**，再按行号渲染：只有可见行会被格式化，
            // 两万行也不会卡。
            let visible: Vec<usize> = if filter.is_empty() {
                (0..lines.len()).collect()
            } else {
                lines
                    .iter()
                    .enumerate()
                    .filter(|(_, line)| line.text.to_lowercase().contains(&filter))
                    .map(|(index, _)| index)
                    .collect()
            };
            let total = visible.len();

            egui::ScrollArea::vertical()
                .stick_to_bottom(auto_scroll)
                .auto_shrink([false, false])
                .show_rows(ui, row_height, total, |ui, range| {
                    for slot in range {
                        let Some(line) = visible.get(slot).and_then(|index| lines.get(*index)) else {
                            continue;
                        };
                        let color = line.tag.color(&visuals);
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            ui.label(
                                egui::RichText::new(line.tag.prefix())
                                    .monospace()
                                    .color(color),
                            );
                            ui.label(egui::RichText::new(&line.text).monospace().color(color));
                        });
                    }
                });
        });
    }
}

/// 供状态栏使用的会话可读标签（预留：多会话时用于显示当前目标）。
#[allow(dead_code)]
fn describe(session: &Arc<Session>) -> String {
    format!(
        "{}",
        if session.proto_v2() {
            "协议 v2"
        } else {
            "协议 v1"
        }
    )
}
