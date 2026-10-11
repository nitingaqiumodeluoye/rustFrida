//! rustFrida 主机端客户端核心库。
//!
//! 从 `rfclient` 二进制里抽出来，让 CLI 与 GUI 共用同一套协议实现：
//! GUI 用 eframe/Tauri 都能直接依赖本 crate，不必复制帧解析与 reqid 匹配逻辑。
//!
//! # 依赖边界
//!
//! 本 crate **不含终端 UI、不含命令行解析、不结束进程**：
//! - 无 `rustyline`（行编辑器只属于 CLI）；
//! - 无 `clap`（参数定义只属于 CLI）；
//! - 不做 `std::process::exit`（连接断开的处置权交给上层：CLI 需要退出以免卡在
//!   readline 上，GUI 只需更新状态栏）。
//!
//! # 典型用法
//!
//! ```no_run
//! use std::time::Duration;
//! use rfclient_core::{bootstrap, Reply, ReplyKind, Session};
//!
//! # fn demo(stream: std::net::TcpStream) -> Result<(), String> {
//! // 1) 引导：发一行命令，读 OK 行
//! let mut stream = stream;
//! bootstrap::send_bootstrap(&mut stream, "attach 1234", None)?;
//! let ok_line = bootstrap::read_response_line(&mut stream)?;
//! let proto_hint = bootstrap::parse_proto_hint(&ok_line);
//!
//! // 2) 建立会话：事件流由调用方排空
//! let (session, events) = Session::connect(stream, proto_hint)?;
//! session.wait_for_hello(Duration::from_millis(rfclient_core::HELLO_WAIT_MILLIS));
//!
//! // 3) 事件（日志/断连）与应答（reqid 匹配）是两条独立通路
//! std::thread::spawn(move || {
//!     for event in events {
//!         println!("{:?}", event);
//!     }
//! });
//!
//! // 4) 发命令并取应答
//! let pending = session.send("jseval 1+1", ReplyKind::Eval)?;
//! match pending.wait(Duration::from_secs(30)) {
//!     Reply::Ok(text) => println!("=> {}", text),
//!     Reply::Err(e) => eprintln!("错误: {}", e),
//!     Reply::Timeout => eprintln!("超时"),
//! }
//! # Ok(())
//! # }
//! ```

pub mod adb;
pub mod bootstrap;
pub mod channel;
pub mod event;
pub mod proto;
pub mod query;
pub mod script;
pub mod session;

pub use channel::{Channels, ForwardInfo};
pub use event::{ChannelOpened, Disconnect, Event};
pub use query::{list_processes, list_sessions, open_session, OpenError, Opened, ProcessRow, SessionRow};
pub use session::{
    Pending, Reply, ReplyKind, Session, HEARTBEAT_INTERVAL_SECS, HEARTBEAT_TIMEOUT_SECS, HELLO_WAIT_MILLIS,
};
