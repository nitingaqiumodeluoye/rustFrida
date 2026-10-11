//! rfclient-gui — rustFrida 主机端图形客户端。
//!
//! 与 `rfclient`（CLI）共用 `rfclient-core`：协议帧、reqid 匹配、心跳、
//! 端口转发、引导握手全都在 core 里，这里只做界面。
//!
//! 几个刻意的选择：
//!
//! - **渲染后端用 glow（OpenGL）而不是默认的 wgpu**：调试工具经常要跑在
//!   虚拟机、远程桌面、老显卡上，那些环境里 DX12/Vulkan 未必可用，
//!   而 OpenGL 几乎总是能起来。
//! - **后台线程从不直接碰界面**：它们只写日志环形缓冲与状态，然后通过
//!   一个 `Wake` 回调让 egui 重绘（见 `conn.rs`）。界面的唯一写入者是渲染帧。
//! - **不做 `process::exit`**：core 把断连上报为 `Event::Disconnected`，
//!   GUI 只更新状态栏。CLI 之所以要退出进程，是因为 `rustyline::readline`
//!   无法被取消 —— 那是终端特有的限制，不该传染到图形界面。

mod app;
mod conn;
mod fonts;
mod logbuf;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("rustFrida client")
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([880.0, 560.0]),
        // 与 Cargo.toml 的 feature 对应：只编了 glow，不显式指定会走默认枚举值。
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "rfclient-gui",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
