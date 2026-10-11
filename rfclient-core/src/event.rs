//! 会话事件流：agent/服务端推来的一切「非应答」消息。
//!
//! 与应答分离的原因：应答有明确的请求方（按 reqid 投递，见 [`crate::Session::send`]），
//! 而日志/事件是**广播性质**的 —— 谁在监听谁就能看到，与「正在等哪条命令」无关。
//!
//! 消费方约定：**必须持续排空**。控制连接的 LOG 帧是无节流的（脚本里
//! `console.log` 刷屏时可达上万帧/秒），事件通道不做丢弃，停止消费就会堆积。
//! CLI 用一个专门的打印线程排空；GUI 应每个渲染帧批量 drain 一次
//! （并把历史截断为环形缓冲，否则只是把内存问题从队列挪到 UI 列表里）。

/// 通道（端口转发）建立结果。
#[derive(Debug, Clone)]
pub struct ChannelOpened {
    pub channel_id: u32,
    /// 0 = 成功；其余为 agent 侧错误码（见 agent/src/channel.rs 的 STATUS_*）。
    pub status: u8,
    /// agent 侧的说明文本（失败原因）。
    pub message: String,
    /// 本机请求的目标地址（`host:port`，在目标进程命名空间里解释）。
    /// 由客户端本地记录，未知时为 `None`。
    pub remote: Option<String>,
}

/// 连接结束的方式。分开建模是因为三者在**上层处置不同**：
/// 链路半开要退出进程，正常 BYE 只需提示，IO 错误介于两者之间。
#[derive(Debug, Clone)]
pub enum Disconnect {
    /// 读线程因 IO 错误退出（对端关闭 / RST / 本地网络中断）。
    Io(String),
    /// 心跳超时：连续 [`crate::HEARTBEAT_TIMEOUT_SECS`] 秒无任何入站帧，判定链路半开。
    HeartbeatTimeout,
    /// agent 主动发送 BYE，表示它已完成清理并正常退出。
    Bye,
}

/// agent / 服务端推来的一条消息。
#[derive(Debug, Clone)]
pub enum Event {
    /// agent 日志（`console.log`、`[out] ` 捕获输出、内部 log_msg 等）。
    Log(String),
    /// agent 宣告协议版本，`proto_v2=true` 表示支持 reqid 匹配与心跳。
    Hello { proto_v2: bool },
    /// 服务端结构化事件帧（TSV 已拆好：`ty` + `fields`）。
    /// 例：`detach reason=process-gone pid=1234`、`replay frames=10 bytes=2048 dropped=0`。
    ServerEvent { ty: String, fields: Vec<String> },
    /// 链路保活应答（只用于刷新活动时间，通常无需展示）。
    Pong,
    /// 端口转发通道已建立/失败。
    ChannelOpened(ChannelOpened),
    /// 端口转发通道的数据（目标进程 → 本机方向）。
    ChannelData { channel_id: u32, data: Vec<u8> },
    /// 端口转发通道已关闭。
    ChannelClosed { channel_id: u32 },
    /// 迟到/无主的应答（请求方已超时放弃）。可用于诊断链路时序问题。
    ///
    /// 带上 `kind` 与 `legacy` 是为了让上层能区分「eval 响应 / rpc 错误」
    /// 与「tagged / legacy 通道」四种情形 —— 它们的原因完全不同
    /// （legacy 的 reqid 恒为 0，一旦超时放弃，后续任何 legacy 响应都会成为无主）。
    StaleReply {
        reqid: u32,
        kind: crate::session::ReplyKind,
        legacy: bool,
        text: String,
    },
    /// 连接结束。
    Disconnected(Disconnect),
}
