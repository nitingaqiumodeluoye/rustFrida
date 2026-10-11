//! 帧协议（与 rust_frida/src/communication.rs 及 agent/src/communication.rs 的常量保持一致）。
//!
//! 每一帧: `1 字节 kind + 4 字节 LE length + payload`。
//!
//! ── v1（legacy）──
//! host→agent: CMD(1), QBDI_HELPER(2)
//! agent→host: HELLO(0x80), LOG(0x81), COMPLETE(0x82), EVAL_OK(0x83),
//!             EVAL_ERR(0x84), RPC_OK(0x85), RPC_ERR(0x86), BYE(0x87)
//!
//! ── v2 ──
//! host→agent: CMD_TAGGED(4)   = `4B LE reqid + 命令文本`；agent 响应回填同一 reqid，
//!                               客户端据此并发匹配响应（修复 legacy 单槽响应串台）
//!             PING(5)         = 链路保活探测；agent 回 PONG
//! agent→host: EVAL_OK_TAGGED(0x90) / EVAL_ERR_TAGGED(0x91) / RPC_OK_TAGGED(0x92) /
//!             RPC_ERR_TAGGED(0x93) / COMPLETE_TAGGED(0x94)，载荷 = `4B LE reqid + 原 payload`
//!             EVENT(0x95)     = server 结构化事件（TSV: `detach\treason=...\t...`）
//!             PONG(0x97)
//!
//! HELLO 载荷 `proto=2` 表示对端支持 v2。

use std::io::{Read, Write};

pub const FRAME_KIND_CMD: u8 = 1;
/// 主机→agent 的 QBDI helper 传输帧（客户端暂不发送，保留以保持协议完整）
#[allow(dead_code)]
pub const FRAME_KIND_QBDI_HELPER: u8 = 2;
/// TCP bootstrap frame carrying a script read from the host filesystem.
pub const FRAME_KIND_BOOTSTRAP_SCRIPT: u8 = 3;
/// 协议 v2：带 reqid 的命令帧。
pub const FRAME_KIND_CMD_TAGGED: u8 = 4;
/// 协议 v2：链路保活探测帧。
pub const FRAME_KIND_PING: u8 = 5;

pub const FRAME_KIND_HELLO: u8 = 0x80;
pub const FRAME_KIND_LOG: u8 = 0x81;
pub const FRAME_KIND_COMPLETE: u8 = 0x82;
pub const FRAME_KIND_EVAL_OK: u8 = 0x83;
pub const FRAME_KIND_EVAL_ERR: u8 = 0x84;
pub const FRAME_KIND_RPC_OK: u8 = 0x85;
pub const FRAME_KIND_RPC_ERR: u8 = 0x86;
pub const FRAME_KIND_BYE: u8 = 0x87;

/// 协议 v2 tagged 响应帧（载荷 = 4B LE reqid + 原 payload）。
pub const FRAME_KIND_EVAL_OK_TAGGED: u8 = 0x90;
pub const FRAME_KIND_EVAL_ERR_TAGGED: u8 = 0x91;
pub const FRAME_KIND_RPC_OK_TAGGED: u8 = 0x92;
pub const FRAME_KIND_RPC_ERR_TAGGED: u8 = 0x93;
pub const FRAME_KIND_COMPLETE_TAGGED: u8 = 0x94;
/// server 结构化事件帧（TSV 文本）。
pub const FRAME_KIND_EVENT: u8 = 0x95;
/// 链路保活应答帧。
pub const FRAME_KIND_PONG: u8 = 0x97;

const MAX_FRAME_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

pub fn write_frame(stream: &mut dyn Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("frame payload exceeds {} bytes", MAX_FRAME_PAYLOAD_BYTES),
        ));
    }
    stream.write_all(&[kind])?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)
}

/// 发送带 reqid 的命令帧（协议 v2）。
pub fn write_tagged_cmd(stream: &mut dyn Write, reqid: u32, cmd: &str) -> std::io::Result<()> {
    let mut payload = Vec::with_capacity(4 + cmd.len());
    payload.extend_from_slice(&reqid.to_le_bytes());
    payload.extend_from_slice(cmd.as_bytes());
    write_frame(stream, FRAME_KIND_CMD_TAGGED, &payload)
}

/// 发送链路保活探测帧。
pub fn write_ping(stream: &mut dyn Write) -> std::io::Result<()> {
    write_frame(stream, FRAME_KIND_PING, &[])
}

pub fn write_bootstrap_script(stream: &mut dyn Write, filename: &str, content: &str) -> std::io::Result<()> {
    let filename = filename.as_bytes();
    if filename.is_empty() || filename.len() > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid bootstrap script filename",
        ));
    }
    let mut payload = Vec::with_capacity(4 + filename.len() + content.len());
    payload.extend_from_slice(&(filename.len() as u32).to_le_bytes());
    payload.extend_from_slice(filename);
    payload.extend_from_slice(content.as_bytes());
    write_frame(stream, FRAME_KIND_BOOTSTRAP_SCRIPT, &payload)
}

pub fn read_frame(reader: &mut dyn Read) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// 拆 tagged 响应载荷为 (reqid, payload)。
pub fn split_tagged_payload(payload: &[u8]) -> Option<(u32, &[u8])> {
    if payload.len() < 4 {
        return None;
    }
    let reqid = u32::from_le_bytes(payload[..4].try_into().unwrap());
    Some((reqid, &payload[4..]))
}

/// 判断 kind 是否为 tagged 响应帧。
#[allow(dead_code)]
pub fn is_tagged_response(kind: u8) -> bool {
    matches!(
        kind,
        FRAME_KIND_EVAL_OK_TAGGED
            | FRAME_KIND_EVAL_ERR_TAGGED
            | FRAME_KIND_RPC_OK_TAGGED
            | FRAME_KIND_RPC_ERR_TAGGED
            | FRAME_KIND_COMPLETE_TAGGED
    )
}
