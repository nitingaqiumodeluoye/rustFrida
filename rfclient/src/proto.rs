//! 帧协议（与 rust_frida/src/communication.rs 的常量保持一致）。
//!
//! 每一帧: `1 字节 kind + 4 字节 LE length + payload`。
//! host→agent: CMD(1), QBDI_HELPER(2)
//! agent→host: HELLO(0x80), LOG(0x81), COMPLETE(0x82), EVAL_OK(0x83),
//!             EVAL_ERR(0x84), RPC_OK(0x85), RPC_ERR(0x86), BYE(0x87)

use std::io::{Read, Write};

pub const FRAME_KIND_CMD: u8 = 1;
/// 主机→agent 的 QBDI helper 传输帧（客户端暂不发送，保留以保持协议完整）
#[allow(dead_code)]
pub const FRAME_KIND_QBDI_HELPER: u8 = 2;
/// TCP bootstrap frame carrying a script read from the host filesystem.
pub const FRAME_KIND_BOOTSTRAP_SCRIPT: u8 = 3;
const MAX_FRAME_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

pub const FRAME_KIND_HELLO: u8 = 0x80;
pub const FRAME_KIND_LOG: u8 = 0x81;
pub const FRAME_KIND_COMPLETE: u8 = 0x82;
pub const FRAME_KIND_EVAL_OK: u8 = 0x83;
pub const FRAME_KIND_EVAL_ERR: u8 = 0x84;
pub const FRAME_KIND_RPC_OK: u8 = 0x85;
pub const FRAME_KIND_RPC_ERR: u8 = 0x86;
pub const FRAME_KIND_BYE: u8 = 0x87;

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
