//! stdout/stderr 捕获：把目标进程写到 fd 1/2 的输出转发到主机。
//!
//! 做法与 frida 一致：注入后 `pipe()` + `dup2()` 把写端接到 fd 1/2，
//! 读端交给一个后台线程，逐块转成 LOG 帧（带 `[stdout] `/`[stderr] ` 前缀）。
//!
//! 为什么需要它：Android 上 `printf` / `__android_log_print` 之外的输出
//! （含 app 自己的 `std::cout`、子进程留下的 fd1 继承）只有 logcat 里能看到，
//! 而 logcat 需要 adb 权限、也被 buffer 淹没。捕获到控制连接后，主机侧
//! 与 `console.log` 输出同流可见。
//!
//! 注意：
//! - read 端必须**持续排空**，否则管道写满后目标进程会卡在 write —— 因此
//!   读线程在 dup2 之后立刻启动，且用阻塞 read。
//! - 卸载前 `stop()` 恢复原 fd，避免把 agent 自己的日志写进已无读者的管道。

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;

use crate::communication;

/// 单管道方案下 stdout/stderr 合流（等价 `2>&1`），统一标 `[out]`。
const FRAME_PREFIX: &[u8] = b"[out] ";
const READ_CHUNK: usize = 8 * 1024;

static ACTIVE: AtomicBool = AtomicBool::new(false);
/// 保存的原始 fd 1/2（-1 = 未保存）。
static SAVED_STDOUT: AtomicI32 = AtomicI32::new(-1);
static SAVED_STDERR: AtomicI32 = AtomicI32::new(-1);
/// 管道写端（dup2 之后由 fd 1/2 持有；这里保留一份用于关闭）。
static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);
/// 管道读端；stop() 时关闭它以让读线程退出。
static PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// 开启捕获。重复调用是空操作（返回 false 表示本来就在捕获）。
pub(crate) fn start() -> Result<bool, String> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if ACTIVE.load(Ordering::Acquire) {
        return Ok(false);
    }

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe() 失败: {}", std::io::Error::last_os_error()));
    }
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // 备份原始 fd，卸载时恢复。
    let saved_out = unsafe { libc::dup(libc::STDOUT_FILENO) };
    let saved_err = unsafe { libc::dup(libc::STDERR_FILENO) };

    if unsafe { libc::dup2(write_fd, libc::STDOUT_FILENO) } < 0
        || unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) } < 0
    {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
            if saved_out >= 0 {
                libc::dup2(saved_out, libc::STDOUT_FILENO);
                libc::close(saved_out);
            }
            if saved_err >= 0 {
                libc::dup2(saved_err, libc::STDERR_FILENO);
                libc::close(saved_err);
            }
        }
        return Err(format!("dup2() 失败: {}", err));
    }

    // fd 1/2 已指向管道写端，多余的 write_fd 可以关掉了（否则永远不会 EOF）。
    unsafe { libc::close(write_fd) };

    SAVED_STDOUT.store(saved_out, Ordering::Release);
    SAVED_STDERR.store(saved_err, Ordering::Release);
    PIPE_WRITE.store(libc::STDOUT_FILENO, Ordering::Release);
    PIPE_READ.store(read_fd, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);

    // 立刻开始排空，避免目标进程写满管道后阻塞。
    crate::raw_thread::spawn_detached(b"wwb-out\0", move || reader_loop())?;
    Ok(true)
}

/// 关闭捕获并恢复原始 fd 1/2。
pub(crate) fn stop() -> Result<bool, String> {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !ACTIVE.load(Ordering::Acquire) {
        return Ok(false);
    }
    ACTIVE.store(false, Ordering::Release);

    // 先恢复 fd（此后目标进程的 write 回到真实 stdout/stderr），
    // 再关读端让读线程的阻塞 read 返回。
    let saved_out = SAVED_STDOUT.swap(-1, Ordering::AcqRel);
    let saved_err = SAVED_STDERR.swap(-1, Ordering::AcqRel);
    unsafe {
        if saved_out >= 0 {
            libc::dup2(saved_out, libc::STDOUT_FILENO);
            libc::close(saved_out);
        }
        if saved_err >= 0 {
            libc::dup2(saved_err, libc::STDERR_FILENO);
            libc::close(saved_err);
        }
    }
    let read_fd = PIPE_READ.swap(-1, Ordering::AcqRel);
    if read_fd >= 0 {
        unsafe { libc::close(read_fd) };
    }
    PIPE_WRITE.store(-1, Ordering::Release);
    Ok(true)
}

/// 排空管道：读到的字节按行拆分后转成 LOG 帧。
///
/// stdout 与 stderr 指向同一个管道写端，因此来源不可区分（等价 `2>&1`），
/// 统一标 `[out] `。想区分需两条管道 + 两个线程，收益不抵复杂度。
fn reader_loop() {
    let read_fd = PIPE_READ.load(Ordering::Acquire);
    if read_fd < 0 {
        return;
    }
    let mut buf = vec![0u8; READ_CHUNK];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        if !ACTIVE.load(Ordering::Acquire) {
            break;
        }
        let n = unsafe { libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            pending.extend_from_slice(&buf[..n as usize]);
            flush_lines(&mut pending);
        } else if n == 0 {
            break;
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // EINTR：继续；EBADF（stop 关了读端）：退出。
                Some(libc::EINTR) => continue,
                _ => break,
            }
        }
    }
    // 收尾：把最后不完整的一行也吐出去，否则短命进程的尾部输出会丢。
    if !pending.is_empty() {
        emit(&pending);
        pending.clear();
    }
}

/// 按 `\n` 切出完整行并发送，保留尾部不完整片段。
fn flush_lines(pending: &mut Vec<u8>) {
    while let Some(pos) = pending.iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = pending.drain(..=pos).collect();
        emit(&line);
    }
}

fn emit(line: &[u8]) {
    let trimmed = trim_ascii_whitespace(line);
    if trimmed.is_empty() {
        return;
    }
    let mut out = Vec::with_capacity(FRAME_PREFIX.len() + trimmed.len() + 1);
    out.extend_from_slice(FRAME_PREFIX);
    out.extend_from_slice(trimmed);
    out.push(b'\n');
    communication::write_stream(&out);
}

fn trim_ascii_whitespace(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(data.len());
    let end = data
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &data[start..end]
}

/// `capture <on|off|status>` 命令的文本响应。
pub(crate) fn command(arg: &str) -> String {
    match arg.trim() {
        "on" | "start" => match start() {
            Ok(true) => "stdout/stderr capture: on".to_string(),
            Ok(false) => "stdout/stderr capture: already on".to_string(),
            Err(e) => format!("stdout/stderr capture failed: {}", e),
        },
        "off" | "stop" => match stop() {
            Ok(true) => "stdout/stderr capture: off".to_string(),
            Ok(false) => "stdout/stderr capture: already off".to_string(),
            Err(e) => format!("stdout/stderr capture failed: {}", e),
        },
        "" | "status" => format!(
            "stdout/stderr capture: {}",
            if is_active() { "on" } else { "off" }
        ),
        other => format!("capture: 未知参数 {}（用法 capture on|off|status）", other),
    }
}
