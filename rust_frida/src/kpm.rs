#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::ffi::CString;

const SUPERCALL_NR: libc::c_long = 45;
const KERNELPATCH_VERSION_CODE: u64 = (0u64 << 16) | (13u64 << 8);
const SUPERCALL_MAGIC: u64 = 0x1158;
const SUPERCALL_KPM_CONTROL: u64 = 0x1022;
const KARINAHIDE: &str = "karinahide";

fn versioned_command(command: u64) -> libc::c_long {
    ((KERNELPATCH_VERSION_CODE << 32) | (SUPERCALL_MAGIC << 16) | (command & 0xffff)) as libc::c_long
}

fn control(module: &str, args: &str) -> Result<(), String> {
    let key = CString::new("su").map_err(|e| format!("KernelPatch key 无效: {}", e))?;
    let module = CString::new(module).map_err(|e| format!("KPM 名称无效: {}", e))?;
    let args = CString::new(args).map_err(|e| format!("KPM 参数无效: {}", e))?;
    let mut output = [0u8; 128];

    let ret = unsafe {
        libc::syscall(
            SUPERCALL_NR,
            key.as_ptr(),
            versioned_command(SUPERCALL_KPM_CONTROL),
            module.as_ptr(),
            args.as_ptr(),
            output.as_mut_ptr(),
            output.len(),
        )
    };
    if ret == 0 {
        return Ok(());
    }

    Err(format!(
        "KernelPatch ctl0 {} {} 失败，返回 {}",
        module.to_string_lossy(),
        args.to_string_lossy(),
        ret
    ))
}

/// Ask karinahide to drop MADV_DONTNEED pages in another process without a
/// userspace ptrace call or a target-side libc call.
pub(crate) fn madvise_dontneed(pid: i32, start: usize, len: usize) -> Result<(), String> {
    if pid <= 0 {
        return Err(format!("无效的 madvise pid: {}", pid));
    }
    if start == 0 || len == 0 {
        return Err(format!("无效的 madvise 地址范围: 0x{:x}+0x{:x}", start, len));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| format!("madvise 地址范围溢出: 0x{:x}+0x{:x}", start, len))?;
    if end <= start {
        return Err(format!("madvise 地址范围无效: 0x{:x}+0x{:x}", start, len));
    }

    let args = format!("madvise {} 0x{:x} 0x{:x}", pid, start, len);
    control(KARINAHIDE, &args)
}
