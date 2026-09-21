#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::ffi::CString;

const SUPERCALL_NR: libc::c_long = 45;
const KERNELPATCH_VERSION_CODE: u64 = (0u64 << 16) | (13u64 << 8);
const SUPERCALL_MAGIC: u64 = 0x1158;
const SUPERCALL_KPM_CONTROL: u64 = 0x1022;
const KARINAHIDE: &str = "karinahide";

/// supercall 的 key 参数。
///
/// 内核 supercall 入口会做两道判定：
///   - 调用者是「受信任管理器」（按 APK 签名摘要认定，见 userd.c 的 trusted_managers[]）
///     → is_authed = 1；
///   - 否则仅靠 su 白名单（is_su_allow_uid）只能拿到 is_trusted_caller = 1，
///     **不会**抬高 is_authed，而所有 KPM 命令（load/unload/ctl0/num/list/info）
///     都在 `if (!is_authed) return -EPERM;` 之后 → 一律 EPERM。
/// 因此非管理器进程必须提供**与设备预置值逐字相同**的 superkey。
/// 字面量 "su" 只在「预置 superkey 就是 su」或「root 超级密钥哈希命中」时有效；
/// 换管理器（例如从 me.bmax.apatch 换成 me.yuki.aster）重打 boot 镜像后，
/// 预置值会变成新管理器写入的随机串，此处便不再匹配。
/// 用受信任管理器 uid 调 SUPERCALL_SKEY_GET(0x100a) 可读出当前值。
const SUPERCALL_KEY: &str = "su";

fn versioned_command(command: u64) -> libc::c_long {
    ((KERNELPATCH_VERSION_CODE << 32) | (SUPERCALL_MAGIC << 16) | (command & 0xffff)) as libc::c_long
}

/// 把 errno 还原成人可读的 KernelPatch 错误。
///
/// supercall 挂在真实 syscall 45 (truncate) 上，内核会把返回值里
/// [-4095, -1] 区间的负值统一转成 errno，所以 `libc::syscall` 只会返回 -1，
/// 真正的错误码只在 errno 里。只打印返回值会让 -EPERM / -ENOMEM / -EINVAL /
/// -ESRCH 全部退化成没有信息量的 "-1"。
fn describe_errno(errno: i32) -> &'static str {
    match errno {
        libc::EPERM => {
            "未通过 KernelPatch 授权。KPM 命令在授权门之后，而 kpver/kver 在门之前，\
             所以 kpver 能正常返回并不代表授权通过。需要交给受信任管理器（按 APK 签名\
             摘要认定），或把 SUPERCALL_KEY 换成设备当前的 superkey"
        }
        libc::EINVAL => "参数非法（地址范围/长度/模块名解析失败）",
        libc::ENOENT => "找不到该 KPM 模块（尚未加载，或名字写错）",
        libc::ENOMEM => {
            "内核内存不足，或 madvise 的地址区间未映射/跨了多个 VMA（module 侧回退路径\
             要求整个区间落在单个 VMA 内）"
        }
        libc::ESRCH => "pid/tid 不存在（目标进程或线程已退出）",
        libc::EFAULT => "用户态缓冲区不可访问",
        libc::ENOSYS => "内核不支持该 supercall",
        libc::EOPNOTSUPP => {
            "模块侧功能不可用（例如缺少 madvise 引擎所需的内核符号：do_madvise / \
             find_vma / zap_page_range / down_read / up_read 或 mm_struct 偏移推导失败）"
        }
        _ => "未知错误码",
    }
}

/// KernelPatch 受信任管理器的 uid（由 userd.c 的 trusted_managers[] 按 APK 包名+
/// 签名摘要比对得出）。设备上是 me.yuki.aster，uid=10272。
const TRUSTED_MANAGER_UID: u32 = 10272;

/// 子进程 setuid 失败时经管道回传的哨兵 ret 值（正常 syscall 不会返回它）。
const RET_SETUID_FAILED: i32 = -7001;

/// 在「已 setuid 到受信任管理器 uid」的子进程里执行一次 KPM ctl0，
/// 并把 (ret, errno) 经管道回传。
///
/// 为什么必须降权：内核侧 `is_trusted_manager_uid_android(uid)` 就是
/// `uid == trusted_manager_uid` 的**纯 uid 比较**，而 trusted_manager_uid 由管理器
/// APK 的签名摘要比对得出。rustfrida 本体以 uid 0 运行（ptrace / 改 SELinux 策略
/// 需要 root），但 root 不是管理器 uid，于是所有 KPM 命令
/// （load/unload/ctl0/num/list/info）都因 `if (!is_authed) return -EPERM` 失败。
/// 注意这与传什么 key **完全无关**：实测 key=NULL / 非法指针 / 正确值 / "su" 的
/// 结果完全一致，可见 has_preset_superkey() 为假、key 根本不被解引用。
///
/// 本机设备实测：父进程(uid0) kpm_nums=EPERM；fork 后子进程 setuid(10272)
/// kpm_nums=8、kpm_list 列出全部 8 个模块。父进程保持 root，只在这一次调用上借 uid。
fn control(module: &str, args: &str) -> Result<(), String> {
    let key =
        CString::new(SUPERCALL_KEY).map_err(|e| format!("KernelPatch key 无效: {}", e))?;
    let module = CString::new(module).map_err(|e| format!("KPM 名称无效: {}", e))?;
    let args = CString::new(args).map_err(|e| format!("KPM 参数无效: {}", e))?;

    // 管道：子进程写 8 字节（i32 ret + i32 errno），父进程读。
    let mut fds = [-1 as libc::c_int; 2];
    let pipe_rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if pipe_rc != 0 {
        return Err(format!(
            "KernelPatch ctl0 {} {} 失败: 创建管道出错: {}",
            module.to_string_lossy(),
            args.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(format!(
            "KernelPatch ctl0 {} {} 失败: fork 出错: {}",
            module.to_string_lossy(),
            args.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        /* ================= 子进程：降权后调 supercall ================= */
        // 子进程只写管道，先关掉读端。
        unsafe { libc::close(fds[0]) };

        // SAFETY: 这里的每一步都只为读出一个 (ret, errno)，做完立刻 _exit。
        let (ret, errno) = unsafe {
            if libc::setuid(TRUSTED_MANAGER_UID) != 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                (RET_SETUID_FAILED, e)
            } else {
                let mut output = [0u8; 128];
                let r = libc::syscall(
                    SUPERCALL_NR,
                    key.as_ptr(),
                    versioned_command(SUPERCALL_KPM_CONTROL),
                    module.as_ptr(),
                    args.as_ptr(),
                    output.as_mut_ptr(),
                    output.len(),
                );
                // 必须紧跟 syscall 读取：内核把 supercall 的负返回值折叠成了 errno
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                (r as i32, e)
            }
        };

        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&ret.to_ne_bytes());
        buf[4..].copy_from_slice(&errno.to_ne_bytes());
        unsafe { libc::write(fds[1], buf.as_ptr() as *const libc::c_void, buf.len()) };
        // _exit 不刷新 stdio，但这里没有待刷缓冲；它的返回类型是 !，不会再往下走
        unsafe { libc::_exit(0) }
    }

    /* ================= 父进程：读结果并回收子进程 ================= */
    unsafe { libc::close(fds[1]) };

    let mut buf = [0u8; 8];
    let mut got = 0usize;
    while got < buf.len() {
        let n = unsafe {
            libc::read(
                fds[0],
                buf[got..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - got,
            )
        };
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    unsafe { libc::close(fds[0]) };

    let mut status = 0 as libc::c_int;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    if got != buf.len() {
        return Err(format!(
            "KernelPatch ctl0 {} {} 失败: 子进程未回传结果（管道读到 {} 字节）",
            module.to_string_lossy(),
            args.to_string_lossy(),
            got
        ));
    }

    let ret = i32::from_ne_bytes(buf[..4].try_into().unwrap());
    let code = i32::from_ne_bytes(buf[4..].try_into().unwrap());

    if ret == RET_SETUID_FAILED {
        return Err(format!(
            "KernelPatch ctl0 {} {} 失败: 子进程无法降权到受信任管理器 uid({}): {}\n\
             该 uid 由管理器 APK 签名摘要决定；换过管理器（如 me.bmax.apatch → Aster）后 uid 会变，\n\
             需同步修改 TRUSTED_MANAGER_UID",
            module.to_string_lossy(),
            args.to_string_lossy(),
            TRUSTED_MANAGER_UID,
            describe_errno(code)
        ));
    }

    if ret == 0 {
        return Ok(());
    }

    Err(format!(
        "KernelPatch ctl0 {} {} 失败: syscall={}, errno={} ({})",
        module.to_string_lossy(),
        args.to_string_lossy(),
        ret,
        code,
        describe_errno(code)
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
