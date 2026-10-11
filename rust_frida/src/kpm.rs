#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use crate::{log_verbose, log_warn};
use std::ffi::CString;
use std::sync::OnceLock;

const SUPERCALL_NR: libc::c_long = 45;
const KERNELPATCH_VERSION_CODE: u64 = (0u64 << 16) | (13u64 << 8);
const SUPERCALL_MAGIC: u64 = 0x1158;
const SUPERCALL_KPM_CONTROL: u64 = 0x1022;
const SUPERCALL_KPM_NUMS: u64 = 0x1030;
const KARINAHIDE: &str = "karinahide";

/// supercall 的 key 参数。
///
/// 内核 `before()` 的授权判定分两路：
///   - 预置了 superkey 时（APatch/FolkPatch 安装器用 `--skey` 写入，所以
///     `has_preset_superkey()` 为真），读 key 与预置值比对，命中才 `is_authed = 1`；
///   - `is_trusted_manager_uid(uid)` 命中「受信任管理器」（按 APK 包名+签名摘要认定）
///     时无条件 `is_trusted_caller = 1; is_authed = 1`。
///
/// 而 `is_su_allow_uid(uid)` 只抬 `is_trusted_caller`、**不抬** `is_authed`，
/// 于是 uid 0 依旧会在 `if (!is_authed) return -EPERM;` 处被拒。
/// 本设备实测：root 调 `kpm_nums` 得到 EPERM，dmesg 里连
/// `module_control0` 的 `name %s, args: %s` 都没有。
///
/// 预置 superkey 是安装时随机生成的，无从得知，所以这里保留原值不作依赖——
/// 真正生效的是 `TRUSTED_MANAGER_PACKAGES` 那条路径（降权到管理器 uid）。
const SUPERCALL_KEY: &str = "su";

/// 内核 `userd.c` 的 `trusted_managers[]` 按「包名 + APK 签名摘要」扫出管理器 uid。
/// 不同分支里这张表只有一项：
///   - LyraVoid/KernelPatch（FolkPatch 用的）：`me.yuki.folk`
///   - bmax121/KernelPatch：`me.bmax.apatch`
/// 候选按下面顺序尝试，取第一个能在 packages.list 里解析出 uid 的。
const TRUSTED_MANAGER_PACKAGES: [&str; 3] =
    ["me.yuki.folk", "me.yuki.aster", "me.bmax.apatch"];

/// 兜底 uid。换设备/重装后管理器 uid 会变，正常情况下走自动解析；
/// 这个值只在 packages.list 读不到时的最后兜底（本机实测值）。
const FALLBACK_TRUSTED_MANAGER_UID: u32 = 10236;

/// 内核自己也是从这两个文件读 uid 的（`userd.c` 的
/// `ANDROID_PACKAGES_LIST_PATH` / `..._TMP_PATH`），这里跟随同一来源。
const PACKAGES_LIST: &str = "/data/system/packages.list";
const PACKAGES_LIST_TMP: &str = "/data/system/packages.list.tmp";

/// 子进程 setuid 失败时经管道回传的哨兵 ret 值（正常 syscall 不会返回它）。
const RET_SETUID_FAILED: i32 = -7001;

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
             摘要认定），或提供设备预置的 superkey"
        }
        libc::EINVAL => "参数非法（地址范围/长度/模块名解析失败）",
        libc::ENOENT => {
            "授权门未放行，或找不到该 KPM 模块。两种情况的 errno 相同——未授权时内核\
             不设 skip_origin，原始 truncate(\"su\", …) 会真的执行并以 ENOENT 失败，\
             把授权问题伪装成「模块不存在」。真正的授权结论见同一错误里的探测结果"
        }
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

/// 从 `/data/system/packages.list` 里按包名取 uid。
///
/// 格式（空白分隔）：`<name> <uid> <debuggable> <dataDir> <seinfo> [gids…]`
///
/// rustfrida 以 uid 0 运行，读得到这个文件；读不到时返回 None 交给调用方兜底。
fn lookup_package_uid(package: &str) -> Option<u32> {
    for path in [PACKAGES_LIST, PACKAGES_LIST_TMP] {
        let content = match std::fs::read_to_string(path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for line in content.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() != Some(package) {
                continue;
            }
            if let Some(uid) = fields.next().and_then(|v| v.parse::<u32>().ok()) {
                return Some(uid);
            }
        }
    }
    None
}

/// 解析受信任管理器的 uid，结果进程内缓存。
///
/// 内核侧 `is_trusted_manager_uid_android()` 就是一次纯 uid 比较，而 trusted_manager_uid
/// 由管理器 APK 的签名摘要比对得出。rustfrida 本体以 uid 0 运行（ptrace / 改 SELinux
/// 策略需要 root），但 root 不是管理器 uid，于是所有 KPM 命令都因
/// `if (!is_authed) return -EPERM` 失败。所以只在「这一次」KPM 调用上借管理器 uid。
///
/// 硬编码常量换设备就失效（历史上从 me.bmax.apatch 换成 me.yuki.aster 时 uid 由
/// 10272 变过），因此改为按候选包名实时解析。
fn trusted_manager_uid() -> u32 {
    static CACHE: OnceLock<u32> = OnceLock::new();
    *CACHE.get_or_init(|| {
        for package in TRUSTED_MANAGER_PACKAGES {
            if let Some(uid) = lookup_package_uid(package) {
                log_verbose!(
                    "受信任管理器: {} uid={}（来自 {}）",
                    package,
                    uid,
                    PACKAGES_LIST
                );
                return uid;
            }
        }
        log_warn!(
            "未在 {} 里找到任何候选管理器包名 {:?}，回退到兜底 uid {}；\
             若 KPM 调用报授权失败，请核对 TRUSTED_MANAGER_PACKAGES 与 FALLBACK_TRUSTED_MANAGER_UID",
            PACKAGES_LIST,
            TRUSTED_MANAGER_PACKAGES,
            FALLBACK_TRUSTED_MANAGER_UID
        );
        FALLBACK_TRUSTED_MANAGER_UID
    })
}

/// 在「已 setuid 到 `uid`」的子进程里执行一次 supercall，把 (ret, errno) 经管道回传。
///
/// 为什么必须降权：内核侧 `is_trusted_manager_uid_android(uid)` 是纯 uid 比较，
/// 而 uid 0 既不是管理器、也不在 su 白名单，因此在授权门处直接返回，
/// 连模块的 ctl0 都进不去。
///
/// 特意用 fork 而不是直接 setuid：父进程必须留在 uid 0（ptrace、SELinux 策略都要 root），
/// 只把这一次调用借给管理器 uid。子进程除了这一次 syscall 什么都不做，
/// `_exit` 收尾，避免把 rustFrida 的 fd / 锁带进另一个 uid。
///
/// `key` / `name` / `args` / `out` 都在 fork 前构造，子进程直接用它们在共享内存里的地址。
fn supercall_as(
    uid: u32,
    key: &CString,
    command: u64,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
) -> Result<(i32, i32), String> {
    // 管道：子进程写 8 字节（i32 ret + i32 errno），父进程读。
    let mut fds = [-1 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!(
            "创建管道出错: {}",
            std::io::Error::last_os_error()
        ));
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(format!("fork 出错: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        /* ================= 子进程：降权后调 supercall ================= */
        unsafe { libc::close(fds[0]) };

        let (ret, errno) = unsafe {
            if libc::setuid(uid) != 0 {
                let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                (RET_SETUID_FAILED, e)
            } else {
                let r = libc::syscall(
                    SUPERCALL_NR,
                    key.as_ptr(),
                    versioned_command(command),
                    a1,
                    a2,
                    a3,
                    a4,
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
        return Err(format!("子进程未回传结果（管道读到 {} 字节）", got));
    }

    let ret = i32::from_ne_bytes(buf[..4].try_into().unwrap());
    let errno = i32::from_ne_bytes(buf[4..].try_into().unwrap());

    if ret == RET_SETUID_FAILED {
        return Err(format!(
            "子进程无法降权到受信任管理器 uid({}): {}\n\
             该 uid 由管理器 APK 签名摘要决定；换过管理器（如 me.bmax.apatch → Aster/FolkPatch）后 uid 会变。\n\
             确认方式：pm list packages -U | grep -E '{}'",
            uid,
            describe_errno(errno),
            TRUSTED_MANAGER_PACKAGES.join("|")
        ));
    }

    Ok((ret, errno))
}

/// 用无副作用的 `SUPERCALL_KPM_NUMS` 探测当前身份能否通过授权门。
///
/// 这是区分 ENOENT 两种含义的唯一可靠手段：授权失败时 `before()` 提前 return，
/// 既不设 `skip_origin` 也不设 `ret`，原始 `truncate("su", …)` 真的执行并以 ENOENT
/// 失败；而模块不存在时才会走到 `module_control0()` 里返回 -ENOENT。两者 errno 相同。
///
/// 返回 `Ok(count)` 表示授权已通过（count 是已加载模块数，可以为 0）；
/// `Err(detail)` 表示授权未通过或途径异常。
fn probe_authorization(uid: u32) -> Result<i64, String> {
    let key = CString::new(SUPERCALL_KEY).map_err(|e| format!("key 无效: {}", e))?;

    let (ret, errno) = supercall_as(uid, &key, SUPERCALL_KPM_NUMS, 0, 0, 0, 0)?;
    if ret >= 0 {
        return Ok(ret as i64);
    }

    Err(format!(
        "探测 kpm_nums 也失败（errno={} {}）→ 说明 uid {} 没有通过授权门，\
         不是「模块不存在」",
        errno,
        describe_errno(errno),
        uid
    ))
}

fn control(module: &str, args: &str) -> Result<(), String> {
    let key =
        CString::new(SUPERCALL_KEY).map_err(|e| format!("KernelPatch key 无效: {}", e))?;
    let module = CString::new(module).map_err(|e| format!("KPM 名称无效: {}", e))?;
    let args_c = CString::new(args).map_err(|e| format!("KPM 参数无效: {}", e))?;

    let uid = trusted_manager_uid();

    // out_msg/outlen 交给模块写 ctl0 应答（karinahide 的 `list` 命令会用到）。
    // 必须在 fork 前分配：子进程直接用它在共享内存里的地址。
    let mut output = [0u8; 128];

    let (ret, errno) = supercall_as(
        uid,
        &key,
        SUPERCALL_KPM_CONTROL,
        module.as_ptr() as usize,
        args_c.as_ptr() as usize,
        output.as_mut_ptr() as usize,
        output.len(),
    )
    .map_err(|e| {
        format!(
            "KernelPatch ctl0 {} {} 失败: {}",
            module.to_string_lossy(),
            args_c.to_string_lossy(),
            e
        )
    })?;

    if ret == 0 {
        return Ok(());
    }

    // ENOENT 有歧义：授权被拒（原始 truncate 落空）与模块确实不存在无法从 errno 区分。
    // 用无副作用的 kpm_nums 探测一次，把结论写进报错，避免再去查错方向。
    let auth_note = if errno == libc::ENOENT {
        match probe_authorization(uid) {
            Ok(n) => format!(
                "\n授权正常（kpm_nums={}），所以 ENOENT 确实是内核里没有名为 \"{}\" 的模块：\
                 该 KPM 尚未加载，或名字写错",
                n,
                module.to_string_lossy()
            ),
            Err(detail) => format!("\n{}", detail),
        }
    } else {
        String::new()
    };

    Err(format!(
        "KernelPatch ctl0 {} {} 失败: syscall={}, errno={} (uid={}) ({}){}",
        module.to_string_lossy(),
        args_c.to_string_lossy(),
        ret,
        errno,
        uid,
        describe_errno(errno),
        auth_note
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
