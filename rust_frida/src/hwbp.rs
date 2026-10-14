//! hwbp — ARM64 写观察点(rustFrida 侧)。
//!
//! 内核侧模块见 `mykpm/kpms/hwbp/`,结构体定义必须与 `hwbp.h` 逐字段对应;
//! 改一边必须同步改另一边,否则命中的数据会被按错误偏移解释。
//!
//! ## 取数通道
//!
//! 内核 ctl0 的 `out_msg` 是「调用方给的用户缓冲」,长度由 `outlen` 指定,
//! KernelPatch 侧不做限制。但 `supercall_as` 会 fork 一个子进程降权去执行 ——
//! 普通栈缓冲 fork 后是**私有 COW 页**,内核写进去的内容父进程看不到。
//!
//! 所以这里用 `MAP_SHARED | MAP_ANONYMOUS` 页承载:`control_shared` 负责映射、
//! 在 mmap 后立刻整块写一遍(既清零也保证页驻留),然后把地址交给子进程。
//! 父子共享同一物理页,子进程里内核写入的内容父进程能直接读到。
//!
//! 「必须驻留」是内核侧的硬约束:`module_control0()` 全程持 `rcu_read_lock()`
//! (KernelPatch 的 `patch/module/module.c:618`),RCU 读侧临界区不能睡眠,
//! 而用户页缺页处理会睡 —— `compat_copy_to_user` 只能命中已驻留的页。

use crate::kpm;

/// 命中环容量,对应 `hwbp.h` 的 `HWBP_HITS_MAX`。
pub(crate) const HITS_MAX: usize = 32;
/// 每条命中保存的寄存器个数(x0-x7),对应 `HWBP_HIT_REG_WORDS`。
pub(crate) const HIT_REG_WORDS: usize = 8;

/// 内核模块名,对应 `KPM_NAME("hwbp")`。
const MODULE: &str = "hwbp";

/// 一次写命中。与 C 侧 `struct hwbp_hit` 逐字段对应。
///
/// 只含 trap 上下文里零风险可得的字段 —— 全部来自 `pt_regs`。刻意不含 value /
/// 栈快照:那需要在 debug exception 里解引用用户内存,异常态缺页会睡眠 → 内核
/// panic。需要值时在 `hits()` 返回后自己读(那时已不在异常上下文)。
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub(crate) struct HwbpHit {
    /// 触发 trap 的那条 store 指令地址
    pub pc: u64,
    /// x30(trap 时的链接寄存器)
    pub lr: u64,
    /// trap 时的栈指针
    pub sp: u64,
    /// 被观察的地址
    pub addr: u64,
    /// x0-x7
    pub x: [u64; HIT_REG_WORDS],
}

/// `hits` 的应答。与 C 侧 `struct hwbp_hits` 逐字段对应。
///
/// 注意 C 侧结构体的前 16 字节(`watch_addr`/`tid`/`node_index`)在命令里走字符串,
/// 内核只把它们回填进输出结构;这里保留同样的布局以维持 `repr(C)` 对齐一致。
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct HwbpHits {
    /// 回显:被查询的地址
    pub watch_addr: u64,
    /// 回显:tid 筛选值(0 = 不限)
    pub tid: u32,
    /// 回显:节点序号
    pub node_index: u32,

    /// 该地址匹配到的节点总数
    pub node_total: u32,
    /// `entries` 的有效条数
    pub count: u32,
    /// 该节点的累计命中数(可能大于 `count`,环会被回绕覆盖)
    pub total: u32,
    /// 同 `total`,取自节点计数器
    pub hit_count: u32,
    /// 观察宽度
    pub bp_len: u32,
    /// 0 = 已被 `max_hits` 自动关掉
    pub is_armed: u32,
    /// 环游标
    pub ring_head: u32,
    /// 自动关闭阈值
    pub max_hits: u32,
    pub _pad: u32,

    /// 命中环,按「最旧 -> 最新」排列
    pub entries: [HwbpHit; HITS_MAX],
}

impl Default for HwbpHits {
    fn default() -> Self {
        // 显式零初始化:数组长度 32 正好踩在 derive(Default) 的数组实现边界上,
        // 手写更稳。
        unsafe { core::mem::zeroed() }
    }
}

/// 观察宽度。地址必须按宽度对齐(arm64 `arch_build_bp_info()` 强制)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BpLen {
    Len1,
    Len2,
    Len4,
    Len8,
}

impl BpLen {
    pub(crate) fn bytes(self) -> u32 {
        match self {
            BpLen::Len1 => 1,
            BpLen::Len2 => 2,
            BpLen::Len4 => 4,
            BpLen::Len8 => 8,
        }
    }
}

/// 在指定线程上注册一个写观察点。
///
/// `addr` 必须按 `len` 对齐(arm64 强制,不对齐内核返回 `EINVAL`)。`max_hits`
/// 传 0 用缺省值(`DEF_MAX_HITS`);到量后**内核侧**自动关掉该观察点,不等用户态。
///
/// 注意这是**按线程**的:观察点寄存器是 per-thread 资源(每线程只有 4 个),
/// 覆盖整个进程需要调用方遍历 `/proc/<pid>/task` 逐个 TID 下发。
pub(crate) fn watch(addr: u64, tid: u32, len: BpLen, max_hits: u32) -> Result<(), String> {
    if addr == 0 {
        return Err("hwbp::watch: 地址为 0".to_string());
    }
    if addr & (len.bytes() as u64 - 1) != 0 {
        return Err(format!(
            "hwbp::watch: 地址 0x{:x} 未按宽度 {} 对齐(arm64 硬件观察点强制要求)",
            addr,
            len.bytes()
        ));
    }
    kpm::control(MODULE, &format!("watch 0x{:x} {} {} {}", addr, tid, len.bytes(), max_hits))
}

/// 卸掉观察点。`tid` 传 0 表示卸掉该地址上的全部线程。
pub(crate) fn unwatch(addr: u64, tid: u32) -> Result<(), String> {
    if addr == 0 {
        return Err("hwbp::unwatch: 地址为 0(要卸全部请用 clear)".to_string());
    }
    kpm::control(MODULE, &format!("unwatch 0x{:x} {}", addr, tid))
}

/// 卸掉全部观察点。
#[allow(dead_code)] // 供后续 JS API / REPL 命令复用
pub(crate) fn clear() -> Result<(), String> {
    kpm::control(MODULE, "clear")
}

/// 读某个观察点的命中环。
///
/// `tid` 传 0 表示不筛线程(取第一个匹配),`node_index` 用于同一 (addr, tid) 上
/// 存在多个节点时逐个取。
///
/// `node_total == 0` 表示该地址上没有任何观察点,直接报错 —— 区别于「有观察点
/// 但还没命中」(那种情况返回 `Ok`,里面 `count == 0`)。
pub(crate) fn hits(addr: u64, tid: u32, node_index: u32) -> Result<HwbpHits, String> {
    if addr == 0 {
        return Err("hwbp::hits: 地址为 0".to_string());
    }

    let size = core::mem::size_of::<HwbpHits>();
    let raw = kpm::control_shared(
        MODULE,
        &format!("hits 0x{:x} {} {}", addr, tid, node_index),
        size,
    )?;

    if raw.len() < size {
        return Err(format!(
            "hwbp::hits: 内核只回了 {} 字节,期望 {}",
            raw.len(),
            size
        ));
    }

    // 共享页内容按 repr(C) 结构体解释。read_unaligned:共享页只保证页对齐。
    //
    // 注意 entries[count..] 是共享页里的历史残留(内核只写实际命中过的条目),
    // 所以下面一定按 count 截断 —— `effective_hits` 负责这件事,调用方不要直接
    // 遍历 entries。
    let parsed = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const HwbpHits) };

    if parsed.node_total == 0 {
        return Err(format!(
            "hwbp::hits: 0x{:x} 上没有观察点(tid 筛选 = {})",
            addr, tid
        ));
    }
    Ok(parsed)
}

/// 命中环里的有效条目。
pub(crate) fn effective_hits(h: &HwbpHits) -> &[HwbpHit] {
    let n = (h.count as usize).min(HITS_MAX);
    &h.entries[..n]
}

/// 列出当前全部观察点,返回内核的原始状态串。
///
/// 形如 `hwbp ready v1.0.0 nodes=2 7f1234000:1234:5 ...`(每项 `地址:tid:命中数`)。
#[allow(dead_code)] // 供后续 JS API / REPL 命令复用
pub(crate) fn list() -> Result<String, String> {
    let raw = kpm::control_shared(MODULE, "list", 512)?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
}

/// 模块是否已加载且能应答(用 `list` 探活)。
pub(crate) fn probe() -> Result<String, String> {
    list()
}