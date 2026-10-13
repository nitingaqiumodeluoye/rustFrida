//! Hook registry: StealthMode, HookData, HOOK_REGISTRY, error constants

use crate::jsapi::callback_util::ensure_registry_initialized;
use std::collections::HashMap;
use std::sync::Mutex;

// Error codes from hook_engine.h
pub(crate) const HOOK_OK: i32 = 0;
const HOOK_ERROR_NOT_INITIALIZED: i32 = -1;
const HOOK_ERROR_INVALID_PARAM: i32 = -2;
const HOOK_ERROR_ALREADY_HOOKED: i32 = -3;
const HOOK_ERROR_ALLOC_FAILED: i32 = -4;
const HOOK_ERROR_MPROTECT_FAILED: i32 = -5;
const HOOK_ERROR_NOT_FOUND: i32 = -6;
const HOOK_ERROR_BUFFER_TOO_SMALL: i32 = -7;
const HOOK_ERROR_WXSHADOW_FAILED: i32 = -8;

/// Convert hook error code to error message
pub(crate) fn hook_error_message(code: i32) -> &'static [u8] {
    match code {
        HOOK_ERROR_NOT_INITIALIZED => b"hook engine not initialized\0",
        HOOK_ERROR_INVALID_PARAM => b"invalid parameter\0",
        HOOK_ERROR_ALREADY_HOOKED => b"address already hooked\0",
        HOOK_ERROR_ALLOC_FAILED => b"memory allocation failed\0",
        HOOK_ERROR_MPROTECT_FAILED => b"mprotect failed: cannot change memory protection\0",
        HOOK_ERROR_NOT_FOUND => b"hook not found at address\0",
        HOOK_ERROR_BUFFER_TOO_SMALL => b"buffer too small for jump instruction\0",
        HOOK_ERROR_WXSHADOW_FAILED => b"wxshadow prctl failed: kernel may not support shadow pages\0",
        _ => b"unknown hook error\0",
    }
}

/// Hook stealth 模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealthMode {
    /// 普通 inline hook（直接 patch 原始代码）
    Normal = 0,
    /// wxshadow stealth（内核 shadow page patch）
    WxShadow = 1,
    /// recomp stealth（页级重编译，在重编译页上 hook）
    Recomp = 2,
}

/// JS 常量值
pub(crate) const STEALTH_NORMAL: i32 = StealthMode::Normal as i32;
pub(crate) const STEALTH_WXSHADOW: i32 = StealthMode::WxShadow as i32;
pub(crate) const STEALTH_RECOMP: i32 = StealthMode::Recomp as i32;

/// 参数省略时使用的默认 stealth 模式：无痕（wxshadow）。
///
/// 为什么默认 WxShadow：它走内核 shadow 页，原始页字节一个都不改，
/// `/proc/self/mem` 读回原字节、CRC 校验也过；Recomp 要多占重编译页
/// 并依赖 ART 页翻译，Normal 则直接改原始字节（CRC / maps 扫描可见）。
///
/// 装不上时**不降级**：C 层 `patch_target` 在 stealth==1 失败时直接返回
/// `HOOK_ERROR_WXSHADOW_FAILED`，明确拒绝退回 mprotect（降级会改原始字节并把页
/// 改成 RWX，CRC / /proc/self/maps 都能发现）。调用方须把这个错误如实抛给脚本，
/// 不要静默继续。
///
/// 需要旧行为（普通 inline hook）时显式传 `0` / `false` / `Hook.NORMAL`。
pub(crate) const DEFAULT_STEALTH_MODE: StealthMode = StealthMode::WxShadow;

impl StealthMode {
    /// 从 JS 参数解析 stealth 模式
    /// - 0 / false / omitted → Normal
    /// - 1 / true → WxShadow
    /// - 2 → Recomp
    pub(crate) fn from_js_arg(val: i64) -> Self {
        match val {
            1 => StealthMode::WxShadow,
            2 => StealthMode::Recomp,
            _ => StealthMode::Normal,
        }
    }
}

/// Hook 安装种类: Replace 单阶段（hook_replace） or Attach 双阶段（hook_attach）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookKind {
    /// hook_replace: 完全替换，thunk 只在进入时调 on_enter；callOriginal 靠 ctx.$orig() 显式触发
    Replace,
    /// hook_attach: Frida-style，thunk 自动 BLR 原函数；on_enter 观察/改参数，on_leave 观察/改返回值
    Attach,
}

/// Stored hook callback data - stores raw bytes to avoid Send/Sync issues
#[derive(Clone, Copy)]
pub(crate) struct HookData {
    pub(crate) ctx: usize,                // Store as usize to avoid Send/Sync issues
    pub(crate) callback_bytes: [u8; 16],  // on_enter / replace callback (JSValue 16 字节)
    pub(crate) on_leave_bytes: [u8; 16],  // on_leave (attach 模式) — has_on_leave=false 时全 0
    pub(crate) has_on_enter: bool,        // attach 模式下 onEnter 可缺省
    pub(crate) has_on_leave: bool,        // attach 模式下 onLeave 可缺省
    pub(crate) trampoline: u64,           // Trampoline address for callOriginal (replace mode)
    pub(crate) kind: HookKind,            // Replace or Attach
    pub(crate) mode: StealthMode,         // hook 模式（unhook 时需要）
    pub(crate) recomp_addr: u64,          // Recomp 模式下的重编译地址
    pub(crate) native_attach_data: usize, // attachNative callback storage (Box<NativeAttachCallbacks>)
    pub(crate) mutation: bool,            // 修改型 hook（onEnter 会改入参）: engine-busy 时自旋等待 300ms 绝不丢弃; 观察型(默认 false)自旋 10ms 耗尽即丢
    /// 创建该 hook 的脚本 id（0 = 非脚本来源）。
    /// 用于日志归属（回调里的 console 输出）与 `jsdrop <id>` 按脚本卸载。
    pub(crate) owner_script: u64,
}

// SAFETY: HookData only contains Copy types now (usize, [u8; 16])
// The actual pointer usage is only done within unsafe blocks on the JS thread
unsafe impl Send for HookData {}
unsafe impl Sync for HookData {}

/// Global hook registry
pub(crate) static HOOK_REGISTRY: Mutex<Option<HashMap<u64, HookData>>> = Mutex::new(None);

/// 取出某脚本注册的全部 native hook（从注册表里删除并返回）。
///
/// 真正的 `hook_remove` / `qjs_free_value` 由 `crate::script_drop` 在持有
/// JS 引擎锁时执行，这里只负责摘表，避免持锁顺序问题。
pub(crate) fn take_hooks_owned_by(script_id: u64) -> Vec<(u64, HookData)> {
    if script_id == 0 {
        return Vec::new();
    }
    let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let Some(registry) = guard.as_mut() else {
        return Vec::new();
    };
    let owned: Vec<u64> = registry
        .iter()
        .filter(|(_, data)| data.owner_script == script_id)
        .map(|(addr, _)| *addr)
        .collect();
    owned
        .into_iter()
        .filter_map(|addr| registry.remove(&addr).map(|data| (addr, data)))
        .collect()
}

/// 查询某个 target 地址上 hook 的归属脚本 id（0 = 无/未知）。
///
/// hook 回调进入时据此切到对应脚本作用域，使回调里的 console 输出可归属。
pub(crate) fn owner_script_of(target: u64) -> u64 {
    let guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .and_then(|registry| registry.get(&target))
        .map(|data| data.owner_script)
        .unwrap_or(0)
}

/// 统计某脚本当前持有的 native hook 数量。
pub(crate) fn count_hooks_owned_by(script_id: u64) -> usize {
    if script_id == 0 {
        return 0;
    }
    let guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(|registry| {
            registry
                .values()
                .filter(|data| data.owner_script == script_id)
                .count()
        })
        .unwrap_or(0)
}

/// Initialize hook registry
pub(crate) fn init_registry() {
    ensure_registry_initialized(&HOOK_REGISTRY);
}
