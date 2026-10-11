//! 脚本级书签：id/名称登记、执行归属（当前脚本）、日志前缀。
//!
//! 这里**只做记账**，不碰 JS 引擎或 hook 注册表：
//! 真正的卸载（`hook_remove` / `qjs_free_value`）需要持有 JS 引擎锁，
//! 由 `crate::script_drop` 在 lib.rs 里完成。
//!
//! 归属模型（单 JS 上下文，非隔离）：
//! - 每个 `loadjs` 登记一个递增 id + 名称；
//! - 求值期间用 `enter_script(id)` 把 id 写入线程局部，console 输出据此加前缀；
//! - hook 记录里保存创建时的脚本 id，回调执行期间同样进入该脚本作用域，
//!   于是回调里的 `console.log` 也能归属到注册它的脚本。
//!
//! 因此 `jsdrop <id>` 的语义是「卸载该脚本注册的 hook + 释放其回调」，
//! 而不是「隔离的 JS 沙箱」：同一上下文里的全局对象仍然共享。

use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub(crate) struct ScriptRecord {
    pub(crate) id: u64,
    pub(crate) name: String,
    /// 登记时携带的脚本字节数（便于在 jslist 里区分同名脚本）。
    pub(crate) source_len: usize,
}

static SCRIPTS: Mutex<Option<HashMap<u64, ScriptRecord>>> = Mutex::new(None);
static NEXT_SCRIPT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// 当前线程正在执行的脚本 id。0 = 无归属（引擎内部/宿主命令）。
    static CURRENT_SCRIPT: Cell<u64> = const { Cell::new(0) };
}

/// 当前线程的脚本归属 id（0 = 无）。
pub(crate) fn current_script() -> u64 {
    CURRENT_SCRIPT.with(|c| c.get())
}

/// 直接设置当前线程归属（内部用；外部请用 `enter_script` 以免忘记恢复）。
pub(crate) fn set_current_script(id: u64) {
    CURRENT_SCRIPT.with(|c| c.set(id));
}

/// RAII 作用域：进入某个脚本的归属，离开时恢复先前值（支持嵌套）。
pub(crate) struct ScriptScope {
    previous: u64,
}

impl Drop for ScriptScope {
    fn drop(&mut self) {
        set_current_script(self.previous);
    }
}

/// 进入脚本作用域；`id == 0` 时退化为「清空归属」并在离开时恢复。
pub(crate) fn enter_script(id: u64) -> ScriptScope {
    let previous = current_script();
    set_current_script(id);
    ScriptScope { previous }
}

/// 登记一个新脚本，返回其 id。名称留空时用 `script#<id>` 占位。
pub(crate) fn register_script(name: &str, source_len: usize) -> u64 {
    let id = NEXT_SCRIPT_ID.fetch_add(1, Ordering::Relaxed);
    let name = if name.trim().is_empty() {
        format!("script#{}", id)
    } else {
        name.trim().to_string()
    };
    let mut guard = SCRIPTS.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .get_or_insert_with(HashMap::new)
        .insert(id, ScriptRecord { id, name, source_len });
    id
}

/// 查询脚本名称。
pub(crate) fn script_name(id: u64) -> Option<String> {
    let guard = SCRIPTS.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_ref()?.get(&id).map(|r| r.name.clone())
}

/// 列出已登记脚本（按 id 升序）。
pub(crate) fn list_scripts() -> Vec<ScriptRecord> {
    let guard = SCRIPTS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(map) = guard.as_ref() else {
        return Vec::new();
    };
    let mut out: Vec<ScriptRecord> = map.values().cloned().collect();
    out.sort_by_key(|r| r.id);
    out
}

/// 移除脚本登记项（hook 卸载由调用方完成）。
pub(crate) fn forget_script(id: u64) -> Option<ScriptRecord> {
    let mut guard = SCRIPTS.lock().unwrap_or_else(|e| e.into_inner());
    guard.as_mut()?.remove(&id)
}

/// 日志前缀：`[script#3 app.js] `；无归属时为空串。
///
/// 供 agent 的 console 回调使用，使多脚本场景下输出可归属。
pub fn script_log_prefix() -> String {
    let id = current_script();
    if id == 0 {
        return String::new();
    }
    match script_name(id) {
        Some(name) => format!("[script#{} {}] ", id, name),
        None => format!("[script#{}] ", id),
    }
}
