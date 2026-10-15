//! quickjs-hook - QuickJS JavaScript engine with inline hook support for ARM64 Android
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

mod completion;
pub mod context;
pub mod fast_hook;
pub mod ffi;
pub mod jsapi;
mod raw_thread;
pub mod recomp;
pub mod runtime;
mod script_registry;
pub mod value;

pub use completion::complete_script;
pub use context::JSContext;
pub use jsapi::console::{set_console_callback, set_verbose};
pub use jsapi::deferred_java_init;
pub use jsapi::hook_api::cleanup_hooks;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::shutdown_qbdi_helper;
pub use jsapi::hook_api::{cut_native_hooks, free_native_hooks};
pub use jsapi::java::abort_raw_clone_java_executor_for_unload;
pub use jsapi::java::art_controller::{
    cut_art_controller_hooks, cut_art_controller_routing_hooks, cut_art_controller_walkstack_guards,
    free_art_controller_state, set_art_controller_reload_paused,
};
pub use jsapi::java::cleanup_java_hooks;
pub use jsapi::java::detach_current_jni_thread;
pub use jsapi::java::finish_java_worker_thread_from_native;
pub use jsapi::java::java_subsystem_active_for_cleanup;
pub use jsapi::java::raw_clone_java_executor_hook_active;
pub use jsapi::java::start_java_worker_thread;
pub use jsapi::java::{cut_java_hooks, drain_thunk_in_flight, free_java_hooks};
pub use jsapi::memory::cleanup_wxshadow_patches;
pub use runtime::JSRuntime;
pub use script_registry::script_log_prefix;
pub use value::JSValue;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS: u64 = 6_500;
/// hook / java hook **回调**的单次执行上限。`0` = 不限制。
///
/// 背景:回调走 `JS_Call` 而不经过顶层 eval 的 deadline 防护。历史上这里
/// 用的是与顶层执行相同的 6.5s 预算,目的是让脚本里的 `while (true) {}`
/// 不会把宿主线程永久挂死。
///
/// 现在默认**不设限**(`0`)。原因:拦截窗口内的 onEnter 常常要做远超 6.5s 的
/// 工作(枚举符号表 / 建立 Stalker / 同步落盘),超时被 QuickJS interrupt
/// 中断后 `sync_js_ctx_to_hook_ctx` 与 `intercept_leave` 会被跳过,回调跑到
/// 一半静默失效 —— 比不设限更难排查。
///
/// 代价:回调里写死循环会挂住宿主线程(`console.log` 也不再执行,`jsclean`
/// 拿不到引擎锁,只能杀进程)。需要恢复旧行为时把下面这行改成
/// `JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS`,或用 `set_hook_callback_timeout_ms()`
/// 在运行时调大。
const JS_HOOK_CALLBACK_TIMEOUT_MS_DEFAULT: u64 = 0;
/// 可运行时覆盖的回调预算(毫秒,`0` = 不限制)。默认取
/// `JS_HOOK_CALLBACK_TIMEOUT_MS_DEFAULT`,host 可用
/// `set_hook_callback_timeout_ms()` 调整。
static JS_HOOK_CALLBACK_TIMEOUT_MS: AtomicU64 = AtomicU64::new(JS_HOOK_CALLBACK_TIMEOUT_MS_DEFAULT);

static QBDI_OUTPUT_DIR: OnceLock<String> = OnceLock::new();
static QBDI_HELPER_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static JS_EXECUTION_DEADLINE_MS: AtomicU64 = AtomicU64::new(0);

pub fn set_qbdi_output_dir(output_dir: impl Into<String>) {
    let _ = QBDI_OUTPUT_DIR.set(output_dir.into());
}

pub fn set_qbdi_helper_blob(blob: Vec<u8>) {
    *QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(blob);
}

pub(crate) fn qbdi_output_dir() -> Option<&'static str> {
    QBDI_OUTPUT_DIR.get().map(|s| s.as_str())
}

pub(crate) fn qbdi_helper_blob() -> Option<Vec<u8>> {
    QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Global JS engine instance (protected by Mutex).
/// pub(crate) so hook_callback_wrapper can serialize concurrent JS_Call invocations.
pub(crate) static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);
/// Best-effort owner tracking for the thread currently executing inside the global JS engine.
/// Used by hook callbacks to distinguish same-thread reentrancy from ordinary contention.
pub(crate) static JS_ENGINE_OWNER_THREAD: AtomicU64 = AtomicU64::new(0);

static RAW_CLONE_JS_THREAD_0: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_1: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_2: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_3: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_4: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_5: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_6: AtomicU64 = AtomicU64::new(0);
static RAW_CLONE_JS_THREAD_7: AtomicU64 = AtomicU64::new(0);

fn raw_clone_js_thread_slots() -> [&'static AtomicU64; 8] {
    [
        &RAW_CLONE_JS_THREAD_0,
        &RAW_CLONE_JS_THREAD_1,
        &RAW_CLONE_JS_THREAD_2,
        &RAW_CLONE_JS_THREAD_3,
        &RAW_CLONE_JS_THREAD_4,
        &RAW_CLONE_JS_THREAD_5,
        &RAW_CLONE_JS_THREAD_6,
        &RAW_CLONE_JS_THREAD_7,
    ]
}

pub struct RawCloneJsThreadGuard {
    id: u64,
}

impl Drop for RawCloneJsThreadGuard {
    fn drop(&mut self) {
        for slot in raw_clone_js_thread_slots() {
            if slot.load(Ordering::Acquire) == self.id {
                let _ = slot.compare_exchange(self.id, 0, Ordering::AcqRel, Ordering::Acquire);
                break;
            }
        }
    }
}

pub fn mark_raw_clone_js_thread() -> RawCloneJsThreadGuard {
    let id = current_thread_id_u64();
    for slot in raw_clone_js_thread_slots() {
        if slot.load(Ordering::Acquire) == id
            || slot
                .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return RawCloneJsThreadGuard { id };
        }
    }
    RawCloneJsThreadGuard { id }
}

pub(crate) fn is_raw_clone_js_thread() -> bool {
    let id = current_thread_id_u64();
    raw_clone_js_thread_slots()
        .iter()
        .any(|slot| slot.load(Ordering::Acquire) == id)
}

#[inline]
pub(crate) fn current_thread_id_u64() -> u64 {
    // Must use TPIDR_EL0 directly — on API 36, pthread_self() != TPIDR_EL0.
    // The thunk bypass uses MRS TPIDR_EL0 for thread matching.
    let tpidr: u64;
    unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr) };
    tpidr
}

#[inline]
pub(crate) fn mark_js_engine_owner_current_thread() {
    JS_ENGINE_OWNER_THREAD.store(current_thread_id_u64(), Ordering::Release);
}

#[inline]
pub(crate) fn clear_js_engine_owner_current_thread() {
    let current = current_thread_id_u64();
    let _ = JS_ENGINE_OWNER_THREAD.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Relaxed);
}

struct JsEngineOwnerGuard;

impl JsEngineOwnerGuard {
    fn acquire() -> Self {
        mark_js_engine_owner_current_thread();
        JsEngineOwnerGuard
    }
}

impl Drop for JsEngineOwnerGuard {
    fn drop(&mut self) {
        clear_js_engine_owner_current_thread();
    }
}

struct JsExecutionDeadlineGuard {
    previous_deadline_ms: u64,
}

impl JsExecutionDeadlineGuard {
    /// 设置本次 JS 执行的截止时间（毫秒）。
    ///
    /// 嵌套时取**更早**的截止，而不是直接覆盖：
    /// - 已有外层截止时，内层不会把它延后（否则内层会削弱外层的保护）；
    /// - `timeout_ms == 0`（不限制）时保留外层截止，不会把保护关掉。
    fn begin(timeout_ms: u64) -> Self {
        let previous_deadline_ms = JS_EXECUTION_DEADLINE_MS.load(Ordering::Acquire);
        let deadline_ms = if timeout_ms == 0 {
            previous_deadline_ms
        } else {
            let requested = monotonic_ms().saturating_add(timeout_ms);
            if previous_deadline_ms == 0 {
                requested
            } else {
                requested.min(previous_deadline_ms)
            }
        };
        JS_EXECUTION_DEADLINE_MS.store(deadline_ms, Ordering::Release);
        Self { previous_deadline_ms }
    }
}

/// 供回调路径使用：给当前 JS 调用套上执行截止时间。
pub(crate) fn begin_js_execution_deadline(timeout_ms: u64) -> impl Drop {
    JsExecutionDeadlineGuard::begin(timeout_ms)
}

/// hook / java hook 回调的执行上限（毫秒）。
pub(crate) fn hook_callback_timeout_ms() -> u64 {
    JS_HOOK_CALLBACK_TIMEOUT_MS.load(Ordering::Acquire)
}

/// 设置 hook / java hook 回调的单次执行上限(毫秒)。
///
/// `0` = 不限制(默认)。传非 0 值可恢复「回调超时即中断」的保护。
/// 只影响之后的回调,已在执行中的回调不受影响。
pub fn set_hook_callback_timeout_ms(timeout_ms: u64) {
    JS_HOOK_CALLBACK_TIMEOUT_MS.store(timeout_ms, Ordering::Release);
}

impl Drop for JsExecutionDeadlineGuard {
    fn drop(&mut self) {
        JS_EXECUTION_DEADLINE_MS.store(self.previous_deadline_ms, Ordering::Release);
    }
}

fn monotonic_ms() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000)
        .saturating_add((ts.tv_nsec as u64) / 1_000_000)
}

pub(crate) fn js_execution_deadline_expired() -> bool {
    let deadline_ms = JS_EXECUTION_DEADLINE_MS.load(Ordering::Acquire);
    deadline_ms != 0 && monotonic_ms() >= deadline_ms
}

/// Log callback registered with the C hook engine.
/// Routes hook_engine diagnostic messages through the JS console callback
/// so they appear in the REPL output alongside normal [JS] messages.
unsafe extern "C" fn hook_engine_log_impl(msg: *const std::os::raw::c_char) {
    if msg.is_null() {
        return;
    }
    let s = std::ffi::CStr::from_ptr(msg).to_string_lossy();
    let formatted = format!("[hook_engine] {}", s);
    // 错误/警告永远输出（失败类消息对排错重要），其余全部 verbose 静默
    // 识别关键字: FAILED/failed/失败/ERROR/WARN/\033[31m 红/\033[33m 黄
    let is_error = s.contains("FAILED")
        || s.contains("failed")
        || s.contains("失败")
        || s.contains("ERROR")
        || s.contains("WARN")
        || s.contains("\x1b[31m")
        || s.contains("\x1b[33m");
    if is_error {
        crate::jsapi::console::output_message(&formatted);
    } else {
        crate::jsapi::console::output_verbose(&formatted);
    }
}

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe { ffi::hook::hook_engine_init(exec_mem as *mut _, size) };

    if result == 0 {
        // Register log callback so wxshadow/prctl diagnostics appear in REPL
        unsafe { ffi::hook::hook_engine_set_log_fn(Some(hook_engine_log_impl)) };
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Cleanup the hook engine
///
/// 对标 Frida: 只 reset 内部状态, 不 munmap 扩展 pool (见 hook_engine.c 注释).
/// 线程若还在 thunk 里执行, 代码页保留直到进程退出, 避免 SIGSEGV。
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// High-level JS engine wrapper
/// Note: Field order matters for drop order - context must be dropped before runtime
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// Create a new JS engine with all APIs registered
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // Register all JavaScript APIs
        jsapi::register_all_apis(&context);

        // 预缓存 hook callback 热路径用到的 atom（x0..x30 / sp / pc / lr / returnAddress /
        // trampoline / __hookCtxPtr / __hookTrampoline），消除每次回调的 CString+JS_NewAtom 开销。
        unsafe {
            jsapi::callback_util::init_hot_atoms(context.as_ptr());
        }

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// Evaluate a script with a specific filename
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// Execute pending jobs (for promises)
    pub fn run_pending_jobs(&self) {
        while self.context.execute_pending_job() {}
    }

    /// Run callbacks queued by Java.perform() after the current top-level script
    /// has finished, so callbacks can reference helpers declared later in the
    /// same loadjs payload.
    ///
    /// 分片语义：每次调用只执行下一个 ready 回调（Java._flushStep），
    /// 返回 "more"（还有剩余）或 "done"。Rust 侧在分片之间释放锁。
    pub fn flush_java_ready_step(&self) -> Result<String, String> {
        if is_raw_clone_js_thread() {
            return Ok("done".to_string());
        }
        let value = self.context.eval(
            "if (globalThis.Java && typeof Java._flushStep === 'function') Java._flushStep(); else 'done';",
            "<java_ready_flush_step>",
        )?;
        let status = value.to_string(self.context.as_ptr()).unwrap_or_else(|| "done".into());
        value.free(self.context.as_ptr());
        Ok(status)
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // 外部编排器 (agent::quickjs_loader::cleanup) 在调用 cleanup_engine 之前
        // 已按 cut → drain → free 完成所有 hook 清理。此处不再重复调用 cleanup_java_hooks
        // / cleanup_hooks — 否则 drain 会再跑一次 30s 上限（hook registry 已空，
        // 但 g_thunk_in_flight 可能仍 > 0，纯粹浪费时间）。
        //
        // 若 JSEngine 被独立 drop（非经 orchestrator），调用方负责先 cut/drain/free。
        //
        // Drop 顺序（字段声明顺序）：先 context（这里访问仍有效）→ 再 runtime。
        // 在 context drop 前释放热路径 atom，让 JS_FreeAtom 有合法上下文。
        unsafe {
            jsapi::callback_util::free_hot_atoms(self.context.as_ptr());
        }
    }
}

// Safety: JSEngine is protected by Mutex, ensuring single-threaded access
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// Load and execute a JavaScript script using the global engine.
/// Returns the string representation of the result, or an empty string for `undefined`.
///
/// 等价于 `load_script_with_filename(script, "<eval>")`。
pub fn load_script(script: &str) -> Result<String, String> {
    load_script_with_filename(script, "<eval>")
}

/// Load + execute with an explicit filename (用于 QuickJS 报错时显示 `filename:line:col`)。
pub fn load_script_with_filename(script: &str, filename: &str) -> Result<String, String> {
    load_script_with_filename_inner(script, filename, true)
}

/// Execute a short internal script without implicitly flushing Java.perform().
///
/// Java-perform bootstrap uses this so every probe performs exactly one JNI
/// reprobe. The eventual callback flush is submitted as a separate worker task.
pub fn load_script_with_filename_without_ready_flush(script: &str, filename: &str) -> Result<String, String> {
    load_script_with_filename_inner(script, filename, false)
}

fn load_script_with_filename_inner(script: &str, filename: &str, flush_java_ready: bool) -> Result<String, String> {
    // Span 1: eval + 结果转字符串（拿锁）—— 毕即放锁。
    let result = {
        let mut engine = JS_ENGINE
            .lock()
            .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
        if engine.is_none() {
            *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
        }
        let engine = engine.as_ref().ok_or("JS engine not initialized")?;
        let _owner_guard = JsEngineOwnerGuard::acquire();
        let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);
        let value = engine.eval_file(script, filename)?;
        let result = if value.is_undefined() {
            "undefined".to_string()
        } else {
            value.to_string(engine.context().as_ptr()).unwrap_or_default()
        };
        value.free(engine.context().as_ptr());
        result
    };

    // Span 2: 分片 flush Java.perform 回调 —— 每分片独立拿锁,分片间放锁,
    // 让 app 线程排队的 hook 事件有机会插队（缩短临界区）。
    if flush_java_ready {
        flush_java_ready_chunked()?;
    } else {
        // 保持原语义：无 flush 路径也要泵一次 pending jobs（独立短锁）。
        {
            let engine = JS_ENGINE
                .lock()
                .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
            if let Some(engine) = engine.as_ref() {
                let _owner_guard = JsEngineOwnerGuard::acquire();
                engine.run_pending_jobs();
            }
        }
    }
    Ok(result)
}

/// 分片 flush Java.perform 回调。
///
/// 每个 chunk = 一次拿锁只跑【一个】 ready 回调 + 它的 pending jobs，分片间真正释放
/// JS_ENGINE 锁。原先一次性跑完所有回调（含用户脚本里的 Java.perform 主体，
/// boot 期可达秒级）是 hook 引擎 busy 自旋耗尽的头号元凶；分片后 app 线程的
/// hook 事件可在分片间隙同步执行，大幅减少 engine-busy 丢弃。
pub fn flush_java_ready_chunked() -> Result<(), String> {
    const MAX_CHUNKS: usize = 128;
    for _ in 0..MAX_CHUNKS {
        let status = {
            let engine = JS_ENGINE
                .lock()
                .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
            let engine = engine.as_ref().ok_or("JS engine not initialized")?;
            let _owner_guard = JsEngineOwnerGuard::acquire();
            let s = engine.flush_java_ready_step()?;
            engine.run_pending_jobs();
            s
        };
        if status != "more" {
            break;
        }
    }
    Ok(())
}

/// 将任意字符串编码成 JS 字符串字面量（带双引号），可直接拼入 JS 源码。
fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 调用 `rpc.exports[method]` 并返回 JSON 字符串化后的结果。
///
/// 使用全局 JS 引擎锁，与 REPL eval 互斥。HTTP RPC 调用应在外层用 Mutex 串行化，
/// 防止多个并发请求竞争同一把 JS 引擎锁。
///
/// # 参数
/// * `method` - 注册在 `rpc.exports` 上的方法名
/// * `args_json` - JSON array 字符串（如 `"[1, 2, 3]"`），空字符串等价于 `"[]"`
///
/// # 返回
/// * `Ok(json)` - 返回值的 JSON 字符串表示；`undefined` 返回 `"null"`
/// * `Err(msg)` - 引擎未初始化 / 方法不存在 / JS 异常
pub fn dispatch_rpc(method: &str, args_json: &str) -> Result<String, String> {
    let engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let _deadline_guard = JsExecutionDeadlineGuard::begin(JS_TOP_LEVEL_EXECUTION_TIMEOUT_MS);

    // 构造 `__rpc_dispatch("method", "args_json")` 表达式。
    let script = format!(
        "__rpc_dispatch({}, {})",
        js_string_literal(method),
        js_string_literal(args_json),
    );

    let value = engine.eval(&script)?;
    engine.run_pending_jobs();
    let result = value
        .to_string(engine.context().as_ptr())
        .unwrap_or_else(|| "null".to_string());
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// Cleanup the global JS engine
pub fn cleanup_engine() {
    if let Ok(mut engine) = JS_ENGINE.lock() {
        *engine = None;
    }
}

// ────────────────────────── 脚本级生命周期 ──────────────────────────

/// 登记一个新脚本，返回其 id。id 单调递增，0 保留为「无归属」。
pub fn script_register(name: &str, source_len: usize) -> u64 {
    script_registry::register_script(name, source_len)
}

/// 进入某个脚本的归属作用域（求值期间与 hook 回调期间使用）。
pub fn script_scope(id: u64) -> impl Drop {
    script_registry::enter_script(id)
}

/// 列出已登记脚本：`(id, 名称, native hook 数, java hook 数, 源字节数)`。
pub fn script_list() -> Vec<(u64, String, usize, usize, usize)> {
    script_registry::list_scripts()
        .into_iter()
        .map(|record| {
            let native = jsapi::hook_api::registry::count_hooks_owned_by(record.id);
            let java = jsapi::java::callback::count_java_hooks_owned_by(record.id);
            (record.id, record.name, native, java, record.source_len)
        })
        .collect()
}

/// 卸载某个脚本：移除其注册的全部 hook（native + java）并释放回调。
///
/// 与 `dispatch_rpc` 一致，这里自行获取全局 JS 引擎锁并**持锁到大功告成**：
/// 释放回调要访问 JSContext，且必须与任何求值互斥。若其它线程正持有引擎锁
/// （如 hook 回调中），这里会等待它结束（回调有 6.5s deadline 兜底）。
///
/// 注意：不清理该脚本写入全局对象的属性（单上下文共享），
/// 因此无法重新加载同名脚本后得到干净环境。
#[allow(unsafe_code)]
pub fn script_drop(id: u64) -> Result<(usize, usize), String> {
    if id == 0 {
        return Err("script_drop: 无效脚本 id 0".to_string());
    }
    if script_registry::script_name(id).is_none() {
        return Err(format!("script_drop: 脚本 #{} 不存在（已卸载？）", id));
    }

    let engine_guard = JS_ENGINE.lock().map_err(|_| "script_drop: JS 引擎锁中毒".to_string())?;
    if engine_guard.is_none() {
        return Err("script_drop: JS 引擎未初始化".to_string());
    }

    // native hooks：抹掉 hook 字节 + 释放 JS 回调
    let native_hooks = jsapi::hook_api::registry::take_hooks_owned_by(id);
    let native_count = native_hooks.len();
    for (addr, data) in &native_hooks {
        unsafe {
            jsapi::hook_api::remove_single_hook(*addr, data);
            jsapi::hook_api::free_hook_callback(data);
        }
    }

    // java hooks：移除 native trampoline + 释放资源
    let java_count = jsapi::java::release_owned_java_hooks(jsapi::java::callback::take_java_hooks_owned_by(id));

    script_registry::forget_script(id);
    drop(engine_guard);
    Ok((native_count, java_count))
}
