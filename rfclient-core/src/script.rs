//! 脚本相关的小工具：与设备端 REPL 保持一致的表达式包装与字面量转义。

/// `jseval` 的错误标记：设备端把异常包装成普通返回值，靠这个前缀区分。
///
/// 必须与设备端 `repl.rs` 里的同名字符串一致，否则错误会被当成正常结果打印。
pub const JSEVAL_ERROR_PREFIX: &str = "__RF_JSEVAL_ERROR__:";

/// 把表达式包装成「求值 + 友好错误提示」的 JS。
///
/// 与设备端 `repl.rs` 的 `wrap_jseval_expr` 等价：捕获异常后把
/// `name: message` 与 stack 拼起来，并以 [`JSEVAL_ERROR_PREFIX`] 开头返回，
/// 使 TCP 客户端能在「只有文本通道」的前提下区分成功与失败。
pub fn wrap_jseval_expr(expr: &str) -> String {
    format!(
        "(() => {{ try {{ return eval({}); }} catch (e) {{ let msg = String((e && e.message) ? ((e.name || 'Error') + ': ' + e.message) : e); let st = ''; try {{ st = (e && e.stack) ? String(e.stack) : ''; }} catch (_) {{}} let s = st ? (st.indexOf(msg) >= 0 ? st : (msg + '\\n' + st)) : msg; return {} + s; }} }})()",
        js_string_literal(expr),
        js_string_literal(JSEVAL_ERROR_PREFIX)
    )
}

/// 把字符串转义成单引号 JS 字面量。
pub fn js_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        match c {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// 该命令是否会产生 EVAL 应答？
///
/// `trace` / `stalker` / `detach` 等只输出 LOG 帧，等应答会白等到超时。
pub fn expects_response(cmd: &str) -> bool {
    let name = cmd.split_whitespace().next().unwrap_or("");
    !matches!(name, "trace" | "stalker" | "__set_verbose__" | "detach" | "shutdown")
}
