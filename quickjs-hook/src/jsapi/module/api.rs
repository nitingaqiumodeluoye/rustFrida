// ============================================================================
// JS API: Module namespace
// ============================================================================

use crate::jsapi::callback_util::{extract_pointer_address, throw_internal_error};
use crate::jsapi::util::add_cfunction_to_object;

unsafe fn module_info_to_js(ctx: *mut ffi::JSContext, m: &ModuleInfo) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);

    let name_val = JSValue::string(ctx, &m.name);
    let base_val = create_native_pointer(ctx, m.base);
    // Keep module fields JSON-serializable. `base` is a NativePointer with `toJSON()`,
    // and `size` must stay out of BigInt territory for JSON.stringify().
    let size_val = if m.size <= i64::MAX as u64 {
        JSValue(ffi::qjs_new_int64(ctx, m.size as i64))
    } else {
        JSValue::float(m.size as f64)
    };
    let path_val = JSValue::string(ctx, &m.path);

    obj_val.set_property(ctx, "name", name_val);
    obj_val.set_property(ctx, "base", base_val);
    obj_val.set_property(ctx, "size", size_val);
    obj_val.set_property(ctx, "path", path_val);

    // Frida 对齐：ModuleInfo 实例方法。官方 Frida 的 Module 实例可直接
    // `mod.findExportByName("sym")`，而不再需要回传模块名给静态 Module.*。
    // 实现方式：这些 C 函数从 `this.name` 取自己的模块名，再复用静态路径。
    add_cfunction_to_object(ctx, obj, "findExportByName", js_module_instance_find_export, 1);
    add_cfunction_to_object(ctx, obj, "getExportByName", js_module_instance_get_export, 1);
    add_cfunction_to_object(ctx, obj, "enumerateExports", js_module_instance_enumerate_exports, 0);
    add_cfunction_to_object(ctx, obj, "enumerateImports", js_module_instance_enumerate_imports, 0);
    add_cfunction_to_object(ctx, obj, "enumerateSymbols", js_module_instance_enumerate_symbols, 0);
    add_cfunction_to_object(ctx, obj, "findSymbolByName", js_module_instance_find_symbol, 1);
    add_cfunction_to_object(ctx, obj, "getSymbolByName", js_module_instance_get_symbol, 1);
    add_cfunction_to_object(ctx, obj, "enumerateRanges", js_module_instance_enumerate_ranges, 1);

    obj
}

/// 从 `this.name` 取当前 ModuleInfo 实例的模块名。
/// 失败时抛 TypeError（正常不会发生，除非用户把方法拆下来单独调用）。
unsafe fn instance_module_name(ctx: *mut ffi::JSContext, this: ffi::JSValue) -> Result<String, ffi::JSValue> {
    let name_val = JSValue(this).get_property(ctx, "name");
    let name = name_val.to_string(ctx);
    name_val.free(ctx);
    match name {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(ffi::JS_ThrowTypeError(
            ctx,
            b"Module method called on an object without a module name\0".as_ptr() as *const _,
        )),
    }
}

/// mod.findExportByName(symbolName) → NativePointer | null
///
/// 在模块的导出表里查符号，找不到返回 null（与静态 Module.findExportByName 一致）。
unsafe extern "C" fn js_module_instance_find_export(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"mod.findExportByName(symbolName) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    let symbol_name = match require_string_arg(ctx, JSValue(*argv), "symbolName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };

    let addr = module_dlsym(&module_name, &symbol_name);
    if addr.is_null() {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, addr as u64).raw()
    }
}

/// mod.getExportByName(symbolName) — 同 findExportByName，但找不到时抛异常。
unsafe extern "C" fn js_module_instance_get_export(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = js_module_instance_find_export(ctx, this, argc, argv);
    if JSValue(result).is_null() {
        let module_name = instance_module_name(ctx, this).unwrap_or_else(|_| String::from("<unknown>"));
        let symbol_name = if argc >= 1 {
            JSValue(*argv).to_string(ctx).unwrap_or_default()
        } else {
            String::new()
        };
        let msg = format!("{}: unable to find export '{}'", module_name, symbol_name);
        return throw_internal_error(ctx, msg);
    }
    result
}

/// mod.enumerateExports() → 与静态 Module.enumerateExports(self.name) 同形。
unsafe extern "C" fn js_module_instance_enumerate_exports(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_exports_for_module(ctx, &module_name)
}

/// mod.enumerateImports()
unsafe extern "C" fn js_module_instance_enumerate_imports(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_imports_for_module(ctx, &module_name)
}

/// mod.enumerateSymbols()
unsafe extern "C" fn js_module_instance_enumerate_symbols(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_symbols_for_module(ctx, &module_name)
}

/// mod.findSymbolByName(symbolName) → NativePointer | null
///
/// 与 findExportByName 的区别：本函数查 ELF 符号表（含 local/undefined），
/// 不要求符号是动态导出。debug 符号（如 linker64 的 __dl_* 系列）需要走这里。
unsafe extern "C" fn js_module_instance_find_symbol(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"mod.findSymbolByName(symbolName) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    let symbol_name = match require_string_arg(ctx, JSValue(*argv), "symbolName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };

    match find_symbol_in_module(&module_name, &symbol_name) {
        Some(addr) => create_native_pointer(ctx, addr).raw(),
        None => JSValue::null().raw(),
    }
}

/// mod.getSymbolByName(symbolName) — 同 findSymbolByName，未命中时抛异常。
unsafe extern "C" fn js_module_instance_get_symbol(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let result = js_module_instance_find_symbol(ctx, this, argc, argv);
    if JSValue(result).is_null() {
        let module_name = instance_module_name(ctx, this).unwrap_or_else(|_| String::from("<unknown>"));
        let symbol_name = if argc >= 1 {
            JSValue(*argv).to_string(ctx).unwrap_or_default()
        } else {
            String::new()
        };
        let msg = format!("{}: unable to find symbol '{}'", module_name, symbol_name);
        return throw_internal_error(ctx, msg);
    }
    result
}

/// mod.enumerateRanges(protection) → 与静态 Module.enumerateRanges(self.name, prot) 同形。
unsafe extern "C" fn js_module_instance_enumerate_ranges(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let module_name = match instance_module_name(ctx, this) {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    // 复用静态实现：把模块名合成成第一个参数转发过去。
    // 注意与静态版一致：protection 可省略，故此处不强制 argc >= 1。
    let mut args = [
        JSValue::string(ctx, &module_name),
        if argc >= 1 { JSValue(*argv) } else { JSValue::undefined() },
    ];
    js_module_enumerate_ranges(ctx, JSValue::undefined(), if argc >= 1 { 2 } else { 1 }, args.as_mut_ptr())
}

/// Module.findExportByName(moduleName, symbolName) → NativePointer | null
///
/// moduleName == null → search all loaded modules through our ELF parser
/// moduleName != null → module_dlsym(moduleName, symbolName)
unsafe extern "C" fn js_module_find_export(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findExportByName(moduleName, symbolName) requires 2 arguments\0".as_ptr()
                as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let arg1 = JSValue(*argv.add(1));

    // Get symbol name (required)
    let symbol_name = match arg1.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"symbolName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let addr: *mut std::ffi::c_void = if arg0.is_null() || arg0.is_undefined() {
        find_export_in_loaded_modules(&symbol_name)
    } else {
        // Specific module
        let module_name = match arg0.to_string(ctx) {
            Some(s) => s,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"moduleName must be a string or null\0".as_ptr() as *const _,
                );
            }
        };
        module_dlsym(&module_name, &symbol_name)
    };

    if addr.is_null() {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, addr as u64).raw()
    }
}

/// Module.findBaseAddress(moduleName) → NativePointer | null
unsafe extern "C" fn js_module_find_base(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findBaseAddress(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let module_name = match arg0.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"moduleName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let base = find_module_base(&module_name);
    if base == 0 {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, base).raw()
    }
}

/// Module.findByAddress(addr) → {name, base, size, path} | null
unsafe extern "C" fn js_module_find_by_address(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findByAddress(addr) requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let addr = match extract_pointer_address(ctx, JSValue(*argv), "Module.findByAddress") {
        Ok(a) => a,
        Err(e) => return e,
    };

    match find_module_by_address(addr) {
        Some(module) => module_info_to_js(ctx, &module),
        None => JSValue::null().raw(),
    }
}

/// Module.enumerateModules() → Array of {name, base, size, path}
unsafe extern "C" fn js_module_enumerate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let modules = enumerate_modules_from_maps();

    let arr = ffi::JS_NewArray(ctx);
    for (i, m) in modules.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, module_info_to_js(ctx, m));
    }

    arr
}

/// Resolve a module name to (file_path, base_address). `None` means the module
/// is either missing or has no on-disk backing file (memfd / synthetic).
fn resolve_module_for_enumeration(module_name: &str) -> Option<(String, u64)> {
    find_module_path_and_base(module_name)
}

/// Convert a required-string JS arg to a `String`, throwing a TypeError on miss.
unsafe fn require_string_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    what: &str,
) -> Result<String, ffi::JSValue> {
    match value.to_string(ctx) {
        Some(s) => Ok(s),
        None => {
            let msg = format!("{} must be a string\0", what);
            Err(ffi::JS_ThrowTypeError(
                ctx,
                msg.as_ptr() as *const _,
            ))
        }
    }
}

unsafe fn symbol_record_to_js(
    ctx: *mut ffi::JSContext,
    rec: &SymbolRecord,
    include_is_global: bool,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "type", JSValue::string(ctx, rec.kind));
    obj_val.set_property(ctx, "name", JSValue::string(ctx, &rec.name));
    obj_val.set_property(ctx, "address", create_native_pointer(ctx, rec.address));
    if include_is_global {
        obj_val.set_property(ctx, "isGlobal", JSValue::bool(rec.is_global));
        // Match Frida's shape — consumers use this to skip unresolved imports.
        obj_val.set_property(ctx, "isDefined", JSValue::bool(rec.is_defined));
    }
    obj
}

unsafe fn import_record_to_js(
    ctx: *mut ffi::JSContext,
    rec: &ImportRecord,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "type", JSValue::string(ctx, rec.kind));
    obj_val.set_property(ctx, "name", JSValue::string(ctx, &rec.name));
    obj_val.set_property(ctx, "slot", create_native_pointer(ctx, rec.slot));
    obj_val.set_property(ctx, "address", create_native_pointer(ctx, rec.address));
    obj
}

unsafe fn range_record_to_js(
    ctx: *mut ffi::JSContext,
    rec: &RangeRecord,
) -> ffi::JSValue {
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "base", create_native_pointer(ctx, rec.base));
    let size_val = if rec.size <= i64::MAX as u64 {
        JSValue(ffi::qjs_new_int64(ctx, rec.size as i64))
    } else {
        JSValue::float(rec.size as f64)
    };
    obj_val.set_property(ctx, "size", size_val);
    obj_val.set_property(ctx, "protection", JSValue::string(ctx, &rec.protection));

    // file = { path } — enough for identification; offset/size omitted.
    let file = ffi::JS_NewObject(ctx);
    let file_val = JSValue(file);
    file_val.set_property(ctx, "path", JSValue::string(ctx, &rec.path));
    obj_val.set_property(ctx, "file", file_val);

    obj
}

// ---------------------------------------------------------------------------
// 按模块名枚举（静态 `Module.*` 与实例方法 `mod.*` 共用）
// ---------------------------------------------------------------------------

/// 导出符号（defined + global）——`Module.enumerateExports(name)` / `mod.enumerateExports()`。
unsafe fn enumerate_exports_for_module(ctx: *mut ffi::JSContext, module_name: &str) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    let Some((path, base)) = resolve_module_for_enumeration(module_name) else {
        return arr;
    };

    let symbols = elf_module_enumerate_symbols(&path, base);
    let mut out_idx = 0u32;
    for sym in &symbols {
        // Exports are defined + globally visible.
        if !sym.is_defined || !sym.is_global {
            continue;
        }
        ffi::JS_SetPropertyUint32(ctx, arr, out_idx, symbol_record_to_js(ctx, sym, false));
        out_idx += 1;
    }
    arr
}

/// 导入符号（含 PLT/GOT slot）——`Module.enumerateImports(name)` / `mod.enumerateImports()`。
unsafe fn enumerate_imports_for_module(ctx: *mut ffi::JSContext, module_name: &str) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    let Some((path, base)) = resolve_module_for_enumeration(module_name) else {
        return arr;
    };

    let imports = elf_module_enumerate_imports(&path, base);
    for (i, rec) in imports.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, import_record_to_js(ctx, rec));
    }
    arr
}

/// 全部符号（含 local / undefined）——`Module.enumerateSymbols(name)` / `mod.enumerateSymbols()`。
unsafe fn enumerate_symbols_for_module(ctx: *mut ffi::JSContext, module_name: &str) -> ffi::JSValue {
    let arr = ffi::JS_NewArray(ctx);
    let Some((path, base)) = resolve_module_for_enumeration(module_name) else {
        return arr;
    };

    let symbols = elf_module_enumerate_symbols(&path, base);
    for (i, sym) in symbols.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, symbol_record_to_js(ctx, sym, true));
    }
    arr
}

/// 在模块 ELF 符号表里按名字查地址（含 local / debug 符号）。
///
/// 与 `module_dlsym` 的区别：后者只认动态导出表，而 linker64 的 `__dl_*` 这类
/// 内部符号需要走本函数。命中但 address 为 0（如 `.c` 这类 FILE 符号）视为未命中。
unsafe fn find_symbol_in_module(module_name: &str, symbol_name: &str) -> Option<u64> {
    let (path, base) = resolve_module_for_enumeration(module_name)?;
    let symbols = elf_module_enumerate_symbols(&path, base);
    symbols
        .iter()
        .find(|s| s.name == symbol_name && s.address != 0)
        .map(|s| s.address)
}

/// Module.enumerateExports(moduleName) → Array of {type, name, address}
unsafe extern "C" fn js_module_enumerate_exports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.enumerateExports(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let module_name = match require_string_arg(ctx, JSValue(*argv), "moduleName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_exports_for_module(ctx, &module_name)
}

/// Module.enumerateImports(moduleName) → Array of {type, name, slot, address}
unsafe extern "C" fn js_module_enumerate_imports(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.enumerateImports(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let module_name = match require_string_arg(ctx, JSValue(*argv), "moduleName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_imports_for_module(ctx, &module_name)
}

/// Module.enumerateSymbols(moduleName) → Array of {type, name, address, isGlobal, isDefined}
unsafe extern "C" fn js_module_enumerate_symbols(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.enumerateSymbols(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }
    let module_name = match require_string_arg(ctx, JSValue(*argv), "moduleName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    enumerate_symbols_for_module(ctx, &module_name)
}

/// Module.enumerateRanges(moduleName, protection?) → Array of {base, size, protection, file}
///
/// `protection` is optional — "r-x" matches any range satisfying read+exec; if
/// omitted, all file-backed VMAs of the module are returned.
unsafe extern "C" fn js_module_enumerate_ranges(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.enumerateRanges(moduleName, protection?) requires at least 1 argument\0"
                .as_ptr() as *const _,
        );
    }
    let module_name = match require_string_arg(ctx, JSValue(*argv), "moduleName") {
        Ok(s) => s,
        Err(exc) => return exc,
    };

    let prot_filter = if argc >= 2 {
        let arg1 = JSValue(*argv.add(1));
        if arg1.is_null() || arg1.is_undefined() {
            None
        } else {
            match arg1.to_string(ctx) {
                Some(s) => Some(s),
                None => {
                    return ffi::JS_ThrowTypeError(
                        ctx,
                        b"protection must be a string\0".as_ptr() as *const _,
                    );
                }
            }
        }
    } else {
        None
    };

    let ranges = enumerate_module_ranges(&module_name, prot_filter.as_deref());
    let arr = ffi::JS_NewArray(ctx);
    for (i, rec) in ranges.iter().enumerate() {
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, range_record_to_js(ctx, rec));
    }
    arr
}

fn tagged_module_memfd_name(basename: &str) -> String {
    let mut name = String::from("wwb_");
    for ch in basename.chars() {
        if name.len() >= 180 {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    if name == "wwb_" {
        name.push_str("module.so");
    }
    name
}

/// Module.load(path, flags?, tagged?) → {name, base, size, path} | throws
///
/// Frida 兼容: 加载指定路径的 SO。成功返回 module info 对象; 失败抛异常。
/// flags 可选, 默认 RTLD_NOW (2)。tagged=true 时通过 memfd 加载并使用 `wwb_` maps 标记。
unsafe extern "C" fn js_module_load(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.load(path, flags?, tagged?) requires at least 1 argument\0".as_ptr() as *const _,
        );
    }
    let path = match require_string_arg(ctx, JSValue(*argv), "path") {
        Ok(s) => s,
        Err(exc) => return exc,
    };
    let mut flags = libc::RTLD_NOW;
    let mut tagged = false;
    if argc >= 2 {
        let arg = JSValue(*argv.add(1));
        if let Some(value) = arg.to_bool() {
            tagged = value;
        } else {
            flags = arg.to_i64(ctx).unwrap_or(libc::RTLD_NOW as i64) as i32;
        }
    }
    if argc >= 3 {
        let arg = JSValue(*argv.add(2));
        if let Some(value) = arg.to_bool() {
            tagged = value;
        } else {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Module.load(path, flags?, tagged?) tagged argument must be a boolean\0".as_ptr() as *const _,
            );
        }
    }

    let basename: String = path.rsplit('/').next().unwrap_or(&path).to_string();
    let memfd_name = tagged.then(|| tagged_module_memfd_name(&basename));
    let handle = if let Some(name) = memfd_name.as_deref() {
        match module_dlopen_load_memfd(&path, flags, name) {
            Ok(handle) => handle,
            Err(e) => {
                return crate::jsapi::callback_util::throw_internal_error(
                    ctx,
                    format!("Module.load: memfd load('{}', '{}') failed: {}", path, name, e),
                );
            }
        }
    } else {
        module_dlopen_load(&path, flags)
    };
    if handle.is_null() {
        let err_ptr = libc::dlerror();
        let err_msg = if err_ptr.is_null() {
            format!("Module.load: dlopen('{}') returned null", path)
        } else {
            let e = std::ffi::CStr::from_ptr(err_ptr).to_string_lossy().into_owned();
            format!("Module.load: dlopen('{}') failed: {}", path, e)
        };
        return crate::jsapi::callback_util::throw_internal_error(ctx, err_msg);
    }

    // 从 /proc/self/maps 找刚加载的模块。tagged=true 时优先返回 memfd 映射，
    // 避免原始 so 已加载时误返回同路径的旧模块。
    let modules = enumerate_modules_from_maps();
    if let Some(name) = memfd_name.as_deref() {
        for m in &modules {
            if m.path.contains(name) || m.name.contains(name) {
                return module_info_to_js(ctx, m);
            }
        }
    }
    for m in &modules {
        if m.path == path {
            return module_info_to_js(ctx, m);
        }
    }
    for m in &modules {
        if m.name == basename || m.path.ends_with(&path) {
            return module_info_to_js(ctx, m);
        }
    }

    // 没在 maps 里找到 (memfd / 被 hide_soinfo 摘除): 最小 info, handle 作 base
    let obj = ffi::JS_NewObject(ctx);
    let obj_val = JSValue(obj);
    obj_val.set_property(ctx, "name", JSValue::string(ctx, &basename));
    obj_val.set_property(ctx, "path", JSValue::string(ctx, &path));
    obj_val.set_property(ctx, "base", create_native_pointer(ctx, handle as u64));
    obj_val.set_property(ctx, "size", JSValue(ffi::qjs_new_int64(ctx, 0)));
    obj
}

/// Register Module JS API
pub fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let module_obj = ffi::JS_NewObject(ctx_ptr);

        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "findExportByName",
            js_module_find_export,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "findBaseAddress",
            js_module_find_base,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "findByAddress",
            js_module_find_by_address,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateModules",
            js_module_enumerate,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateExports",
            js_module_enumerate_exports,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateImports",
            js_module_enumerate_imports,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateSymbols",
            js_module_enumerate_symbols,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "enumerateRanges",
            js_module_enumerate_ranges,
            2,
        );
        add_cfunction_to_object(
            ctx_ptr,
            module_obj,
            "load",
            js_module_load,
            1,
        );

        global.set_property(ctx.as_ptr(), "Module", JSValue(module_obj));
    }

    global.free(ctx.as_ptr());

    register_process_api(ctx);
}
