use super::ffi;
use super::api::{lua_to_jvalue, lua_string_to_jstring, push_jni_arg};

type JniEnv = crate::jsapi::java::jni_core::JniEnv;

/// JNI vtable 常用索引
const JNI_FIND_CLASS: usize = 6;
const JNI_GET_METHOD_ID: usize = 33;
const JNI_GET_STATIC_METHOD_ID: usize = 113;
const JNI_NEW_LOCAL_REF: usize = 25;
const JNI_DELETE_LOCAL_REF: usize = 23;
const JNI_EXCEPTION_CHECK: usize = 228;
const JNI_EXCEPTION_CLEAR: usize = 17;
const JNI_CALL_NONVIRTUAL_VOID_METHOD_A: usize = 93;
const JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A: usize = 96;
const JNI_CALL_NONVIRTUAL_INT_METHOD_A: usize = 99;
const JNI_CALL_NONVIRTUAL_LONG_METHOD_A: usize = 102;
const JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A: usize = 105;
const JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A: usize = 108;
const JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A: usize = 111;
const JNI_CALL_STATIC_VOID_METHOD_A: usize = 143;
const JNI_CALL_STATIC_BOOLEAN_METHOD_A: usize = 146;
const JNI_CALL_STATIC_INT_METHOD_A: usize = 149;
const JNI_CALL_STATIC_LONG_METHOD_A: usize = 152;
const JNI_CALL_STATIC_FLOAT_METHOD_A: usize = 155;
const JNI_CALL_STATIC_DOUBLE_METHOD_A: usize = 158;
const JNI_CALL_STATIC_OBJECT_METHOD_A: usize = 161;
const JNI_NEW_OBJECT_A: usize = 30;

unsafe fn jni_fn_ptr(env: JniEnv, idx: usize) -> *const std::ffi::c_void {
    crate::jsapi::java::jni_core::jni_fn_ptr(env, idx)
}

macro_rules! jfn {
    ($env:expr, $ty:ty, $idx:expr) => {
        std::mem::transmute::<*const std::ffi::c_void, $ty>(jni_fn_ptr($env, $idx))
    };
    ($env:expr, $idx:expr) => {
        std::mem::transmute(jni_fn_ptr($env, $idx))
    };
}

unsafe fn exc_check_clear(env: JniEnv) -> bool {
    let check: unsafe extern "C" fn(JniEnv) -> u8 = jfn!(env, JNI_EXCEPTION_CHECK);
    if check(env) != 0 {
        let clear: unsafe extern "C" fn(JniEnv) = jfn!(env, JNI_EXCEPTION_CLEAR);
        clear(env);
        true
    } else {
        false
    }
}

unsafe fn find_class(env: JniEnv, name: &str) -> *mut std::ffi::c_void {
    crate::jsapi::java::reflect::find_class_safe(env, &name.replace('.', "/"))
}

unsafe fn del_local(env: JniEnv, obj: *mut std::ffi::c_void) {
    if !obj.is_null() {
        let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) = jfn!(env, JNI_DELETE_LOCAL_REF);
        f(env, obj);
    }
}

/// Java._call(jptr, className, methodName, sig, ...)
/// 实例方法调用: CallNonvirtual*MethodA
pub(crate) unsafe extern "C" fn lua_jni_call(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let jptr = ffi::lua_touserdata(L, 1) as u64;
    let cls_c = ffi::lua_tostring_ex(L, 2);
    let method_c = ffi::lua_tostring_ex(L, 3);
    let sig_c = ffi::lua_tostring_ex(L, 4);
    if cls_c.is_null() || method_c.is_null() || sig_c.is_null() || jptr == 0 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let method_name = std::ffi::CStr::from_ptr(method_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }

    let new_local: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void) -> *mut std::ffi::c_void = jfn!(env, JNI_NEW_LOCAL_REF);
    let local_obj = new_local(env, jptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_METHOD_ID);
    let cm = std::ffi::CString::new(method_name.as_ref()).unwrap_or_default();
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, cm.as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, local_obj);
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let return_type = crate::jsapi::java::callback::get_return_type_from_sig(&sig);
    let return_type_sig = crate::jsapi::java::callback::get_return_type_sig(&sig);

    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (5 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    call_and_push_result(L, env, local_obj, cls, mid, jargs_ptr, return_type, &return_type_sig, false);
    del_local(env, local_obj);
    del_local(env, cls);
    1
}

/// Java._staticCall(className, methodName, sig, ...)
pub(crate) unsafe extern "C" fn lua_jni_static_call(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let cls_c = ffi::lua_tostring_ex(L, 1);
    let method_c = ffi::lua_tostring_ex(L, 2);
    let sig_c = ffi::lua_tostring_ex(L, 3);
    if cls_c.is_null() || method_c.is_null() || sig_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let method_name = std::ffi::CStr::from_ptr(method_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() { ffi::lua_pushnil(L); return 1; }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_STATIC_METHOD_ID);
    let cm = std::ffi::CString::new(method_name.as_ref()).unwrap_or_default();
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, cm.as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let return_type = crate::jsapi::java::callback::get_return_type_from_sig(&sig);
    let return_type_sig = crate::jsapi::java::callback::get_return_type_sig(&sig);

    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (4 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    call_and_push_result(L, env, std::ptr::null_mut(), cls, mid, jargs_ptr, return_type, &return_type_sig, true);
    del_local(env, cls);
    1
}

/// Java._new(className, sig, ...)
pub(crate) unsafe extern "C" fn lua_jni_new(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    let cls_c = ffi::lua_tostring_ex(L, 1);
    let sig_c = ffi::lua_tostring_ex(L, 2);
    if cls_c.is_null() || sig_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();

    let cls = find_class(env, &cls_name);
    if cls.is_null() { ffi::lua_pushnil(L); return 1; }

    let get_mid: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *const i8, *const i8) -> *mut std::ffi::c_void = jfn!(env, JNI_GET_METHOD_ID);
    let cs = std::ffi::CString::new(sig.as_ref()).unwrap_or_default();
    let mid = get_mid(env, cls, c"<init>".as_ptr() as *const i8, cs.as_ptr() as *const i8);
    if mid.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }

    let param_types = crate::jsapi::java::callback::parse_jni_param_types(&sig);
    let mut jargs: Vec<u64> = Vec::with_capacity(param_types.len());
    for (i, pt) in param_types.iter().enumerate() {
        let lua_idx = (3 + i) as i32;
        jargs.push(lua_to_jvalue(L, lua_idx, Some(pt.as_str()), env));
    }
    let jargs_ptr: *const std::ffi::c_void = if jargs.is_empty() {
        std::ptr::null()
    } else {
        jargs.as_ptr() as *const _
    };

    let new_obj: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> *mut std::ffi::c_void = jfn!(env, JNI_NEW_OBJECT_A);
    let obj = new_obj(env, cls, mid, jargs_ptr);
    if obj.is_null() || exc_check_clear(env) {
        del_local(env, cls);
        ffi::lua_pushnil(L);
        return 1;
    }
    del_local(env, cls);
    ffi::lua_pushlightuserdata(L, obj);
    1
}

/// Java._methods(className) → {{name=, sig=, isStatic=}, ...}
pub(crate) unsafe extern "C" fn lua_jni_methods(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let nargs = ffi::lua_gettop(L);
    let tp = ffi::lua_type(L, 1);
    crate::jsapi::console::output_message(&format!("[lua] _methods ENTRY nargs={} type1={}", nargs, tp));
    let cls_c = ffi::lua_tostring_ex(L, 1);
    if cls_c.is_null() {
        crate::jsapi::console::output_message("[lua] _methods: arg is null");
        ffi::lua_pushnil(L); return 1;
    }
    let cls_name = std::ffi::CStr::from_ptr(cls_c).to_string_lossy();

    // 直接调 Rust JNI 反射 (不经过 JS 引擎, 避免死锁)
    let env = get_env(L);
    if env.is_null() { ffi::lua_pushnil(L); return 1; }

    // 确保 reflect IDs 已初始化
    crate::jsapi::java::reflect::ensure_reflect_ids(env);

    let methods = match crate::jsapi::java::reflect::enumerate_methods(env, &cls_name) {
        Ok(ms) => ms,
        Err(e) => {
            crate::jsapi::console::output_message(&format!("[lua] _methods({}) error: {}", cls_name, e));
            ffi::lua_pushnil(L);
            return 1;
        }
    };

    ffi::lua_createtable(L, methods.len() as i32, 0);
    for (i, m) in methods.iter().enumerate() {
        ffi::lua_createtable(L, 0, 3);
        let name_cs = std::ffi::CString::new(m.name.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, name_cs.as_ptr());
        ffi::lua_setfield(L, -2, c"name".as_ptr());
        let sig_cs = std::ffi::CString::new(m.sig.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, sig_cs.as_ptr());
        ffi::lua_setfield(L, -2, c"sig".as_ptr());
        ffi::lua_pushboolean(L, if m.is_static { 1 } else { 0 });
        ffi::lua_setfield(L, -2, c"isStatic".as_ptr());
        ffi::lua_rawseti(L, -2, (i + 1) as ffi::lua_Integer);
    }
    1
}

/// 执行 JNI 调用并 push 结果到 Lua 栈
unsafe fn call_and_push_result(
    L: *mut ffi::lua_State,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    mid: *mut std::ffi::c_void,
    args: *const std::ffi::c_void,
    return_type: u8,
    return_type_sig: &str,
    is_static: bool,
) {
    macro_rules! call_jni {
        ($ret_ty:ty, $idx:expr, $static_idx:expr) => {{
            if is_static {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty = jfn!(env, $static_idx);
                f(env, cls, mid, args)
            } else {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty = jfn!(env, $idx);
                f(env, obj, cls, mid, args)
            }
        }};
    }

    match return_type {
        b'V' => {
            if is_static {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) = jfn!(env, JNI_CALL_STATIC_VOID_METHOD_A);
                f(env, cls, mid, args);
            } else {
                let f: unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) = jfn!(env, JNI_CALL_NONVIRTUAL_VOID_METHOD_A);
                f(env, obj, cls, mid, args);
            }
            exc_check_clear(env);
            ffi::lua_pushnil(L);
        }
        b'Z' => {
            let r = call_jni!(u8, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A, JNI_CALL_STATIC_BOOLEAN_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushboolean(L, r as i32);
        }
        b'I' | b'B' | b'C' | b'S' => {
            let r = call_jni!(i32, JNI_CALL_NONVIRTUAL_INT_METHOD_A, JNI_CALL_STATIC_INT_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushinteger(L, r as ffi::lua_Integer);
        }
        b'J' => {
            let r = call_jni!(i64, JNI_CALL_NONVIRTUAL_LONG_METHOD_A, JNI_CALL_STATIC_LONG_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushinteger(L, r as ffi::lua_Integer);
        }
        b'F' => {
            let r = call_jni!(f32, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A, JNI_CALL_STATIC_FLOAT_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushnumber(L, r as f64);
        }
        b'D' => {
            let r = call_jni!(f64, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A, JNI_CALL_STATIC_DOUBLE_METHOD_A);
            exc_check_clear(env);
            ffi::lua_pushnumber(L, r);
        }
        b'L' | b'[' => {
            let r = call_jni!(*mut std::ffi::c_void, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A, JNI_CALL_STATIC_OBJECT_METHOD_A);
            exc_check_clear(env);
            if r.is_null() {
                ffi::lua_pushnil(L);
            } else {
                // 返回 lightuserdata (可以传给 jstr 或其他方法)
                ffi::lua_pushlightuserdata(L, r);
            }
        }
        _ => ffi::lua_pushnil(L),
    }
}

unsafe fn get_env(L: *mut ffi::lua_State) -> JniEnv {
    let env_ptr = super::api::get_current_env();
    if !env_ptr.is_null() {
        return env_ptr as JniEnv;
    }
    match crate::jsapi::java::jni_core::get_thread_env() {
        Ok(e) => e,
        Err(_) => std::ptr::null_mut(),
    }
}
