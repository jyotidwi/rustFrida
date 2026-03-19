//! js_hook, js_unhook, js_call_native implementations

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_pointer_address, js_i64_to_js_number_or_bigint,
    js_value_to_u64_or_zero, throw_internal_error,
};
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

use super::callback::hook_callback_wrapper;
use super::registry::{hook_error_message, init_registry, HookData, StealthMode, HOOK_OK, HOOK_REGISTRY};
use crate::jsapi::callback_util::with_registry_mut;

/// hook(ptr, callback, mode?) - Install a hook at the given address
///
/// mode: Hook.NORMAL (0, default), Hook.WXSHADOW (1) / true, Hook.RECOMP (2)
pub(crate) unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"hook() requires at least 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // 解析 stealth 模式：0=Normal, 1/true=WxShadow, 2=Recomp
    let mode = if argc >= 3 {
        let mode_arg = JSValue(*argv.add(2));
        match mode_arg.to_i64(ctx) {
            Some(v) => StealthMode::from_js_arg(v),
            // bool true → WxShadow（向后兼容）
            None if mode_arg.to_bool() == Some(true) => StealthMode::WxShadow,
            None => StealthMode::Normal,
        }
    } else {
        StealthMode::Normal
    };

    install_hook(ctx, ptr_arg, callback_arg, mode)
}

/// recompHook(ptr, callback) - 便捷函数，等价于 hook(ptr, callback, Hook.RECOMP)
pub(crate) unsafe extern "C" fn js_recomp_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(ctx, b"recompHook() requires 2 arguments\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    install_hook(ctx, ptr_arg, callback_arg, StealthMode::Recomp)
}

/// 统一 hook 安装逻辑
unsafe fn install_hook(
    ctx: *mut ffi::JSContext,
    ptr_arg: JSValue,
    callback_arg: JSValue,
    mode: StealthMode,
) -> ffi::JSValue {
    let addr = match extract_pointer_address(ctx, ptr_arg, "hook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if let Err(err) = ensure_function_arg(ctx, callback_arg, b"hook() second argument must be a function\0") {
        return err;
    }

    init_registry();

    // Recomp 模式：先重编译页，获取重编译后的地址
    let (hook_addr, recomp_addr) = match mode {
        StealthMode::Recomp => {
            match crate::recomp::ensure_and_translate(addr as usize) {
                Ok(ra) => (ra as u64, ra as u64),
                Err(e) => return throw_internal_error(ctx, &format!("hook(recomp): {}", e)),
            }
        }
        _ => (addr, 0),
    };

    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    let stealth_flag = match mode {
        StealthMode::WxShadow => 1,
        _ => 0,
    };

    let trampoline = hook_ffi::hook_replace(
        hook_addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        addr as *mut std::ffi::c_void, // user_data = 原始地址（registry key）
        stealth_flag,
    );

    if trampoline.is_null() {
        let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
        return throw_internal_error(ctx, "hook_replace failed: could not install hook");
    }

    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            addr,
            HookData {
                ctx: ctx as usize,
                callback_bytes,
                trampoline: trampoline as u64,
                mode,
                recomp_addr,
            },
        );
    });

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
pub(crate) unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "unhook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    // Recomp 模式下 hook_remove 要用重编译后的地址
    let remove_addr = with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.get(&addr).map(|d| {
            if d.mode == StealthMode::Recomp { d.recomp_addr } else { addr }
        })
    }).flatten().unwrap_or(addr);

    let result = hook_ffi::hook_remove(remove_addr as *mut std::ffi::c_void);

    if result != HOOK_OK {
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    if let Some(data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr)) {
        if let Some(data) = data {
            let ctx = data.ctx as *mut ffi::JSContext;
            let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, callback);
        }
    }

    JSValue::bool(true).raw()
}

/// callNative(ptr, arg0?, arg1?, ..., arg5?) - Call a native function at addr with 0-6 args.
/// Arguments are passed in x0-x5 (ARM64 calling convention). Unspecified args default to 0.
/// Return value: Number when result fits exactly in f64 (≤ 2^53), BigUint64 otherwise.
pub(crate) unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"callNative() requires at least 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "callNative") {
        Ok(a) => a,
        Err(e) => return e,
    };

    if addr < 0x10000 {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(ctx, b"callNative() address is not mapped\0".as_ptr() as *const _);
    }

    {
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        if unsafe { libc::dladdr(addr as *const std::ffi::c_void, &mut info) } == 0 {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"callNative() address is not in an executable segment\0".as_ptr() as *const _,
            );
        }
    }

    let mut args = [0u64; 6];
    for i in 0..6usize {
        if (i + 1) < argc as usize {
            let arg = JSValue(*argv.add(i + 1));
            args[i] = js_value_to_u64_or_zero(ctx, arg);
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 = std::mem::transmute(addr as usize);
    let result = func(args[0], args[1], args[2], args[3], args[4], args[5]);

    js_i64_to_js_number_or_bigint(ctx, result)
}
