//! hook() and unhook() API implementation

mod callback;
mod functions;
#[cfg(feature = "qbdi")]
mod qbdi;
mod registry;

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::set_js_u64_property;
use crate::jsapi::util::add_cfunction_to_object;

use callback::{in_flight_native_hook_callbacks, wait_for_in_flight_native_hook_callbacks};
use functions::{js_call_native, js_hook, js_recomp_hook, js_unhook};
#[cfg(feature = "qbdi")]
pub use qbdi::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use qbdi::shutdown_qbdi_helper;
pub use registry::StealthMode;
use registry::{HOOK_REGISTRY, STEALTH_NORMAL, STEALTH_RECOMP, STEALTH_WXSHADOW};

/// Register hook API
pub fn register_hook_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let g = global.raw();
        add_cfunction_to_object(ctx.as_ptr(), g, "hook", js_hook, 3);
        add_cfunction_to_object(ctx.as_ptr(), g, "unhook", js_unhook, 1);
        add_cfunction_to_object(ctx.as_ptr(), g, "callNative", js_call_native, 1);
        add_cfunction_to_object(ctx.as_ptr(), g, "recompHook", js_recomp_hook, 2);

        // Hook.NORMAL = 0, Hook.WXSHADOW = 1, Hook.RECOMP = 2
        let hook_obj = ffi::JS_NewObject(ctx.as_ptr());
        set_js_u64_property(ctx.as_ptr(), hook_obj, "NORMAL", STEALTH_NORMAL as u64);
        set_js_u64_property(ctx.as_ptr(), hook_obj, "WXSHADOW", STEALTH_WXSHADOW as u64);
        set_js_u64_property(ctx.as_ptr(), hook_obj, "RECOMP", STEALTH_RECOMP as u64);
        global.set_property(ctx.as_ptr(), "Hook", crate::value::JSValue(hook_obj));
    }

    #[cfg(feature = "qbdi")]
    {
        let qbdi = ctx.new_object();
        qbdi::register_qbdi_api(ctx.as_ptr(), qbdi.raw());
        global.set_property(ctx.as_ptr(), "qbdi", qbdi);
    }

    global.free(ctx.as_ptr());
}

/// Cleanup all hooks (call before dropping context)
pub fn cleanup_hooks() {
    let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        // 第一阶段：移除所有 hook，阻止新回调触发
        for (_addr, data) in registry.iter() {
            let remove_addr = if data.mode == StealthMode::Recomp {
                data.recomp_addr
            } else {
                *_addr
            };
            unsafe {
                ffi::hook::hook_remove(remove_addr as *mut std::ffi::c_void);
            }
        }
        if !wait_for_in_flight_native_hook_callbacks(std::time::Duration::from_millis(200)) {
            crate::jsapi::console::output_message(&format!(
                "[hook cleanup] waiting for in-flight callbacks timed out, remaining={}",
                in_flight_native_hook_callbacks()
            ));
        }
        // 第二阶段：安全释放 callback
        for (_addr, data) in registry {
            unsafe {
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
}
