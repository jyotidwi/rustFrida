/* QBDI 动态二进制插装功能模块 */
#![cfg(feature = "qbdi")]

use crate::{log_msg, OUTPUT_PATH};
use crossbeam_channel::{bounded, Sender};
use lazy_static::lazy_static;
use prost::Message;
use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::thread;

use qbdi::ffi::{
    InstPosition_QBDI_PREINST, MemoryAccessType_QBDI_MEMORY_READ, VMAction_QBDI_CONTINUE,
    VMEvent_QBDI_EXEC_TRANSFER_RETURN, VMInstanceRef,
};
use qbdi::{FPRState, GPRState, RWord, VMAction, VMRef, VirtualStack, VM};

// 条件编译：仅在同时启用 frida-gum 时才引入这些依赖
#[cfg(feature = "frida-gum")]
use crate::stalker::{get_interceptor, GLOBAL_ORIGINAL, GLOBAL_TARGET, GUM};
#[cfg(feature = "frida-gum")]
use frida_gum::{NativePointer, Process};

// 内存访问记录
#[derive(Clone, PartialEq, Message)]
pub struct MemAccess {
    #[prost(uint64, tag = "1")]
    inst_addr: u64,
    #[prost(uint64, tag = "2")]
    access_addr: u64,
    #[prost(uint64, tag = "3")]
    value: u64,
    #[prost(uint32, tag = "4")]
    size: u32,
}

// 外部调用返回记录
#[derive(Clone, PartialEq, Message)]
pub struct ExternalReturn {
    #[prost(uint64, tag = "1")]
    return_addr: u64,
    #[prost(uint64, tag = "2")]
    return_value: u64,
}

// 全局 QBDI VM 包装器
struct VMCell(UnsafeCell<VM>);
unsafe impl Sync for VMCell {}
unsafe impl Send for VMCell {}

static GLOBAL_VM: OnceLock<VMCell> = OnceLock::new();

// 仅 qbdi 模式下的全局变量（不依赖 frida-gum）
#[cfg(not(feature = "frida-gum"))]
pub static GLOBAL_TARGET: OnceLock<usize> = OnceLock::new();
#[cfg(not(feature = "frida-gum"))]
pub static GLOBAL_ORIGINAL: OnceLock<usize> = OnceLock::new();

lazy_static! {
    // QBDI 地址发送通道
    static ref QBDI_ADDR_SENDER: Sender<RWord> = {
        let (sender, receiver) = bounded::<RWord>(100000);

        thread::spawn(move || {
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/trace.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建 QBDI 日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开 QBDI 日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(addr) = receiver.recv() {
                if let Err(e) = log_file.write_all(&addr.to_le_bytes()) {
                    log_msg(format!("写入 QBDI 日志失败: {}", e));
                }
            }
            let _ = log_file.flush();
        });

        sender
    };

    // 内存访问记录通道
    static ref MEM_ACCESS_SENDER: Sender<MemAccess> = {
        let (sender, receiver) = bounded::<MemAccess>(100000);

        thread::spawn(move || {
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/mem_access.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建内存访问日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开内存访问日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(mem_acc) = receiver.recv() {
                let mut buf = Vec::new();
                if let Err(e) = mem_acc.encode_length_delimited(&mut buf) {
                    log_msg(format!("MemAccess 编码失败: {}", e));
                    continue;
                }
                if let Err(e) = log_file.write_all(&buf) {
                    log_msg(format!("写入内存访问日志失败: {}", e));
                }
            }
            let _ = log_file.flush();
        });

        sender
    };

    // 外部调用返回记录通道
    static ref EXTERNAL_RETURN_SENDER: Sender<ExternalReturn> = {
        let (sender, receiver) = bounded::<ExternalReturn>(100000);

        thread::spawn(move || {
            let log_path = match OUTPUT_PATH.get() {
                Some(base) => format!("{}/external_return.pb", base),
                None => {
                    log_msg("错误: OUTPUT_PATH 未设置，无法创建外部返回日志文件".to_string());
                    return;
                }
            };

            let mut log_file = match OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&log_path)
            {
                Ok(f) => f,
                Err(e) => {
                    log_msg(format!("无法打开外部返回日志文件 {}: {}", log_path, e));
                    return;
                }
            };

            while let Ok(ext_ret) = receiver.recv() {
                let mut buf = Vec::new();
                if let Err(e) = ext_ret.encode_length_delimited(&mut buf) {
                    log_msg(format!("ExternalReturn 编码失败: {}", e));
                    continue;
                }
                if let Err(e) = log_file.write_all(&buf) {
                    log_msg(format!("写入外部返回日志失败: {}", e));
                }
            }
            let _ = log_file.flush();
        });

        sender
    };
}

/// 获取全局 QBDI VM
#[inline]
fn get_vm() -> &'static mut VM {
    let cell = GLOBAL_VM.get().expect("QBDI VM not initialized");
    unsafe { &mut *cell.0.get() }
}

/// QBDI 指令回调
pub extern "C" fn qbdicb(
    _vm: VMInstanceRef,
    gpr_state: *mut GPRState,
    _fpr_state: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        let addr = (*gpr_state).pc;
        let _ = QBDI_ADDR_SENDER.send(addr);
    }
    VMAction_QBDI_CONTINUE
}

/// 内存访问回调
extern "C" fn mem_acc_cb(
    _vm: VMInstanceRef,
    _gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        let accesses = VMRef::from_raw(_vm).get_inst_memory_access();
        for acc in accesses {
            if !acc.is_read() {
                continue;
            }

            let mem_acc = MemAccess {
                inst_addr: acc.inst_address(),
                access_addr: acc.access_address(),
                value: acc.value(),
                size: acc.size() as u32,
            };

            let _ = MEM_ACCESS_SENDER.try_send(mem_acc);
        }
    }
    VMAction_QBDI_CONTINUE
}

/// EXEC_TRANSFER_RETURN 事件回调
extern "C" fn exec_transfer_return_cb(
    _vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if event.is_null() || gpr.is_null() {
            return VMAction_QBDI_CONTINUE;
        }

        let ext_ret = ExternalReturn {
            return_addr: (*gpr).pc,
            return_value: (*gpr).x0,
        };

        let _ = EXTERNAL_RETURN_SENDER.try_send(ext_ret);
    }
    VMAction_QBDI_CONTINUE
}

/// QBDI 替换回调（需要 frida-gum 支持时使用）
#[cfg(feature = "frida-gum")]
pub extern "C" fn replaceq(jenv: RWord, jobj: RWord) -> RWord {
    get_interceptor().revert(NativePointer(
        GLOBAL_TARGET.get().unwrap().clone() as *mut c_void
    ));
    log_msg(format!("replaceq: arg1=0x{:x}, arg2=0x{:x}\n", jenv, jobj));

    let value: u64;
    unsafe {
        core::arch::asm!(
            "mrs {0}, tpidr_el0",
            out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    log_msg(format!("tls=0x{:x}", value));

    let vm = get_vm();
    let target = GLOBAL_TARGET.get().unwrap().clone() as u64;

    let state = vm.gpr_state().expect("GPRState is null");
    let _stack = VirtualStack::new(state, 0x100000).unwrap();
    log_msg(format!("SP=0x{:x}\n", _stack.alloc.ptr as u64 + 0x100000));

    match vm.call(target as RWord, &[jenv, jobj]) {
        Some(ret) => {
            log_msg(format!("QBDI call succeeded, ret=0x{:x}", ret));
            ret
        }
        None => {
            log_msg("QBDI vm.call() failed, trying vm.run()...".to_string());

            let state = vm.gpr_state().unwrap();
            state.x0 = jenv;
            state.x1 = jobj;
            state.lr = 0;

            let success = vm.run(target as RWord, 0);
            log_msg(format!("vm.run() returned: {}", success));

            if success {
                let ret = vm.gpr_state().unwrap().x0;
                log_msg(format!("run succeeded, ret=0x{:x}", ret));
                ret
            } else {
                log_msg("QBDI vm.run() also failed, calling original".to_string());
                let orig: extern "C" fn(RWord, RWord) -> RWord =
                    unsafe { std::mem::transmute(*GLOBAL_ORIGINAL.get().unwrap()) };
                orig(jenv, jobj)
            }
        }
    }
}

/// qfollow - 使用 QBDI 进行函数追踪（需要 frida-gum 支持）
#[cfg(feature = "frida-gum")]
pub fn qfollow(lib: &str, addr: usize) {
    let md = Process::obtain(&GUM).find_module_by_name(lib).unwrap();
    let base = md.range().base_address().0 as usize;
    let end = base + md.range().size();
    let target = base + addr;
    let _ = GLOBAL_TARGET.set(target);
    log_msg(format!("base:0x{:x}\n", base));
    log_msg(format!("target:0x{:x}\n", target));

    // 初始化 QBDI VM
    let mut vm = VM::new();
    vm.add_instrumented_range(base as RWord, end as RWord);

    // 添加回调
    vm.add_code_cb(InstPosition_QBDI_PREINST, Some(qbdicb), null_mut(), 0);
    vm.add_mem_access_cb(
        MemoryAccessType_QBDI_MEMORY_READ,
        Some(mem_acc_cb),
        null_mut(),
        0,
    );
    vm.add_vm_event_cb(
        VMEvent_QBDI_EXEC_TRANSFER_RETURN,
        Some(exec_transfer_return_cb),
        null_mut(),
    );

    // 存储 VM 到全局变量
    let _ = GLOBAL_VM.set(VMCell(UnsafeCell::new(vm)));

    let interceptor = get_interceptor();
    match interceptor.replace(
        NativePointer(target as *mut c_void),
        NativePointer(replaceq as *mut c_void),
        NativePointer(null_mut()),
    ) {
        Ok(original) => {
            let _ = GLOBAL_ORIGINAL.set(original.0 as usize);
        }
        Err(e) => {
            log_msg(format!("replace failed: {:?}", e));
        }
    }
}

/// qfollow - 纯 QBDI 模式（不需要 frida-gum）
#[cfg(not(feature = "frida-gum"))]
pub fn qfollow(_lib: &str, _addr: usize) {
    log_msg("qfollow requires frida-gum feature to find module base address".to_string());
    log_msg("Please enable both 'qbdi' and 'frida-gum' features".to_string());
}
