#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close, write as libc_write};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::io::RawFd;

use crate::process::{
    attach_to_process, call_target_function, get_lib_base, read_memory, write_bytes, write_memory,
};
use crate::types::{write_string_table, AgentArgs, DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_verbose, log_verbose_addr, log_warn};

// 嵌入loader.bin
pub(crate) const SHELLCODE: &[u8] = include_bytes!("../../loader/build/loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] =
    include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] =
    include_bytes!("../../target/aarch64-linux-android/release/libagent.so");

/// 在目标进程中分配内存并写入结构体，返回远程地址。
fn alloc_and_write_struct<T>(pid: i32, malloc_addr: usize, data: &T, name: &str) -> Result<usize, String> {
    let size = size_of::<T>();
    let addr = call_target_function(pid, malloc_addr, &[size], None)
        .map_err(|e| format!("分配{}内存失败: {}", name, e))?;
    log_verbose!("分配{}内存", name);
    log_verbose_addr!("地址", addr);
    write_memory(pid, addr, data)?;
    log_verbose!("{}写入成功", name);
    log_verbose_addr!("地址", addr);
    Ok(addr)
}

/// 在目标进程中调用 socketpair()，返回 (fd0, fd1)
fn create_socketpair_in_target(pid: i32, offsets: &LibcOffsets) -> Result<(i32, i32), String> {
    // 在目标进程中分配 8 字节存放 int[2]
    let sv_addr = call_target_function(pid, offsets.malloc, &[8], None)
        .map_err(|e| format!("分配 socketpair 缓冲区失败: {}", e))?;

    // 调用 socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv_ptr)
    let ret = call_target_function(
        pid,
        offsets.socketpair,
        &[1, 1, 0, sv_addr],
        None,
    )
    .map_err(|e| format!("调用 socketpair 失败: {}", e))?;

    if ret as isize != 0 {
        return Err(format!("socketpair 返回错误: {}", ret as isize));
    }

    // 读回 fd0, fd1
    let sv: [i32; 2] = read_memory(pid, sv_addr)?;
    log_verbose!("socketpair 创建成功: fd0={}, fd1={}", sv[0], sv[1]);

    // 释放临时缓冲区
    let _ = call_target_function(pid, offsets.free, &[sv_addr], None);

    Ok((sv[0], sv[1]))
}

// aarch64 syscall numbers
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;

/// 通过 pidfd_getfd 从目标进程提取文件描述符到 host
fn extract_fd_from_target(pid: i32, target_fd: i32) -> Result<RawFd, String> {
    // pidfd_open(pid, flags=0)
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if pidfd < 0 {
        return Err(format!(
            "pidfd_open({}) 失败: {}",
            pid,
            std::io::Error::last_os_error()
        ));
    }

    // pidfd_getfd(pidfd, target_fd, flags=0)
    let host_fd = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd as i32, target_fd, 0u32) };
    unsafe { close(pidfd as i32) };

    if host_fd < 0 {
        return Err(format!(
            "pidfd_getfd(pid={}, fd={}) 失败: {}",
            pid,
            target_fd,
            std::io::Error::last_os_error()
        ));
    }

    log_verbose!("pidfd_getfd: pid={} target_fd={} → host_fd={}", pid, target_fd, host_fd);
    Ok(host_fd as RawFd)
}

/// 在目标进程中调用 memfd_create()，返回目标进程内的 fd 号
fn create_memfd_in_target(pid: i32, offsets: &LibcOffsets) -> Result<i32, String> {
    let name = b"jit-cache\0";
    let name_addr = call_target_function(pid, offsets.malloc, &[name.len()], None)
        .map_err(|e| format!("分配 memfd name 内存失败: {}", e))?;
    write_bytes(pid, name_addr, name)?;

    // 调用 memfd_create(name, flags=0)
    let ret = call_target_function(pid, offsets.memfd_create, &[name_addr, 0], None)
        .map_err(|e| format!("调用 memfd_create 失败: {}", e))?;

    // 释放临时 name 缓冲区
    let _ = call_target_function(pid, offsets.free, &[name_addr], None);

    let fd = ret as i32;
    if fd < 0 {
        return Err(format!("memfd_create 返回错误: {}", fd));
    }

    log_verbose!("目标进程 memfd_create 成功: fd={}", fd);
    Ok(fd)
}

/// RAII guard: 注入失败时自动关闭 host_fd 并 detach 目标进程
struct InjectionGuard {
    pid: i32,
    host_fd: RawFd,
    disarmed: bool,
}

impl InjectionGuard {
    fn new(pid: i32, host_fd: RawFd) -> Self {
        Self { pid, host_fd, disarmed: false }
    }

    /// 注入成功，取走 host_fd，不再自动清理
    fn into_fd(mut self) -> RawFd {
        self.disarmed = true;
        self.host_fd
    }
}

impl Drop for InjectionGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            unsafe { close(self.host_fd) };
            let _ = ptrace::detach(Pid::from_raw(self.pid), None);
        }
    }
}

/// 注入 agent 到目标进程，返回 host_fd（socketpair 的 host 端）
pub(crate) fn inject_to_process(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    log_info!("正在附加到进程 PID: {}", pid);

    // 获取自身和目标进程的 libc / libdl 基址
    let self_base = get_lib_base(None, "libc.so")?;
    let target_base = get_lib_base(Some(pid), "libc.so")?;
    let self_dl_base = get_lib_base(None, "libdl.so")?;
    let target_dl_base = get_lib_base(Some(pid), "libdl.so")?;

    log_verbose!("自身 libc.so 基址: 0x{:x}", self_base);
    log_verbose!("目标进程 libc.so 基址: 0x{:x}", target_base);
    log_verbose!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
    log_verbose!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);

    // 计算目标进程中的函数地址
    let offsets = LibcOffsets::calculate(self_base, target_base)?;
    let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base)?;

    // 打印所有函数地址（仅 verbose 模式）
    if crate::logger::is_verbose() {
        offsets.print_offsets();
        dl_offsets.print_offsets();
    }

    // 附加到目标进程
    attach_to_process(pid)?;

    // === socketpair 通道建立 ===
    // 1. 在目标进程中创建 socketpair
    let (fd0, fd1) = create_socketpair_in_target(pid, &offsets)?;

    // 2. 通过 pidfd_getfd 提取 fd0 到 host
    let host_fd = extract_fd_from_target(pid, fd0)?;
    // RAII guard: 后续任何 ? 返回都会自动 close(host_fd) + detach
    let guard = InjectionGuard::new(pid, host_fd);

    // 3. 在目标进程中关闭 fd0（host 已复制，目标只保留 fd1）
    let _ = call_target_function(pid, offsets.close, &[fd0 as usize], None);
    log_verbose!("目标进程 fd0={} 已关闭，fd1={} 保留给 agent", fd0, fd1);

    // 4. 在目标进程中创建 memfd，pidfd_getfd 提取到 host，写入 agent.so
    let target_memfd = create_memfd_in_target(pid, &offsets)?;
    let host_memfd = extract_fd_from_target(pid, target_memfd)?;
    log_verbose!("已提取目标 memfd: target_fd={} → host_fd={}", target_memfd, host_memfd);

    // 写入 AGENT_SO 数据到 host_memfd
    let mut written = 0usize;
    while written < AGENT_SO.len() {
        let ret = unsafe {
            libc_write(
                host_memfd,
                AGENT_SO[written..].as_ptr() as *const c_void,
                AGENT_SO.len() - written,
            )
        };
        if ret >= 0 {
            written += ret as usize;
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { close(host_memfd) };
            return Err(format!("写入 agent.so 到 memfd 失败: {}", err));
        }
    }
    unsafe { close(host_memfd) };
    log_verbose!("agent.so ({} bytes) 已写入目标进程 memfd", AGENT_SO.len());

    // === 分配并写入注入数据 ===
    log_verbose!("开始分配内存");

    // 分配内存用于shellcode
    let page_size = 4096;
    let shellcode_len = ((SHELLCODE.len() + page_size - 1) / page_size) * page_size;
    let mmap_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let mmap_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let shellcode_addr = call_target_function(
        pid,
        offsets.mmap,
        &[
            0, // addr = NULL，让内核分配
            shellcode_len,
            mmap_prot as usize,
            mmap_flags as usize,
            !0usize, // fd = -1
            0,       // offset = 0
        ],
        None,
    )
    .map_err(|e| format!("调用 mmap 失败: {}", e))?;

    log_verbose!("分配shellcode内存");
    log_verbose_addr!("地址", shellcode_addr);

    // 写入shellcode
    write_bytes(pid, shellcode_addr, SHELLCODE)?;
    log_verbose!("Shellcode写入成功");
    log_verbose_addr!("地址", shellcode_addr);

    // 分配并写入 LibcOffsets / DlOffsets 结构体
    let offsets_addr = alloc_and_write_struct(pid, offsets.malloc, &offsets, "offsets")?;
    let dloffset_addr = alloc_and_write_struct(pid, offsets.malloc, &dl_offsets, "dloffsets")?;

    // 写入字符串表
    let string_table_addr = write_string_table(pid, offsets.malloc, string_overrides)?;
    log_verbose!("字符串表写入成功");
    log_verbose_addr!("地址", string_table_addr);

    // 分配并写入 AgentArgs
    let agent_args = AgentArgs {
        table: string_table_addr as u64,
        ctrl_fd: fd1,
        agent_memfd: target_memfd,
    };
    let agent_args_addr = alloc_and_write_struct(pid, offsets.malloc, &agent_args, "AgentArgs")?;

    // 使用 call_target_function 调用 shellcode（4 参数）
    match call_target_function(
        pid,
        shellcode_addr,
        &[offsets_addr, dloffset_addr, string_table_addr, agent_args_addr],
        None,
    ) {
        Ok(return_value) => {
            // shellcode_entry 返回 int (32位)，ARM64 X0 高 32 位为 0，
            // 需先截断为 i32 再符号扩展，否则 -3 变成 0x00000000FFFFFFFD
            let ret = return_value as u32 as i32 as isize;
            log_verbose!("Shellcode 执行完成，返回值: 0x{:x}", ret);

            // 检查 shellcode 返回值（1 = 成功，负数 = 失败）
            if ret != 1 {
                let reason = match ret {
                    -3 => "（已废弃，不应出现）",
                    -5 => "android_dlopen_ext 失败（SO 加载失败）",
                    -6 => "pthread_create 失败（无法创建 agent 线程）",
                    -7 => "dlsym 失败（未找到 hello_entry 符号）",
                    _ => "未知错误",
                };
                // 清理 shellcode 内存
                let _ = call_target_function(pid, offsets.munmap, &[shellcode_addr, shellcode_len], None);
                let _ = ptrace::detach(Pid::from_raw(pid), None);
                let fd = guard.into_fd();
                unsafe { close(fd) };
                return Err(format!("Shellcode 执行失败 ({}): {}", ret, reason));
            }

            // 释放shellcode内存
            log_verbose!("正在释放shellcode内存...");
            match call_target_function(pid, offsets.munmap, &[shellcode_addr, shellcode_len], None)
            {
                Ok(_) => log_verbose!("Shellcode内存释放成功"),
                Err(e) => log_error!("释放shellcode内存失败: {}", e),
            }

            // detach 目标进程（guard.into_fd 阻止自动 detach）
            if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
                log_error!("分离目标进程失败: {}", e);
            } else {
                log_success!("已分离目标进程");
            }
            Ok(guard.into_fd())
        }
        Err(e) => {
            log_error!("执行 shellcode 失败: {}", e);
            log_warn!("暂停目标进程，等待调试器附加...");
            // 特殊处理：关闭 host_fd 但发 SIGSTOP（不走 guard 默认的 detach）
            let fd = guard.into_fd();
            unsafe { close(fd) };
            let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
            Err(e)
        }
    }
}

/// 根据 UID 查找 /data/data/ 目录下对应的应用数据目录
fn find_data_dir_by_uid(uid: u32) -> Option<String> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let data_dir = "/data/data";

    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.uid() == uid {
                        if let Some(path) = entry.path().to_str() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            log_error!("读取 /data/data 目录失败: {}", e);
            None
        }
    }
}

/// 使用 eBPF 监听 SO 加载并自动附加
pub(crate) fn watch_and_inject(
    so_pattern: &str,
    timeout_secs: Option<u64>,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<RawFd, String> {
    use ldmonitor::DlopenMonitor;
    use std::time::Duration;

    log_info!("正在启动 eBPF 监听器，等待加载: {}", so_pattern);

    let monitor = DlopenMonitor::new(None).map_err(|e| format!("启动 eBPF 监听失败: {}", e))?;

    let info = if let Some(secs) = timeout_secs {
        log_info!("超时时间: {} 秒", secs);
        monitor.wait_for_path_timeout(so_pattern, Duration::from_secs(secs))
    } else {
        log_info!("无超时限制，持续监听中...");
        monitor.wait_for_path(so_pattern)
    };

    monitor.stop();

    match info {
        Some(dlopen_info) => {
            let pid = dlopen_info.pid();
            if let Some(ns_pid) = dlopen_info.ns_pid {
                if ns_pid != dlopen_info.host_pid {
                    log_success!(
                        "检测到 SO 加载: pid={} (host_pid={}), uid={}, path={}",
                        ns_pid,
                        dlopen_info.host_pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                } else {
                    log_success!(
                        "检测到 SO 加载: pid={}, uid={}, path={}",
                        pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                }
            } else {
                log_success!(
                    "检测到 SO 加载: host_pid={}, uid={}, path={}",
                    dlopen_info.host_pid,
                    dlopen_info.uid,
                    dlopen_info.path
                );
            }

            // 克隆 string_overrides 以便修改
            let mut overrides = string_overrides.clone();

            // 根据 uid 自动检测 /data/data/ 目录
            if let Some(data_dir) = find_data_dir_by_uid(dlopen_info.uid) {
                log_info!("自动检测到应用数据目录: {}", data_dir);
                overrides.insert("output_path".to_string(), data_dir);
            } else {
                log_warn!("未能找到 uid {} 对应的 /data/data/ 目录", dlopen_info.uid);
            }

            inject_to_process(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string()),
    }
}
