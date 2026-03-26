#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use clap::{ArgGroup, Parser};

fn parse_pid(s: &str) -> std::result::Result<i32, String> {
    match s.parse::<i32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("PID 必须是正整数".to_string()),
    }
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "ARM64 Android 动态插桩工具，通过 ptrace 注入 agent.so，支持 QuickJS 脚本/inline hook/Frida Stalker",
    long_about = "\
ARM64 Android 动态插桩工具。通过 ptrace 注入 agent.so 到目标进程，支持 QuickJS 脚本执行、\
inline hook、Frida Stalker 追踪等功能。

常见用法:
  rustfrida --pid 1234                         # 注入到指定 PID
  rustfrida --name com.example.app             # 按进程名注入
  rustfrida --watch-so libnative.so            # 等待 SO 加载后自动注入
  rustfrida --spawn com.example.app            # Spawn 模式：启动前注入
  rustfrida --pid 1234 -l script.js            # 注入并执行 JS 脚本
  rustfrida --pid 1234 --verbose               # 显示详细注入调试信息

属性伪装:
  rustfrida --dump-props default                                    # Dump 属性快照
  rustfrida --set-prop default ro.build.fingerprint=google/...      # 修改属性值
  rustfrida --set-prop default ro.debuggable=0                      # 可多次调用
  rustfrida --spawn com.app --profile default                       # Spawn 并应用

注入后进入 REPL，输入 help 查看可用命令（jsinit / loadjs / jsrepl / jhook 等）。",
    group(ArgGroup::new("target").required(true).args(["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop", "repack_props"]))
)]
pub(crate) struct Args {
    /// 目标进程的PID（与 --watch-so、--name、--spawn 互斥）
    #[arg(
        short,
        long,
        conflicts_with_all = ["watch_so", "name", "spawn"],
        allow_hyphen_values = true,
        value_parser = parse_pid
    )]
    pub(crate) pid: Option<i32>,

    /// 监听指定 SO 路径加载，自动附加到加载该 SO 的进程（需要 ldmonitor eBPF 组件：cargo build -p ldmonitor）
    #[arg(short = 'w', long = "watch-so", conflicts_with_all = ["name", "spawn"])]
    pub(crate) watch_so: Option<String>,

    /// 按进程名注入（与 --pid、--watch-so、--spawn 互斥）
    #[arg(short = 'n', long = "name", conflicts_with = "spawn")]
    pub(crate) name: Option<String>,

    /// Spawn 模式：启动 App 前注入，确保能 hook 到 Application.onCreate() 等早期代码
    #[arg(short = 'f', long = "spawn")]
    pub(crate) spawn: Option<String>,

    /// 监听超时时间（秒），默认无限等待
    #[arg(short = 't', long = "timeout")]
    pub(crate) timeout: Option<u64>,

    /// 等待 agent 连接的超时时间（秒），默认 30 秒
    #[arg(long = "connect-timeout", default_value = "30")]
    pub(crate) connect_timeout: u64,

    /// 覆盖字符串表中的指定值（可多次使用），格式: name=value
    ///
    /// 可用名称及用途:
    ///   sym_name     — loader 查找的导出符号（高级调试）
    ///   pthread_err  — pthread 库错误消息前缀
    ///   dlsym_err    — dlsym 调用错误消息前缀
    ///   cmdline      — procfs cmdline 路径
    ///   output_path  — 日志输出路径
    #[arg(short = 's', long = "string", value_name = "NAME=VALUE")]
    pub(crate) strings: Vec<String>,

    /// 加载并执行JavaScript脚本文件
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    pub(crate) load_script: Option<String>,

    /// 显示详细注入信息（地址、偏移等）
    #[arg(short = 'v', long = "verbose")]
    pub(crate) verbose: bool,

    /// Dump 本机属性到 profile（独立操作，不注入进程）
    ///
    /// 复制 /dev/__properties__/ 二进制文件到 profile 目录，
    /// 之后用 --set-prop 修改单个属性值。
    #[arg(
        long = "dump-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "set_prop"]
    )]
    pub(crate) dump_props: Option<String>,

    /// 修改 profile 中的属性值（类似 magisk resetprop）
    ///
    /// 直接 patch profile 目录中的二进制属性区域文件。可多次调用设置不同属性。
    /// 格式: --set-prop <PROFILE> <key=value>
    #[arg(
        long = "set-prop",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY=VALUE"]
    )]
    pub(crate) set_prop: Option<Vec<String>>,

    /// 删除 profile 中的属性
    ///
    /// 清零属性值和 serial，使属性不可读。
    /// 格式: --del-prop <PROFILE> <key>
    #[arg(
        long = "del-prop",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "repack_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY"]
    )]
    pub(crate) del_prop: Option<Vec<String>>,

    /// 重排 profile 消除空洞（重新 dump + 重放变更日志）
    #[arg(
        long = "repack-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop"]
    )]
    pub(crate) repack_props: Option<String>,

    /// 指定属性覆盖 profile（仅 --spawn 模式可用）
    #[arg(long = "profile", value_name = "NAME", requires = "spawn")]
    pub(crate) profile: Option<String>,
}
