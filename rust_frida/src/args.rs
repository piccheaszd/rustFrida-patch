#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use clap::{ArgGroup, Parser, ValueEnum};

#[cfg(not(feature = "noptrace"))]
fn parse_pid(s: &str) -> std::result::Result<i32, String> {
    match s.parse::<i32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("PID 必须是正整数".to_string()),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum QuickJsProfile {
    /// Full Frida-compatible API surface.
    Full,
    /// Minimal API surface for hardened apps that crash during optional bootstraps.
    Minimal,
    /// Minimal API surface with fail-closed hardening checks.
    Hardened,
}

impl QuickJsProfile {
    pub(crate) fn as_agent_value(self) -> &'static str {
        match self {
            QuickJsProfile::Full => "full",
            QuickJsProfile::Minimal => "minimal",
            QuickJsProfile::Hardened => "hardened",
        }
    }
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[cfg_attr(
    not(feature = "noptrace"),
    command(
    author,
    version,
    about = "ARM64 Android 动态插桩工具，支持 ptrace 注入和 pure spawn 自加载 agent",
    long_about = "\
ARM64 Android 动态插桩工具。支持 ptrace 注入 agent.so 或 pure spawn 自加载 agent，\
支持 QuickJS 脚本执行、inline hook、Frida Stalker 追踪等功能。

常见用法:
  rustfrida --pid 1234                         # 注入到指定 PID
  rustfrida --name com.example.app             # 按进程名注入
  rustfrida --watch-so libnative.so            # 等待 SO 加载后自动注入
  rustfrida --spawn com.example.app            # 普通 Spawn：冷启动后再按 PID attach，适合 REPL
  rustfrida --spawn com.example.app --spawn-pure # Pure Spawn：子进程自加载 loader/agent，不 ptrace 子进程
  rustfrida --spawn com.example.app -l early.js # Early Spawn：恢复前加载脚本，抢早期 hook
  rustfrida --spawn com.example.app --spawn-early # 强制恢复前注入（无脚本也 early）
  rustfrida --spawn com.example.app -l hook.js --spawn-late # 强制冷启动后加载脚本
  rustfrida --pid 1234 -l script.js            # 注入并执行 JS 脚本
  rustfrida --pid 1234 --verbose               # 显示详细注入调试信息

属性伪装:
  rustfrida --dump-props default                                    # Dump 属性快照
  rustfrida --set-prop default ro.build.fingerprint=google/...      # 修改属性值
  rustfrida --set-prop default ro.debuggable=0                      # 可多次调用
  rustfrida --spawn com.app --profile default                       # Spawn 并应用

Server daemon 模式（多 session 并发）:
  rustfrida --server                                                # 启动 server
  rustfrida --server --profile default                              # 启动 + 属性伪装持续生效

注入后进入 REPL，输入 help 查看可用命令（jsinit / loadjs / jsrepl / jhook 等）。",
    group(ArgGroup::new("target").required(true).args(["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop", "repack_props", "server"]))
    )
)]
#[cfg_attr(
    feature = "noptrace",
    command(
        author,
        version,
        about = "ARM64 Android pure spawn 动态插桩工具",
        long_about = "\
ARM64 Android pure spawn 动态插桩工具。子进程从 zymbiote socket 接收 stage-1 loader、agent.so 和脚本，\
host 不读写目标 App 子进程寄存器或 /proc/<pid>/mem。

常见用法:
  rustfrida --spawn com.example.app --spawn-pure                 # Pure Spawn：子进程自加载 loader/agent
  rustfrida --spawn com.example.app --spawn-pure -l early.js      # 恢复前通过 agent socket 加载脚本

属性伪装:
  rustfrida --dump-props default
  rustfrida --set-prop default ro.build.fingerprint=google/...
  rustfrida --del-prop default ro.debuggable
  rustfrida --repack-props default

注入后进入 REPL，输入 help 查看可用命令。",
        group(ArgGroup::new("target").required(true).args(["spawn", "dump_props", "set_prop", "del_prop", "repack_props"]))
    )
)]
pub(crate) struct Args {
    /// 目标进程的PID（与 --watch-so、--name、--spawn 互斥）
    #[cfg(not(feature = "noptrace"))]
    #[arg(
        short,
        long,
        conflicts_with_all = ["watch_so", "name", "spawn"],
        allow_hyphen_values = true,
        value_parser = parse_pid
    )]
    pub(crate) pid: Option<i32>,

    /// 监听指定 SO 路径加载，自动附加到加载该 SO 的进程（需要 ldmonitor eBPF 组件：cargo build -p ldmonitor）
    #[cfg(not(feature = "noptrace"))]
    #[arg(short = 'w', long = "watch-so", conflicts_with_all = ["name", "spawn"])]
    pub(crate) watch_so: Option<String>,

    /// 按进程名注入（与 --pid、--watch-so、--spawn 互斥）
    #[cfg(not(feature = "noptrace"))]
    #[arg(short = 'n', long = "name", conflicts_with = "spawn")]
    pub(crate) name: Option<String>,

    /// Spawn 模式：不带 -l 时冷启动后再 attach；带 -l 时默认恢复前加载脚本，确保能 hook 到 Application.onCreate() 等早期代码
    #[cfg_attr(not(feature = "noptrace"), arg(short = 'f', long = "spawn"))]
    #[cfg_attr(
        feature = "noptrace",
        arg(
            short = 'f',
            long = "spawn",
            requires = "spawn_pure",
            help = "Pure Spawn 目标包名；noptrace 构建下必须配合 --spawn-pure"
        )
    )]
    pub(crate) spawn: Option<String>,

    /// Spawn early 模式：即使不带 -l，也在子进程恢复前注入（抢早期窗口，稳定性弱于 late）
    #[cfg(not(feature = "noptrace"))]
    #[arg(long = "spawn-early", requires = "spawn", conflicts_with = "spawn_late")]
    pub(crate) spawn_early: bool,

    /// Spawn late 模式：即使带 -l，也先恢复 App，等待主线程进入 Looper 后再按 PID attach（稳定优先，不保证早期 hook）
    #[cfg(not(feature = "noptrace"))]
    #[arg(long = "spawn-late", requires = "spawn", conflicts_with = "spawn_early")]
    pub(crate) spawn_late: bool,

    /// Pure Spawn 模式：子进程从 zymbiote socket 接收 loader/agent 并自加载，不调用 ptrace 注入子进程
    #[cfg_attr(
        not(feature = "noptrace"),
        arg(long = "spawn-pure", requires = "spawn", conflicts_with = "spawn_late")
    )]
    #[cfg_attr(feature = "noptrace", arg(long = "spawn-pure", requires = "spawn"))]
    pub(crate) spawn_pure: bool,

    /// 监听超时时间（秒），默认无限等待
    #[arg(short = 't', long = "timeout")]
    pub(crate) timeout: Option<u64>,

    /// 等待 agent 连接的超时时间（秒），默认 10 秒
    #[arg(long = "connect-timeout", default_value = "10")]
    pub(crate) connect_timeout: u64,

    /// 覆盖字符串表中的指定值（可多次使用），格式: name=value
    ///
    /// 可用名称及用途:
    ///   sym_name     — loader 查找的导出符号（高级调试）
    ///   dlsym_err    — dlsym 调用错误消息前缀
    ///   cmdline      — procfs cmdline 路径
    ///   output_path  — 日志输出路径
    #[arg(short = 's', long = "string", value_name = "NAME=VALUE")]
    pub(crate) strings: Vec<String>,

    /// 加载并执行JavaScript脚本文件
    #[arg(short = 'l', long = "load-script", value_name = "FILE")]
    pub(crate) load_script: Option<String>,

    /// QuickJS API profile: full keeps all APIs; minimal skips optional JS bootstraps/Module/Java
    #[arg(long = "quickjs-profile", value_enum, default_value_t = QuickJsProfile::Full)]
    pub(crate) quickjs_profile: QuickJsProfile,

    /// 显示详细注入信息（地址、偏移等）
    #[arg(short = 'v', long = "verbose")]
    pub(crate) verbose: bool,

    /// 同步写入日志到指定文件（终端仍正常输出）
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub(crate) output: Option<String>,

    /// Dump 本机属性到 profile（独立操作，不注入进程）
    ///
    /// 复制 /dev/__properties__/ 二进制文件到 profile 目录，
    /// 之后用 --set-prop 修改单个属性值。
    #[cfg_attr(
        not(feature = "noptrace"),
        arg(
        long = "dump-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "set_prop"]
        )
    )]
    #[cfg_attr(
        feature = "noptrace",
        arg(long = "dump-props", value_name = "PROFILE", conflicts_with_all = ["spawn", "set_prop"])
    )]
    pub(crate) dump_props: Option<String>,

    /// 修改 profile 中的属性值（类似 magisk resetprop）
    ///
    /// 直接 patch profile 目录中的二进制属性区域文件。可多次调用设置不同属性。
    /// 格式: --set-prop <PROFILE> <key=value>
    #[cfg_attr(
        not(feature = "noptrace"),
        arg(
        long = "set-prop",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY=VALUE"]
        )
    )]
    #[cfg_attr(
        feature = "noptrace",
        arg(
            long = "set-prop",
            value_name = "PROFILE",
            conflicts_with_all = ["spawn", "dump_props"],
            num_args = 2,
            value_names = ["PROFILE", "KEY=VALUE"]
        )
    )]
    pub(crate) set_prop: Option<Vec<String>>,

    /// 删除 profile 中的属性
    ///
    /// 清零属性值和 serial，使属性不可读。
    /// 格式: --del-prop <PROFILE> <key>
    #[cfg_attr(
        not(feature = "noptrace"),
        arg(
        long = "del-prop",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "repack_props"],
        num_args = 2,
        value_names = ["PROFILE", "KEY"]
        )
    )]
    #[cfg_attr(
        feature = "noptrace",
        arg(
            long = "del-prop",
            conflicts_with_all = ["spawn", "dump_props", "set_prop", "repack_props"],
            num_args = 2,
            value_names = ["PROFILE", "KEY"]
        )
    )]
    pub(crate) del_prop: Option<Vec<String>>,

    /// 重排 profile 消除空洞（重新 dump + 重放变更日志）
    #[cfg_attr(
        not(feature = "noptrace"),
        arg(
        long = "repack-props",
        value_name = "PROFILE",
        conflicts_with_all = ["pid", "watch_so", "name", "spawn", "dump_props", "set_prop", "del_prop"]
        )
    )]
    #[cfg_attr(
        feature = "noptrace",
        arg(
            long = "repack-props",
            value_name = "PROFILE",
            conflicts_with_all = ["spawn", "dump_props", "set_prop", "del_prop"]
        )
    )]
    pub(crate) repack_props: Option<String>,

    /// 指定属性覆盖 profile（--spawn 或 --server 模式可用）
    #[cfg(not(feature = "noptrace"))]
    #[arg(long = "profile", value_name = "NAME")]
    pub(crate) profile: Option<String>,

    /// Server daemon 模式：多 session 并发 spawn/inject，profile 持续生效
    ///
    /// 启动后进入 server REPL，支持同时管理多个注入 session。
    /// 配合 --profile 使用可在整个 server 生命周期内持续生效。
    #[cfg(not(feature = "noptrace"))]
    #[arg(long = "server", conflicts_with_all = ["pid", "watch_so", "name", "spawn"])]
    pub(crate) server: bool,

    /// 启动 HTTP RPC 服务器，暴露 agent 端 `rpc.exports` 注册的方法。
    ///
    /// 格式: --rpc-port <PORT> 或 --rpc-port <HOST:PORT>（默认绑定 0.0.0.0）。
    /// 路由：
    ///   GET  /sessions                        列出 session
    ///   POST /rpc/<session>/<method>          调用 rpc.exports[method]，请求体为 JSON 参数数组
    ///
    /// 在 legacy 单会话模式下 session_id 为 0；多会话 daemon 模式下为 list 命令显示的 id。
    #[arg(long = "rpc-port", value_name = "PORT_OR_ADDR")]
    pub(crate) rpc_port: Option<String>,
}
