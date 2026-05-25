#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use std::time::Duration;

use crate::proc_mem::ProcMem;
use crate::process::{
    attach_to_process, call_target_function_with_return_trap, parse_proc_maps, sample_thread_stop_point,
    ThreadStopSample,
};
use crate::types::{bootstrap_status, message_type, FridaBootstrapContext, FridaLibcApi, RustFridaLoaderContext};
use crate::{log_error, log_info, log_success, log_verbose, log_warn};

pub(crate) const BOOTSTRAPPER: &[u8] = include_bytes!("../../loader/build/bootstrapper.bin");
pub(crate) const FRIDA_LOADER: &[u8] = include_bytes!("../../loader/build/rustfrida-loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] = include_bytes!("../../target/aarch64-linux-android/release/libagent.so");

#[cfg(feature = "qbdi")]
pub(crate) const QBDI_HELPER_SO: &[u8] = include_bytes!(env!("QBDI_HELPER_SO_PATH"));

// aarch64 syscall numbers
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;
const PAGE_SIZE: u64 = 4096;

fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

fn padded_agent_memfd_len() -> Result<usize, String> {
    let elf = goblin::elf::Elf::parse(AGENT_SO).map_err(|e| format!("解析 agent ELF 失败: {}", e))?;
    let mut len = AGENT_SO.len() as u64;

    for phdr in elf
        .program_headers
        .iter()
        .filter(|phdr| phdr.p_type == goblin::elf::program_header::PT_LOAD && phdr.p_memsz != 0)
    {
        let seg_start = align_down(phdr.p_vaddr, PAGE_SIZE);
        let seg_end = align_up(phdr.p_vaddr + phdr.p_memsz, PAGE_SIZE);
        let file_page_start = align_down(phdr.p_offset, PAGE_SIZE);
        let required = file_page_start + (seg_end - seg_start);
        len = len.max(required);
    }

    usize::try_from(len).map_err(|_| "agent padded memfd 长度溢出".to_string())
}

fn mem_write_value<T>(mem: &ProcMem, addr: usize, value: &T) -> Result<(), String> {
    let bytes = unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) };
    mem.pwrite_all(bytes, addr as u64)
}

fn mem_read_value<T: Default>(mem: &ProcMem, addr: usize) -> Result<T, String> {
    let mut value = T::default();
    let bytes = unsafe { std::slice::from_raw_parts_mut(&mut value as *mut T as *mut u8, size_of::<T>()) };
    mem.pread_exact(bytes, addr as u64)?;
    Ok(value)
}

const MPROTECT_SYSCALL_STUB: &[u8] = &[
    0x48, 0x1c, 0x80, 0xd2, // mov x8, #226 (__NR_mprotect)
    0x01, 0x00, 0x00, 0xd4, // svc #0
    0xc0, 0x03, 0x5f, 0xd6, // ret
];
const BRK_RETURN_TRAP: &[u8] = &[
    0x00, 0x00, 0x20, 0xd4, // brk #0
];

fn call_target_function_brk(
    mem: &ProcMem,
    tid: i32,
    func_addr: usize,
    args: &[usize],
    return_trap_addr: usize,
) -> Result<usize, String> {
    mem.pwrite_all(BRK_RETURN_TRAP, return_trap_addr as u64)?;
    call_target_function_with_return_trap(tid, func_addr, args, return_trap_addr)
}

fn remote_mprotect_syscall(
    mem: &ProcMem,
    tid: i32,
    swap_addr: usize,
    original_code: &[u8],
    return_trap_addr: usize,
    addr: usize,
    len: usize,
    prot: i32,
) -> Result<(), String> {
    mem.pwrite_all(MPROTECT_SYSCALL_STUB, swap_addr as u64)?;
    let result = call_target_function_with_return_trap(tid, swap_addr, &[addr, len, prot as usize], return_trap_addr);
    let restore_result = mem.pwrite_all(original_code, swap_addr as u64);
    restore_result?;

    let ret = result?;
    if ret != 0 {
        return Err(format!(
            "remote mprotect syscall(0x{:x}, {}, 0x{:x}) returned {}",
            addr, len, prot, ret
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct InjectionResult {
    pub(crate) host_fd: RawFd,
    pub(crate) target_pid: i32,
    pub(crate) loader_ctx_addr: u64,
    pub(crate) agent_current_thread_eval_impl: u64,
}

/// 通过 pidfd_getfd 从目标进程提取文件描述符到 host
fn extract_fd_from_target(pid: i32, target_fd: i32) -> Result<RawFd, String> {
    // pidfd_open(pid, flags=0)
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if pidfd < 0 {
        return Err(format!("pidfd_open({}) 失败: {}", pid, std::io::Error::last_os_error()));
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

/// 设置 fd 的 SELinux label，使 untrusted_app 能通过 SCM_RIGHTS 接收。
///
/// Android MLS/MCS 会阻止 untrusted_app (带 categories) 访问 tmpfs:s0 (无 categories)。
/// 修复：读取目标进程的 SELinux context 提取 MLS range（如 s0:c15,c257,c512,c768），
/// 用目标的 MLS categories + tmpfs 类型标记 memfd。
///
/// 注意：不使用 frida_memfd 类型——即使该类型存在（Frida 残留），其 MLS range
/// 定义可能不完整，导致 fsetxattr 返回 0 但 kernel 无法验证 context、退回 unlabeled:s0。
/// tmpfs 是原生类型，天然支持所有 MLS ranges，且 selinux.rs 已有 TE allow 规则。
fn relabel_fd_for_injection(fd: RawFd, target_pid: i32) {
    // 读取目标进程的 MLS range
    let mls = read_target_mls_range(target_pid).unwrap_or_else(|| "s0".to_string());

    // tmpfs 优先（memfd 底层就是 tmpfs），然后 app_data_file
    let labels = [
        format!("u:object_r:tmpfs:{}", mls),
        format!("u:object_r:app_data_file:{}", mls),
    ];
    for label in &labels {
        let label_cstr = format!("{}\0", label);
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                c"security.selinux".as_ptr(),
                label_cstr.as_ptr() as *const c_void,
                label_cstr.len() - 1, // 不包含 NUL
                0,
            )
        };
        if ret == 0 {
            // 验证 label 是否真正生效（防止 fsetxattr 假成功、kernel 退回 unlabeled）
            let mut readback = [0u8; 128];
            let n = unsafe {
                libc::fgetxattr(
                    fd,
                    c"security.selinux".as_ptr(),
                    readback.as_mut_ptr() as *mut c_void,
                    readback.len(),
                )
            };
            if n > 0 {
                let actual = std::str::from_utf8(&readback[..n as usize])
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if actual.contains("unlabeled") {
                    log_verbose!("memfd SELinux label {} → kernel 退回 unlabeled，尝试下一个", label);
                    continue;
                }
            }
            log_verbose!("memfd SELinux label → {}", label);
            return;
        }
    }
    log_verbose!("memfd SELinux relabel 全部失败，使用默认 tmpfs label");
}

/// 读取目标进程的 SELinux MLS range（例如 "s0:c15,c257,c512,c768"）
fn read_target_mls_range(pid: i32) -> Option<String> {
    let ctx = std::fs::read_to_string(format!("/proc/{}/attr/current", pid)).ok()?;
    let ctx = ctx.trim_end_matches('\0').trim();
    // 格式: u:r:untrusted_app:s0:c15,c257,c512,c768
    // MLS range 从第 4 个 ':' 分隔的字段开始（可能包含多个 ':'）
    let mut parts = ctx.splitn(4, ':');
    let _user = parts.next()?;
    let _role = parts.next()?;
    let _type = parts.next()?;
    let mls = parts.next()?;
    if mls.is_empty() {
        return None;
    }
    Some(mls.to_string())
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn env_value_enabled(value: &str) -> bool {
    value != "0" && !value.eq_ignore_ascii_case("false")
}

fn use_stream_agent_transfer() -> bool {
    if let Ok(mode) = std::env::var("RF_AGENT_TRANSFER") {
        let mode = mode.trim();
        if mode.eq_ignore_ascii_case("memfd")
            || mode.eq_ignore_ascii_case("fd")
            || mode == "0"
            || mode.eq_ignore_ascii_case("false")
            || mode.eq_ignore_ascii_case("off")
        {
            return false;
        }
        if mode.eq_ignore_ascii_case("stream")
            || mode.eq_ignore_ascii_case("socket")
            || mode.eq_ignore_ascii_case("pipe")
            || mode == "1"
            || mode.eq_ignore_ascii_case("true")
        {
            return true;
        }
        log_warn!("未知 RF_AGENT_TRANSFER={}，默认使用 stream agent 传输", mode);
        return true;
    }

    if let Ok(value) = std::env::var("RF_STREAM_AGENT") {
        return env_value_enabled(&value);
    }

    !env_flag_enabled("RF_AGENT_MEMFD")
}

fn build_loader_agent_data(use_pthread_loader: bool) -> Result<Vec<u8>, String> {
    let mut tokens = Vec::new();

    if use_pthread_loader {
        tokens.push("pthread".to_string());
    }

    let close_loader_ctrl = match std::env::var("RF_CLOSE_LOADER_CTRL") {
        Ok(value) => env_value_enabled(&value),
        Err(_) => !env_flag_enabled("RF_KEEP_LOADER_CTRL"),
    };
    if close_loader_ctrl {
        log_verbose!("loader ctrl fd: 进入 agent 前关闭");
        tokens.push("close-ctrl".to_string());
    }

    if use_stream_agent_transfer() {
        log_verbose!("agent SO transfer: stream over loader control socket");
        tokens.push("stream-agent".to_string());
    } else {
        log_verbose!("agent SO transfer: memfd over SCM_RIGHTS");
    }

    if env_flag_enabled("RF_LOADER_DEBUG") {
        log_verbose!("loader debug trace: enabled");
        tokens.push("loader-debug".to_string());
    } else {
        log_verbose!("loader debug trace: disabled (set RF_LOADER_DEBUG=1 for full loader IPC trace)");
    }

    if env_flag_enabled("RF_HOLD_BEFORE_ENTRY") {
        log_verbose!("loader trace: 进入 agent 前保持 3s");
        tokens.push("hold-entry".to_string());
    }

    if env_flag_enabled("RF_CATCH_ENTRY_SIGNALS") {
        log_verbose!("loader trace: 捕获 entry 窗口 native signal");
        tokens.push("catch-signals".to_string());
    }

    if let Ok(name) = std::env::var("RF_AGENT_VMA_NAME") {
        if !name.is_empty() {
            if name.len() > 63 {
                return Err("RF_AGENT_VMA_NAME 最多 63 字节".to_string());
            }
            if !name.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b';') {
                return Err("RF_AGENT_VMA_NAME 仅允许非空白 ASCII，且不能包含分号".to_string());
            }
            log_verbose!("agent VMA name: {}", name);
            tokens.push(format!("vma={}", name));
        }
    }

    let mut data = if tokens.is_empty() {
        Vec::new()
    } else {
        tokens.join(";").into_bytes()
    };
    data.push(0);
    Ok(data)
}

fn build_agent_entrypoint() -> Result<Vec<u8>, String> {
    let name = std::env::var("RF_AGENT_ENTRYPOINT").unwrap_or_else(|_| "hello_entry".to_string());

    if name.is_empty() {
        return Err("RF_AGENT_ENTRYPOINT 不能为空".to_string());
    }
    if name.len() > 127 {
        return Err("RF_AGENT_ENTRYPOINT 最多 127 字节".to_string());
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("RF_AGENT_ENTRYPOINT 仅允许 ASCII 字母、数字和下划线".to_string());
    }
    if name != "hello_entry" {
        log_verbose!("agent entrypoint override: {}", name);
    }

    let mut bytes = name.into_bytes();
    bytes.push(0);
    Ok(bytes)
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
) -> Result<InjectionResult, String> {
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

            inject_via_bootstrapper(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string()),
    }
}

// =============================================================================
// Frida-style 注入：bootstrapper + loader 两阶段
// =============================================================================

/// 在目标进程中找到一个足够大的 r-xp 区域用于 code-swap
/// 优先选择 linker64（所有 Android 进程都有），避免覆盖 libc 的热代码
fn find_executable_region(pid: i32, min_size: usize) -> Result<usize, String> {
    let maps_path = format!("/proc/{}/maps", pid);
    let raw = std::fs::read(&maps_path).map_err(|e| format!("读取 {} 失败: {}", maps_path, e))?;
    let maps = String::from_utf8_lossy(&raw);

    // 优先找 linker64 的 r-xp 段
    for line in maps.lines() {
        if !line.contains("r-xp") {
            continue;
        }
        if !line.contains("linker64") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(range) = parts.first() {
            let mut it = range.split('-');
            if let (Some(start_s), Some(end_s)) = (it.next(), it.next()) {
                let start = usize::from_str_radix(start_s, 16).unwrap_or(0);
                let end = usize::from_str_radix(end_s, 16).unwrap_or(0);
                if end - start >= min_size {
                    return Ok(start);
                }
            }
        }
    }

    // fallback: 任何足够大的 r-xp 区域
    for line in maps.lines() {
        if !line.contains("r-xp") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(range) = parts.first() {
            let mut it = range.split('-');
            if let (Some(start_s), Some(end_s)) = (it.next(), it.next()) {
                let start = usize::from_str_radix(start_s, 16).unwrap_or(0);
                let end = usize::from_str_radix(end_s, 16).unwrap_or(0);
                if end - start >= min_size {
                    return Ok(start);
                }
            }
        }
    }

    Err("未找到可用的 r-xp 区域".into())
}

fn read_task_text(pid: i32, tid: i32, name: &str) -> String {
    std::fs::read_to_string(format!("/proc/{}/task/{}/{}", pid, tid, name))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn thread_state(status: &str) -> char {
    status
        .lines()
        .find_map(|line| line.strip_prefix("State:"))
        .and_then(|state| state.trim().chars().next())
        .unwrap_or('?')
}

fn kernel_wait_reason(value: &str) -> Option<&'static str> {
    const WAIT_PATTERNS: &[(&str, &str)] = &[
        ("get_signal", "signal-path"),
        ("do_signal_stop", "signal-stop"),
        ("futex", "futex-wait"),
        ("ep_poll", "epoll-wait"),
        ("epoll", "epoll-wait"),
        ("poll_schedule", "poll-wait"),
        ("binder", "binder-wait"),
        ("pipe_read", "pipe-read"),
        ("unix_stream_read", "socket-read"),
        ("wait_woken", "kernel-wait"),
        ("io_schedule", "io-wait"),
        ("schedule_timeout", "timeout-wait"),
        ("hrtimer_nanosleep", "nanosleep"),
    ];

    WAIT_PATTERNS
        .iter()
        .find_map(|(needle, reason)| value.contains(needle).then_some(*reason))
}

fn score_probe_presample(pid: i32, tid: i32, comm: &str, state: char, wchan: &str) -> i32 {
    let mut score = 0;
    if tid == pid {
        score -= 2_000;
    }
    match state {
        'R' => score += 300,
        'S' => score += 20,
        'D' => score -= 500,
        'T' | 't' => score -= 250,
        _ => {}
    }
    if let Some(reason) = kernel_wait_reason(wchan) {
        score -= if reason == "signal-path" { 1_500 } else { 350 };
    }
    if is_risky_injection_thread(comm) {
        score -= 10_000;
    }
    score
}

fn score_thread_sample(pid: i32, sample: &ThreadStopSample) -> i32 {
    let mut score = 0;
    let pc_map = sample.pc_map.as_deref().unwrap_or("");
    let lr_map = sample.lr_map.as_deref().unwrap_or("");
    let in_app_code = pc_map.contains("/data/app/") || lr_map.contains("/data/app/");
    let in_libc = pc_map.contains("/libc.so") || lr_map.contains("/libc.so");

    if sample.tid == pid {
        score -= 2_000;
    }
    if sample.pc_is_executable() {
        score += 500;
    } else {
        score -= 600;
    }
    if sample.syscall_before == "running" {
        if in_app_code {
            score -= 350;
        } else {
            score += 120;
        }
    } else if !sample.syscall_before.is_empty() {
        score -= 80;
    }
    if sample.wchan_before == "__arm64_sys_nanosleep" && in_libc {
        score += 180;
    }
    if let Some(reason) = kernel_wait_reason(&sample.wchan_before) {
        score -= match reason {
            "signal-path" | "signal-stop" => 2_000,
            "futex-wait" | "epoll-wait" | "binder-wait" => 500,
            _ => 300,
        };
    }
    if is_risky_injection_thread(&sample.comm) {
        score -= 10_000;
    }
    score
}

fn choose_probe_injection_thread(pid: i32) -> Option<i32> {
    let limit = std::env::var("RF_THREAD_PROBE_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(24);
    let min_score = std::env::var("RF_THREAD_PROBE_MIN_SCORE")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(1);
    let rounds = std::env::var("RF_THREAD_PROBE_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(3);
    let round_delay = std::env::var("RF_THREAD_PROBE_ROUND_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(80));
    let allow_main = std::env::var("RF_THREAD_PROBE_ALLOW_MAIN")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let timeout = std::env::var("RF_THREAD_PROBE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(250));

    let task_dir = format!("/proc/{}/task", pid);
    let mut best_rejected: Option<(i32, ThreadStopSample)> = None;

    for round in 0..rounds {
        let entries = std::fs::read_dir(&task_dir).ok()?;
        let mut presample = Vec::new();
        for entry in entries.flatten() {
            let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
                Some(tid) => tid,
                None => continue,
            };
            if tid == pid && !allow_main {
                continue;
            }
            let status = read_task_text(pid, tid, "status");
            let comm = read_task_text(pid, tid, "comm");
            let wchan = read_task_text(pid, tid, "wchan");
            let score = score_probe_presample(pid, tid, &comm, thread_state(&status), &wchan);
            presample.push((score, tid, comm, wchan));
        }

        presample.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let mut best: Option<(i32, ThreadStopSample)> = None;
        for (rank, (pre_score, tid, comm, wchan)) in presample.into_iter().take(limit).enumerate() {
            log_verbose!(
                "thread probe round {}/{} pre #{}: tid={} score={} comm={} wchan={}",
                round + 1,
                rounds,
                rank + 1,
                tid,
                pre_score,
                comm,
                wchan
            );
            match sample_thread_stop_point(pid, tid, timeout) {
                Ok(sample) => {
                    let score = score_thread_sample(pid, &sample);
                    let wait_note = kernel_wait_reason(&sample.wchan_before).unwrap_or("ok");
                    log_verbose!(
                        "thread probe sample score={} wait={} syscall={} {}",
                        score,
                        wait_note,
                        sample.syscall_before,
                        sample.short_summary()
                    );
                    if best.as_ref().map(|(best_score, _)| score > *best_score).unwrap_or(true) {
                        best = Some((score, sample));
                    }
                }
                Err(e) => {
                    log_verbose!("thread probe sample failed tid={}: {}", tid, e);
                }
            }
        }

        if let Some((score, sample)) = best {
            if score >= min_score {
                log_verbose!("thread probe selected score={} {}", score, sample.short_summary());
                return Some(sample.tid);
            }
            log_warn!(
                "thread probe round {}/{} rejected best score={} below min_score={} {}",
                round + 1,
                rounds,
                score,
                min_score,
                sample.short_summary()
            );
            if best_rejected
                .as_ref()
                .map(|(best_score, _)| score > *best_score)
                .unwrap_or(true)
            {
                best_rejected = Some((score, sample));
            }
        } else {
            log_warn!("thread probe round {}/{} 未采样到可用线程", round + 1, rounds);
        }

        if round + 1 != rounds {
            std::thread::sleep(round_delay);
        }
    }

    if let Some((score, sample)) = best_rejected {
        log_warn!(
            "thread probe 未找到满足 min_score={} 的候选；最佳被拒绝 score={} {}",
            min_score,
            score,
            sample.short_summary()
        );
    }
    None
}

fn choose_injection_thread(pid: i32) -> Result<i32, String> {
    if let Ok(value) = std::env::var("RF_INJECT_THREAD") {
        let value = value.trim();
        if value.eq_ignore_ascii_case("main") || value.eq_ignore_ascii_case("pid") {
            log_verbose!("注入线程候选: forced main tid={}", pid);
            return Ok(pid);
        }
        if value.eq_ignore_ascii_case("probe") {
            if let Some(tid) = choose_probe_injection_thread(pid) {
                return Ok(tid);
            }
            return Err("thread probe 未找到满足阈值的可用候选，拒绝回退到不安全线程".to_string());
        }
        if value.eq_ignore_ascii_case("auto") {
            if let Some(tid) = choose_probe_injection_thread(pid) {
                return Ok(tid);
            }
            log_warn!("thread probe 未找到可用候选，回退到默认线程选择");
        }
        if let Ok(tid) = value.parse::<i32>() {
            log_verbose!("注入线程候选: forced tid={}", tid);
            return Ok(tid);
        }
    }

    let task_dir = format!("/proc/{}/task", pid);
    let mut best_tid = pid;
    let mut best_score = i32::MIN;

    let entries = match std::fs::read_dir(task_dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(pid),
    };

    for entry in entries.flatten() {
        let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
            Some(tid) => tid,
            None => continue,
        };

        let status = std::fs::read_to_string(format!("/proc/{}/task/{}/status", pid, tid)).unwrap_or_default();
        let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, tid)).unwrap_or_default();
        let comm = comm.trim();
        let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, tid)).unwrap_or_default();

        let mut score = 0;
        if tid == pid {
            score -= 500;
        }
        if status.contains("State:\tS") {
            score += 100;
        }
        if wchan.contains("epoll") {
            score += 80;
        } else if wchan.contains("futex") || wchan.contains("poll") {
            score += 50;
        }
        if comm.contains("LigIO")
            || comm.contains("LightHTing")
            || comm.contains("AsyncHTing")
            || comm.contains("soul_im")
            || comm.contains("RxCached")
        {
            score += 120;
        }
        if is_risky_injection_thread(comm) {
            score -= 10_000;
        }

        if score > best_score {
            best_score = score;
            best_tid = tid;
        }
    }

    if best_tid != pid {
        let comm = std::fs::read_to_string(format!("/proc/{}/task/{}/comm", pid, best_tid))
            .unwrap_or_default()
            .trim()
            .to_string();
        let wchan = std::fs::read_to_string(format!("/proc/{}/task/{}/wchan", pid, best_tid))
            .unwrap_or_default()
            .trim()
            .to_string();
        log_verbose!("注入线程候选: tid={} comm={} wchan={}", best_tid, comm, wchan);
    }

    Ok(best_tid)
}

fn is_risky_injection_thread(comm: &str) -> bool {
    const RISKY_NAMES: &[&str] = &[
        "Runtime worker",
        "Signal Catcher",
        "ADB-JDWP",
        "JDWP",
        "perfetto",
        "binder:",
        "HwBinder:",
        "crash",
        "npth",
        "process reaper",
        "Jit thread",
        "Jit thread pool",
        "RenderThread",
        "HeapTaskDaemon",
        "FinalizerDaemon",
        "FinalizerWatchd",
        "ReferenceQueue",
        "Compiler",
        "Chrome_",
        "GpuWatchdog",
    ];

    RISKY_NAMES.iter().any(|name| comm.contains(name))
}

struct StopWorldSession {
    tids: Vec<i32>,
    active: bool,
}

impl StopWorldSession {
    fn new(selected_tid: i32) -> Self {
        Self {
            tids: vec![selected_tid],
            active: true,
        }
    }

    fn attach_siblings(&mut self, pid: i32, selected_tid: i32) -> Result<(), String> {
        let mut attached_count = 0usize;

        for _ in 0..3 {
            let entries = match std::fs::read_dir(format!("/proc/{}/task", pid)) {
                Ok(entries) => entries,
                Err(e) => return Err(format!("读取线程列表失败: {}", e)),
            };
            let mut changed = false;

            for entry in entries.flatten() {
                let tid = match entry.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) {
                    Some(tid) => tid,
                    None => continue,
                };
                if tid == selected_tid || self.tids.contains(&tid) {
                    continue;
                }

                let target = Pid::from_raw(tid);
                match ptrace::attach(target) {
                    Ok(()) => {}
                    Err(Errno::ESRCH) => continue,
                    Err(e) => return Err(format!("暂停线程 {} 失败: {}", tid, e)),
                }

                match waitpid(target, None) {
                    Ok(WaitStatus::Stopped(_, _)) => {
                        self.tids.push(tid);
                        attached_count += 1;
                        changed = true;
                    }
                    Ok(status) => {
                        let _ = ptrace::detach(target, Some(nix::sys::signal::Signal::SIGCONT));
                        return Err(format!("暂停线程 {} 状态异常: {:?}", tid, status));
                    }
                    Err(Errno::ECHILD) | Err(Errno::ESRCH) => {
                        let _ = ptrace::detach(target, Some(nix::sys::signal::Signal::SIGCONT));
                    }
                    Err(e) => {
                        let _ = ptrace::detach(target, Some(nix::sys::signal::Signal::SIGCONT));
                        return Err(format!("等待线程 {} 停止失败: {}", tid, e));
                    }
                }
            }

            if !changed {
                break;
            }
        }

        log_verbose!("stop-the-world: 已暂停 {} 个其他线程", attached_count);
        Ok(())
    }

    fn detach_all(&mut self) {
        if !self.active {
            return;
        }
        for &tid in self.tids.iter().rev() {
            let _ = ptrace::detach(Pid::from_raw(tid), Some(nix::sys::signal::Signal::SIGCONT));
        }
        self.active = false;
    }
}

impl Drop for StopWorldSession {
    fn drop(&mut self) {
        self.detach_all();
    }
}

/// 写入 StringTable 到预分配的内存区域（不使用 malloc）
fn write_string_table_at(
    mem: &ProcMem,
    base_addr: usize,
    overrides: &std::collections::HashMap<String, String>,
) -> Result<usize, String> {
    // 复用 types.rs 中定义的字符串列表
    let entries: Vec<(&str, Vec<u8>)> = vec![
        (
            "sym_name",
            overrides
                .get("sym_name")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"hello_entry".to_vec()),
        ),
        (
            "pthread_err",
            overrides
                .get("pthread_err")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"pthreadded".to_vec()),
        ),
        (
            "dlsym_err",
            overrides
                .get("dlsym_err")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"dlsymFail".to_vec()),
        ),
        (
            "cmdline",
            overrides
                .get("cmdline")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"novalue".to_vec()),
        ),
        (
            "output_path",
            overrides
                .get("output_path")
                .map(|s| s.as_bytes().to_vec())
                .unwrap_or_else(|| b"novalue".to_vec()),
        ),
    ];

    // 每个条目: u64 (ptr) + u32 (len) + 4 bytes padding = 16 bytes
    let table_size = entries.len() * 16;
    let mut strings_data = Vec::new();
    let mut string_offsets = Vec::new();

    for (_, value) in &entries {
        let mut v = value.clone();
        v.push(0); // NULL 结尾
        string_offsets.push((strings_data.len(), v.len()));
        strings_data.extend_from_slice(&v);
    }

    let table_addr = base_addr;
    let strings_base = base_addr + table_size;

    // 构建 StringTable 二进制数据
    let mut table_data = Vec::with_capacity(table_size);
    for (offset, len) in &string_offsets {
        let ptr = (strings_base + offset) as u64;
        table_data.extend_from_slice(&ptr.to_le_bytes()); // u64 ptr
        table_data.extend_from_slice(&(*len as u32).to_le_bytes()); // u32 len
        table_data.extend_from_slice(&[0u8; 4]); // padding
    }

    // 写入 StringTable struct
    mem.pwrite_all(&table_data, table_addr as u64)?;
    // 写入字符串数据
    mem.pwrite_all(&strings_data, strings_base as u64)?;

    Ok(table_addr)
}

fn collect_resolver_module_bases(pid: i32) -> Result<Vec<u64>, String> {
    const RESOLVER_MODULE_COUNT: usize = 4;

    let maps = parse_proc_maps(pid as u32)?;
    let mut bases = [None::<u64>; RESOLVER_MODULE_COUNT];

    for entry in maps {
        if !entry.is_readable() || entry.offset != 0 || entry.path.is_empty() || !entry.path.starts_with('/') {
            continue;
        }
        if !is_system_resolver_module(&entry.path) {
            continue;
        }
        if let Some(priority) = resolver_module_priority(&entry.path) {
            if bases[priority].is_none() {
                bases[priority] = Some(entry.start);
                log_verbose!("resolver host module: {} @ 0x{:x}", entry.path, entry.start);
            }
        }
    }

    Ok(bases.into_iter().flatten().collect())
}

fn resolver_module_priority(path: &str) -> Option<usize> {
    match path.rsplit('/').next().unwrap_or(path) {
        "linker64" => Some(0),
        "libc.so" => Some(1),
        "libm.so" => Some(2),
        "libdl.so" => Some(3),
        _ => None,
    }
}

fn is_system_resolver_module(path: &str) -> bool {
    path.starts_with("/apex/")
        || path.starts_with("/system/")
        || path.starts_with("/system_ext/")
        || path.starts_with("/vendor/")
}

/// Unix socket fd-passing: 通过 SCM_RIGHTS 发送 fd
fn send_fd(sockfd: RawFd, fd_to_send: RawFd) -> Result<(), String> {
    use std::io::IoSlice;

    let dummy = [0u8; 1];
    let iov = [IoSlice::new(&dummy)];

    let mut cmsg_buf = vec![0u8; unsafe { libc::CMSG_SPACE(size_of::<i32>() as u32) } as usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr() as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_buf.len();

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
        std::ptr::copy_nonoverlapping(&fd_to_send as *const i32, libc::CMSG_DATA(cmsg) as *mut i32, 1);
    }

    loop {
        let ret = unsafe { libc::sendmsg(sockfd, &msg, libc::MSG_NOSIGNAL) };
        if ret > 0 {
            return Ok(());
        }
        if ret == 0 {
            return Err("sendmsg(SCM_RIGHTS) 返回 0，fd 未发送".to_string());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            errno if is_would_block(errno) => {
                wait_fd(sockfd, libc::POLLOUT, "send_fd")?;
                continue;
            }
            _ => {
                return Err(format!(
                    "sendmsg(SCM_RIGHTS) 失败: {} errno={:?}",
                    err,
                    err.raw_os_error()
                ));
            }
        }
    }
}

/// 从 ctrl socket 读取指定字节数
fn recv_exact(sockfd: RawFd, buf: &mut [u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let n = unsafe { libc::read(sockfd, buf[done..].as_mut_ptr() as *mut c_void, buf.len() - done) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                errno if is_would_block(errno) => {
                    wait_fd(sockfd, libc::POLLIN, "recv_exact")?;
                    continue;
                }
                _ => {
                    return Err(format!(
                        "recv_exact: read 失败: {} errno={:?}, done={}/{}",
                        err,
                        err.raw_os_error(),
                        done,
                        buf.len()
                    ));
                }
            }
        }
        if n == 0 {
            return Err(format!("recv_exact: EOF, done={}/{}", done, buf.len()));
        }
        done += n as usize;
    }
    Ok(())
}

/// 向 ctrl socket 写入数据
fn send_exact(sockfd: RawFd, buf: &[u8]) -> Result<(), String> {
    let mut done = 0;
    while done < buf.len() {
        let n = unsafe {
            libc::send(
                sockfd,
                buf[done..].as_ptr() as *const c_void,
                buf.len() - done,
                libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                errno if is_would_block(errno) => {
                    wait_fd(sockfd, libc::POLLOUT, "send_exact")?;
                    continue;
                }
                _ => {
                    return Err(format!(
                        "send_exact: send 失败: {} errno={:?}, done={}/{}",
                        err,
                        err.raw_os_error(),
                        done,
                        buf.len()
                    ));
                }
            }
        }
        if n == 0 {
            return Err(format!("send_exact: send 返回 0, done={}/{}", done, buf.len()));
        }
        done += n as usize;
    }
    Ok(())
}

fn is_would_block(errno: Option<i32>) -> bool {
    errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK)
}

fn wait_fd(sockfd: RawFd, events: i16, op: &str) -> Result<(), String> {
    let mut pfd = libc::pollfd {
        fd: sockfd,
        events,
        revents: 0,
    };

    loop {
        let n = unsafe { libc::poll(&mut pfd, 1, 30_000) };
        if n > 0 {
            let fatal = pfd.revents & (libc::POLLERR | libc::POLLNVAL);
            if fatal != 0 {
                return Err(format!("{}: poll 失败 revents=0x{:x} fd={}", op, pfd.revents, sockfd));
            }
            if pfd.revents & events != 0 {
                return Ok(());
            }
            if pfd.revents & libc::POLLHUP != 0 {
                return Err(format!("{}: poll hangup fd={}", op, sockfd));
            }
            continue;
        }
        if n == 0 {
            return Err(format!("{}: poll 超时 fd={} events=0x{:x}", op, sockfd, events));
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!("{}: poll 失败: {} errno={:?}", op, err, err.raw_os_error()));
    }
}

fn recv_loader_string(ctrl_fd: RawFd) -> Result<String, String> {
    let mut len_buf = [0u8; 2];
    recv_exact(ctrl_fd, &mut len_buf)?;
    let msg_len = u16::from_le_bytes(len_buf) as usize;
    if msg_len > 8192 {
        return Err(format!("Loader 字符串过长: {} bytes", msg_len));
    }

    let mut msg_buf = vec![0u8; msg_len];
    recv_exact(ctrl_fd, &mut msg_buf)?;
    Ok(String::from_utf8_lossy(&msg_buf).into_owned())
}

fn drain_loader_messages_for(ctrl_fd: RawFd, duration: std::time::Duration) {
    let deadline = std::time::Instant::now() + duration;

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }

        let remaining_ms = deadline.duration_since(now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: ctrl_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            log_warn!("延迟 detach: poll loader 控制通道失败: {}", err);
            break;
        }

        if pfd.revents & libc::POLLIN == 0 {
            let fatal = pfd.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP);
            if fatal != 0 {
                log_warn!("延迟 detach: loader 控制通道关闭 revents=0x{:x}", pfd.revents);
                break;
            }
            continue;
        }

        let mut msg_type = [0u8; 1];
        if let Err(e) = recv_exact(ctrl_fd, &mut msg_type) {
            log_warn!("延迟 detach: 读取 loader 消息类型失败: {}", e);
            break;
        }

        match msg_type[0] {
            t if t == message_type::DEBUG || t == message_type::LOG => match recv_loader_string(ctrl_fd) {
                Ok(msg) => log_verbose!("Loader debug: {}", msg),
                Err(e) => {
                    log_warn!("延迟 detach: 读取 loader debug 失败: {}", e);
                    break;
                }
            },
            t if t == message_type::ERROR_DLOPEN || t == message_type::ERROR_DLSYM => {
                match recv_loader_string(ctrl_fd) {
                    Ok(msg) => log_warn!("延迟 detach: loader 错误: {}", msg),
                    Err(e) => log_warn!("延迟 detach: 读取 loader 错误失败: {}", e),
                }
                break;
            }
            t if t == message_type::BYE => {
                log_warn!("延迟 detach: loader 在 entry 前退出");
                break;
            }
            t => {
                log_warn!("延迟 detach: loader 控制通道收到未知消息 {}", t);
                break;
            }
        }
    }
}

/// Host 端执行 loader IPC 握手协议
/// 返回 REPL 用的 host_fd
fn run_loader_handshake(ctrl_fd: RawFd, target_pid: i32, loader_ctx_addr: usize) -> Result<InjectionResult, String> {
    // 1. 接收 HELLO 消息: [type:u8][thread_id:i32]
    let mut msg_type = [0u8; 1];
    recv_exact(ctrl_fd, &mut msg_type)?;
    if msg_type[0] != message_type::HELLO {
        return Err(format!("期望 HELLO({}), 收到 {}", message_type::HELLO, msg_type[0]));
    }
    let mut tid_buf = [0u8; 4];
    recv_exact(ctrl_fd, &mut tid_buf)?;
    let thread_id = i32::from_le_bytes(tid_buf);
    log_verbose!("Loader worker tid: {}", thread_id);

    // 2. 发送 agent SO。默认经 loader 控制 socket 流式发送，避免目标进程临时出现
    //    agent memfd fd；仅显式诊断/兼容开关才回退 SCM_RIGHTS memfd。
    if use_stream_agent_transfer() {
        let size = (AGENT_SO.len() as u64).to_le_bytes();
        if let Err(e) = send_exact(ctrl_fd, &size) {
            log_warn!("agent stream size 发送失败，读取 loader 诊断: {}", e);
            drain_loader_messages_for(ctrl_fd, std::time::Duration::from_millis(750));
            return Err(e);
        }
        if let Err(e) = send_exact(ctrl_fd, AGENT_SO) {
            log_warn!("agent stream 发送失败，读取 loader 诊断: {}", e);
            drain_loader_messages_for(ctrl_fd, std::time::Duration::from_millis(750));
            return Err(e);
        }
        log_verbose!("agent SO 已通过控制 socket 流式发送 ({} bytes)", AGENT_SO.len());
    } else {
        // 关键: 必须设置 SELinux label 为 frida_memfd (带 mlstrustedobject 属性)，
        // 否则 untrusted_app 因 MLS 分类不匹配无法通过 SCM_RIGHTS 接收 tmpfs fd。
        let agent_memfd = unsafe { libc::memfd_create(c"jit-cache".as_ptr(), 0) };
        if agent_memfd < 0 {
            return Err(format!("memfd_create 失败: {}", std::io::Error::last_os_error()));
        }
        // relabel memfd：匹配目标进程的 MLS categories，绕过 MLS/MCS 检查
        relabel_fd_for_injection(agent_memfd, target_pid);
        let mut written = 0usize;
        while written < AGENT_SO.len() {
            let n = unsafe {
                libc::write(
                    agent_memfd,
                    AGENT_SO[written..].as_ptr() as *const c_void,
                    AGENT_SO.len() - written,
                )
            };
            if n <= 0 {
                unsafe { close(agent_memfd) };
                return Err("写入 agent SO 到 memfd 失败".to_string());
            }
            written += n as usize;
        }
        let padded_len = match padded_agent_memfd_len() {
            Ok(len) => len,
            Err(e) => {
                unsafe { close(agent_memfd) };
                return Err(e);
            }
        };
        if padded_len > AGENT_SO.len() && unsafe { libc::ftruncate(agent_memfd, padded_len as libc::off_t) } != 0 {
            unsafe { close(agent_memfd) };
            return Err(format!("扩展 agent SO memfd 失败: {}", std::io::Error::last_os_error()));
        }
        if let Err(e) = send_fd(ctrl_fd, agent_memfd) {
            unsafe { close(agent_memfd) };
            return Err(e);
        }
        unsafe { close(agent_memfd) };
        log_verbose!("agent SO fd 已发送 ({} bytes, padded {})", AGENT_SO.len(), padded_len);
    }

    // 3. 创建 REPL socketpair 并发送一端给 loader
    //    注意：loader 先接收 agent_ctrlfd，然后才发送 READY
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(format!("host socketpair 失败: {}", std::io::Error::last_os_error()));
    }
    let host_repl_fd = sv[0];
    let agent_repl_fd = sv[1];
    // 注意：socketpair 在 sockfs 上，不支持 fsetxattr relabel（associate 被拒），
    // 但 Unix socket fd 的 SCM_RIGHTS 传递不受 MLS file 检查约束，无需 relabel
    if let Err(e) = send_fd(ctrl_fd, agent_repl_fd) {
        unsafe {
            close(agent_repl_fd);
            close(host_repl_fd);
        }
        return Err(e);
    }
    unsafe { close(agent_repl_fd) };
    log_verbose!("REPL socketpair fd 已发送");

    // 4. 等待 READY（或错误）— DEBUG/LOG 消息用于定位 READY 前断开的阶段
    loop {
        recv_exact(ctrl_fd, &mut msg_type)?;
        match msg_type[0] {
            t if t == message_type::READY => {
                log_success!("Loader: agent 加载成功");
                break;
            }
            t if t == message_type::DEBUG || t == message_type::LOG => {
                let msg = recv_loader_string(ctrl_fd)?;
                log_verbose!("Loader debug: {}", msg);
            }
            t if t == message_type::ERROR_DLOPEN || t == message_type::ERROR_DLSYM => {
                let msg = recv_loader_string(ctrl_fd)?;
                let kind = if t == message_type::ERROR_DLOPEN {
                    "link"
                } else {
                    "entrypoint"
                };
                unsafe { close(host_repl_fd) };
                return Err(format!("Loader {} 失败: {}", kind, msg));
            }
            t if t == message_type::BYE => {
                unsafe { close(host_repl_fd) };
                return Err("Loader 在 READY 前退出 (BYE)，请查看 loader/agent 崩溃日志".to_string());
            }
            t => {
                unsafe { close(host_repl_fd) };
                return Err(format!("Loader 协议错误: 期望 READY/DEBUG/ERROR, 收到 {}", t));
            }
        }
    }

    let loader_ctx = read_loader_runtime_context(target_pid, loader_ctx_addr)?;
    if loader_ctx.agent_current_thread_eval_impl == 0 {
        unsafe { close(host_repl_fd) };
        return Err("Loader 未解析 rustfrida_loadjs_current_thread".to_string());
    }

    // 5. 发送 ACK
    send_exact(ctrl_fd, &[message_type::ACK])?;

    // ctrl_fd 保持打开用于生命周期管理（BYE 消息）
    // 但对于 rustFrida，REPL 通信走 host_repl_fd
    Ok(InjectionResult {
        host_fd: host_repl_fd,
        target_pid,
        loader_ctx_addr: loader_ctx_addr as u64,
        agent_current_thread_eval_impl: loader_ctx.agent_current_thread_eval_impl,
    })
}

fn read_loader_runtime_context(pid: i32, loader_ctx_addr: usize) -> Result<RustFridaLoaderContext, String> {
    let mem = ProcMem::open(pid as u32)?;
    let mut ctx = RustFridaLoaderContext::default();
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            &mut ctx as *mut RustFridaLoaderContext as *mut u8,
            std::mem::size_of::<RustFridaLoaderContext>(),
        )
    };
    mem.pread_exact(bytes, loader_ctx_addr as u64)?;
    Ok(ctx)
}

/// Frida-style 注入：bootstrapper 在目标进程内探测 libc/linker API，
/// loader 在 worker 线程中完成自定义 linker + entrypoint 查找 + hello_entry 调用。
/// 使用 code-swap 技术：零 host 端偏移计算，bootstrapper 通过 raw syscall 自行分配内存。
pub(crate) fn inject_via_bootstrapper(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<InjectionResult, String> {
    let mut last_err = String::new();

    for attempt in 0..3 {
        match inject_via_bootstrapper_once(pid, string_overrides) {
            Ok(result) => return Ok(result),
            Err(e) => {
                let retryable = e.contains("错误码: 3")
                    || e.contains("目标进程不存在")
                    || e.contains("No such process")
                    || e.contains("ESRCH");
                last_err = e;

                if !retryable || !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                    break;
                }

                log_warn!("注入线程失效，重新选择线程重试 ({}/3): {}", attempt + 1, last_err);
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        }
    }

    Err(last_err)
}

fn inject_via_bootstrapper_once(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<InjectionResult, String> {
    log_info!("正在附加到进程 PID: {} (Frida-style bootstrapper)", pid);

    let trace_tid = choose_injection_thread(pid)?;
    if trace_tid != pid {
        log_verbose!("选择工作线程执行注入: tid={}", trace_tid);
    }

    // 附加到选中的目标线程
    attach_to_process(trace_tid)?;
    let mut stop_world = StopWorldSession::new(trace_tid);
    if std::env::var("RF_STOP_WORLD").map(|v| v != "0").unwrap_or(false) {
        stop_world.attach_siblings(pid, trace_tid)?;
    } else {
        log_verbose!("stop-the-world: disabled (set RF_STOP_WORLD=1 to enable)");
    }

    let mem = ProcMem::open(pid as u32)?;

    let initial_regs = crate::process::get_registers_pub(trace_tid)?;

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 || (page_size & (page_size - 1)) != 0 {
        return Err(format!("非法 page size: {}", page_size));
    }
    let page_size = page_size as usize;
    let code_size = BOOTSTRAPPER.len().max(FRIDA_LOADER.len()) + BRK_RETURN_TRAP.len();
    let code_pages = code_size.div_ceil(page_size) * page_size;
    let data_size = 4 * page_size;
    let total_alloc = code_pages + data_size;

    // === Code-swap: 临时覆盖目标进程可执行区域运行 bootstrapper ===
    // 1. 找到目标进程的一个 r-xp 区域（linker64 最安全，所有进程都有）
    let code_swap_size = BOOTSTRAPPER.len() + BRK_RETURN_TRAP.len();
    let swap_addr = find_executable_region(pid, code_swap_size)?;
    let swap_return_trap_addr = swap_addr + BOOTSTRAPPER.len();
    log_verbose!("code-swap 区域: 0x{:x} ({} bytes)", swap_addr, code_swap_size);

    // 2. 保存原始代码
    let mut original_code = vec![0u8; code_swap_size];
    mem.pread_exact(&mut original_code, swap_addr as u64)?;

    // 3. 写入 bootstrapper
    mem.pwrite_all(BOOTSTRAPPER, swap_addr as u64)?;

    // 4. 在 swap 区域旁找一块可写区域放 BootstrapContext + LibcApi
    //    用目标线程栈来存放（SP 下方有空间）
    let stack_ctx_addr = (initial_regs.sp as usize - 512) & !0xF; // 16 字节对齐
    let stack_libc_addr = stack_ctx_addr - size_of::<FridaLibcApi>();

    // 5. 准备 Phase 1 context: allocation_base = NULL → bootstrapper 自行 mmap
    let zero_api = FridaLibcApi::default();
    mem_write_value(&mem, stack_libc_addr, &zero_api)?;

    let mut phase1_ctx = FridaBootstrapContext::default();
    phase1_ctx.allocation_base = 0; // NULL → 触发 Phase 1 mmap
    phase1_ctx.allocation_size = total_alloc as u64;
    phase1_ctx.page_size = page_size as u64;
    phase1_ctx.libc = stack_libc_addr as u64;
    mem_write_value(&mem, stack_ctx_addr, &phase1_ctx)?;

    // 6. 调用 bootstrapper Phase 1（raw mmap syscall 分配内存）
    log_verbose!("bootstrapper Phase 1: mmap 分配...");
    let status = call_target_function_brk(&mem, trace_tid, swap_addr, &[stack_ctx_addr], swap_return_trap_addr)
        .map_err(|e| {
            // 恢复原始代码后再报错
            let _ = mem.pwrite_all(&original_code, swap_addr as u64);
            format!("bootstrapper Phase 1 失败: {}", e)
        })?;

    if status != bootstrap_status::ALLOCATION_SUCCESS {
        let _ = mem.pwrite_all(&original_code, swap_addr as u64);
        return Err(format!("bootstrapper mmap 失败 (status={})", status));
    }

    // 读回 allocation_base
    let phase1_result: FridaBootstrapContext = mem_read_value(&mem, stack_ctx_addr)?;
    let alloc_base = phase1_result.allocation_base as usize;
    log_verbose!(
        "bootstrapper 分配临时 RWX 区域: 0x{:x} ({} bytes)",
        alloc_base,
        total_alloc
    );

    // 7. 恢复 code-swap 区域的原始代码
    mem.pwrite_all(&original_code, swap_addr as u64)?;
    log_verbose!("code-swap 区域已恢复");

    // === 阶段 1: 在新分配的区域执行 bootstrapper Phase 2 ===
    mem.pwrite_all(BOOTSTRAPPER, alloc_base as u64)?;
    log_verbose!("bootstrapper 写入完成 ({} bytes)", BOOTSTRAPPER.len());

    let data_base = alloc_base + code_pages;
    let alloc_return_trap_addr = alloc_base + code_pages - BRK_RETURN_TRAP.len();
    mem.pwrite_all(BRK_RETURN_TRAP, alloc_return_trap_addr as u64)?;
    log_verbose!("remote call return trap: 0x{:x} (BRK/SIGTRAP)", alloc_return_trap_addr);
    let libc_api_addr = data_base;
    let ctx_addr = libc_api_addr + size_of::<FridaLibcApi>();

    let zero_api = FridaLibcApi::default();
    mem_write_value(&mem, libc_api_addr, &zero_api)?;

    let mut bootstrap_ctx = FridaBootstrapContext::default();
    bootstrap_ctx.allocation_base = alloc_base as u64; // 非 NULL → Phase 2
    bootstrap_ctx.allocation_size = total_alloc as u64;
    bootstrap_ctx.page_size = page_size as u64;
    bootstrap_ctx.enable_ctrlfds = 1;
    bootstrap_ctx.libc = libc_api_addr as u64;
    mem_write_value(&mem, ctx_addr, &bootstrap_ctx)?;

    log_verbose!("调用 bootstrapper Phase 2...");
    let status = call_target_function_with_return_trap(trace_tid, alloc_base, &[ctx_addr], alloc_return_trap_addr)
        .map_err(|e| format!("bootstrapper Phase 2 失败: {}", e))?;

    match status {
        s if s == bootstrap_status::SUCCESS => {
            log_success!("bootstrapper 完成: libc API 已解析");
        }
        s if s == bootstrap_status::AUXV_NOT_FOUND => {
            return Err("bootstrapper: 未找到 /proc/self/auxv".into());
        }
        s if s == bootstrap_status::TOO_EARLY => {
            return Err("bootstrapper: libc 尚未加载（TOO_EARLY）".into());
        }
        s if s == bootstrap_status::LIBC_UNSUPPORTED => {
            return Err("bootstrapper: libc API 不完整".into());
        }
        s => {
            return Err(format!("bootstrapper 返回未知状态: {}", s));
        }
    }

    // 读回结果
    let bootstrap_ctx: FridaBootstrapContext = mem_read_value(&mem, ctx_addr)?;
    let libc_api: FridaLibcApi = mem_read_value(&mem, libc_api_addr)?;

    log_verbose!("rtld_flavor: {}", bootstrap_ctx.rtld_flavor);
    log_verbose!("ctrlfds: [{}, {}]", bootstrap_ctx.ctrlfds[0], bootstrap_ctx.ctrlfds[1]);
    log_verbose!("agent linker: 自解析 ELF/重定位/外部符号，不调用 dlopen/dlsym");
    let use_pthread_loader = std::env::var("RF_LOADER_THREAD")
        .map(|value| value.eq_ignore_ascii_case("pthread"))
        .unwrap_or(false);
    if use_pthread_loader {
        log_verbose!("loader thread: 请求 pthread_create 模式");
    } else {
        log_verbose!("loader thread: raw clone，不调用 pthread_create");
    }

    // 提取 ctrlfds[0] 到 host
    let host_ctrl_fd = extract_fd_from_target(pid, bootstrap_ctx.ctrlfds[0])?;
    log_verbose!(
        "已提取 ctrl fd: target {} → host {}",
        bootstrap_ctx.ctrlfds[0],
        host_ctrl_fd
    );

    // === 写入 StringTable ===
    let string_table_offset = size_of::<FridaLibcApi>()
        + size_of::<FridaBootstrapContext>()
        + size_of::<RustFridaLoaderContext>()
        + size_of::<FridaLibcApi>()
        + 256; // 预留字符串区
    let string_table_base = data_base + string_table_offset;
    let string_table_addr = write_string_table_at(&mem, string_table_base, string_overrides)?;
    log_verbose!("StringTable 写入: 0x{:x}", string_table_addr);

    let resolver_module_bases = collect_resolver_module_bases(pid)?;
    let resolver_module_bases_addr = (string_table_addr + 2048 + 7) & !7usize;
    if !resolver_module_bases.is_empty() {
        let mut resolver_module_bytes = Vec::with_capacity(resolver_module_bases.len() * size_of::<u64>());
        for base in &resolver_module_bases {
            resolver_module_bytes.extend_from_slice(&base.to_le_bytes());
        }
        mem.pwrite_all(&resolver_module_bytes, resolver_module_bases_addr as u64)?;
    }
    log_verbose!(
        "resolver host modules: {} @ 0x{:x}",
        resolver_module_bases.len(),
        resolver_module_bases_addr
    );

    // === 阶段 2: 写入 + 执行 loader ===
    mem.pwrite_all(FRIDA_LOADER, alloc_base as u64)?;
    log_verbose!("loader 写入完成 ({} bytes)", FRIDA_LOADER.len());

    // Loader 数据区（复用 data_base 后面的区域）
    let loader_data_base = data_base + size_of::<FridaLibcApi>() + size_of::<FridaBootstrapContext>();
    let loader_ctx_addr = loader_data_base;
    let loader_libc_addr = loader_ctx_addr + size_of::<RustFridaLoaderContext>();

    // 写入字符串字面量
    let str_base = loader_libc_addr + size_of::<FridaLibcApi>();
    let entrypoint_str = build_agent_entrypoint()?;
    let current_thread_eval_str = b"rustfrida_loadjs_current_thread\0";
    let data_str = build_loader_agent_data(use_pthread_loader)?;
    let fallback_str = format!("\x00rustfrida-{}\0", pid); // abstract socket: \0 prefix
    mem.pwrite_all(&entrypoint_str, str_base as u64)?;
    let current_thread_eval_str_addr = str_base + entrypoint_str.len();
    mem.pwrite_all(current_thread_eval_str, current_thread_eval_str_addr as u64)?;
    let data_str_addr = current_thread_eval_str_addr + current_thread_eval_str.len();
    mem.pwrite_all(&data_str, data_str_addr as u64)?;
    let fallback_str_addr = data_str_addr + data_str.len();
    mem.pwrite_all(fallback_str.as_bytes(), fallback_str_addr as u64)?;

    // 构造 LoaderContext
    let mut loader_ctx = RustFridaLoaderContext {
        ctrlfds: bootstrap_ctx.ctrlfds,
        agent_entrypoint: str_base as u64,
        agent_data: data_str_addr as u64,
        fallback_address: fallback_str_addr as u64,
        libc: loader_libc_addr as u64,
        string_table_addr: string_table_addr as u64,
        agent_current_thread_eval: current_thread_eval_str_addr as u64,
        ..Default::default()
    };
    if !resolver_module_bases.is_empty() {
        loader_ctx.resolver_module_bases = resolver_module_bases_addr as u64;
        loader_ctx.resolver_module_count = resolver_module_bases.len() as u64;
    }
    mem_write_value(&mem, loader_ctx_addr, &loader_ctx)?;

    // 写入 LibcApi（给 loader 用）
    mem_write_value(&mem, loader_libc_addr, &libc_api)?;

    remote_mprotect_syscall(
        &mem,
        trace_tid,
        swap_addr,
        &original_code,
        alloc_return_trap_addr,
        alloc_base,
        code_pages,
        libc::PROT_READ | libc::PROT_EXEC,
    )?;
    remote_mprotect_syscall(
        &mem,
        trace_tid,
        swap_addr,
        &original_code,
        alloc_return_trap_addr,
        data_base,
        data_size,
        libc::PROT_READ | libc::PROT_WRITE,
    )?;
    log_verbose!(
        "bootstrapper/loader 权限收敛: code=0x{:x}-0x{:x} RX, data=0x{:x}-0x{:x} RW",
        alloc_base,
        alloc_base + code_pages,
        data_base,
        data_base + data_size
    );

    // 调用 loader（执行 raw clone 后立即返回）
    log_verbose!("调用 loader...");
    let _ = call_target_function_with_return_trap(trace_tid, alloc_base, &[loader_ctx_addr], alloc_return_trap_addr)
        .map_err(|e| {
            unsafe { close(host_ctrl_fd) };
            format!("loader 执行失败: {}", e)
        })?;

    // === 分离前验证寄存器状态 ===
    {
        let final_regs = crate::process::get_registers_pub(trace_tid);
        if let Ok(r) = final_regs {
            log_verbose!(
                "分离前寄存器: PC={:#x} SP={:#x} LR={:#x} FP(x29)={:#x} x19={:#x}",
                r.pc,
                r.sp,
                r.regs[30],
                r.regs[29],
                r.regs[19]
            );
        }
    }

    let detach_after_handshake = std::env::var("RF_DETACH_AFTER_HANDSHAKE")
        .map(|v| v != "0")
        .unwrap_or(false);

    if !detach_after_handshake {
        // === ptrace 分离 ===
        stop_world.detach_all();
        unsafe {
            libc::kill(pid, libc::SIGCONT);
        }
        log_success!("已分离目标进程");
    } else {
        log_verbose!("延迟 detach: 保持旧线程停止直到 loader READY/ACK 完成");
    }

    // === Host 端 loader IPC 握手 ===
    let result = match run_loader_handshake(host_ctrl_fd, pid, loader_ctx_addr) {
        Ok(result) => result,
        Err(e) => {
            unsafe { close(host_ctrl_fd) };
            if detach_after_handshake {
                stop_world.detach_all();
                unsafe {
                    libc::kill(pid, libc::SIGCONT);
                }
            }
            return Err(e);
        }
    };

    if detach_after_handshake {
        let delay_ms = std::env::var("RF_DETACH_AFTER_HANDSHAKE_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if delay_ms != 0 {
            log_verbose!(
                "延迟 detach: 等待 agent 首帧 {}ms，并继续读取 loader 控制日志",
                delay_ms
            );
            drain_loader_messages_for(host_ctrl_fd, std::time::Duration::from_millis(delay_ms));
        }
        stop_world.detach_all();
        unsafe {
            libc::kill(pid, libc::SIGCONT);
        }
        log_success!("已分离目标进程");
    }

    Ok(result)
}
