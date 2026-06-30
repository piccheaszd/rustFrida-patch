#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::collections::HashSet;
use std::time::{Duration, Instant};

use crate::proc_mem::ProcMem;
use crate::{log_info, log_verbose, log_warn};

#[derive(Clone, Debug)]
pub(crate) struct SpawnIdentitySpec {
    pub(crate) package: String,
    pub(crate) expected_process: String,
}

impl SpawnIdentitySpec {
    pub(crate) fn new(package: String, expected_process: String) -> Self {
        Self {
            package,
            expected_process,
        }
    }
}

#[derive(Clone, Debug)]
struct ProcIdentity {
    pid: i32,
    tgid: i32,
    ppid: i32,
    uid: i32,
    tracer_pid: i32,
    status_name: String,
    cmdline_first: String,
    cmdline_display: String,
    maps_has_package: bool,
    maps_hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityClass {
    Target,
    TargetAlias,
    SelfTraceChild,
    UnmatchedChild,
    ForeignProcess,
}

#[derive(Clone, Debug)]
pub(crate) struct UidProcess {
    pub(crate) pid: i32,
    pub(crate) ppid: i32,
    pub(crate) uid: i32,
    pub(crate) status_name: String,
    pub(crate) cmdline_display: String,
}

pub(crate) fn audit_target(stage: &str, pid: i32, spec: &SpawnIdentitySpec) {
    let Some(info) = sample_process(pid, Some(&spec.package), true) else {
        log_warn!("进程身份审计({}): pid={} 已不存在", stage, pid);
        return;
    };

    log_verbose!(
        "进程身份审计({}): pid={} expected={} cmdline={} status.Name={} ppid={} uid={}",
        stage,
        pid,
        spec.expected_process,
        printable(&info.cmdline_display),
        printable(&info.status_name),
        info.ppid,
        info.uid
    );

    match classify_target_identity(&info, spec) {
        IdentityClass::Target => {}
        IdentityClass::TargetAlias => log_identity_alias(stage, &info, spec, IdentityClass::TargetAlias),
        other => log_identity_mismatch(stage, &info, spec, other),
    }
}

pub(crate) fn process_uid(pid: i32) -> Option<i32> {
    sample_process(pid, None, false).map(|info| info.uid)
}

pub(crate) fn collect_uid_processes(uid: i32) -> Vec<UidProcess> {
    if uid < 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    for pid in list_pids() {
        let Some(info) = sample_process(pid, None, false) else {
            continue;
        };
        if info.uid != uid {
            continue;
        }
        out.push(UidProcess {
            pid: info.pid,
            ppid: info.ppid,
            uid: info.uid,
            status_name: info.status_name,
            cmdline_display: info.cmdline_display,
        });
    }
    out.sort_by_key(|p| p.pid);
    out
}

pub(crate) fn describe_uid_process(process: &UidProcess) -> String {
    format!(
        "pid={} ppid={} uid={} cmdline={} status.Name={}",
        process.pid,
        process.ppid,
        process.uid,
        printable(&process.cmdline_display),
        printable(&process.status_name)
    )
}

pub(crate) fn start_spawn_identity_watcher(target_pid: i32, spec: SpawnIdentitySpec) {
    let duration = identity_watch_duration();
    if duration.is_zero() {
        return;
    }

    log_info!(
        "启动 spawn 身份侦察: pid={} package={} window={}s",
        target_pid,
        spec.package,
        duration.as_secs()
    );

    let _ = std::thread::Builder::new()
        .name("id-watch".into())
        .spawn(move || watch_spawn_identity(target_pid, spec, duration));
}

fn watch_spawn_identity(target_pid: i32, spec: SpawnIdentitySpec, duration: Duration) {
    let mut seen: HashSet<(i32, &'static str)> = HashSet::new();
    let target_uid = sample_process(target_pid, Some(&spec.package), false).map(|p| p.uid);
    let deadline = Instant::now() + duration;

    while Instant::now() < deadline {
        if !std::path::Path::new(&format!("/proc/{}", target_pid)).exists() {
            log_verbose!("spawn 身份侦察: 目标 pid={} 已退出", target_pid);
            break;
        }

        for pid in list_pids() {
            let cheap = sample_process(pid, None, false);
            let Some(cheap) = cheap else {
                continue;
            };

            if !should_watch_process(pid, &cheap, target_pid, target_uid) {
                continue;
            }

            let info = sample_process(pid, Some(&spec.package), true).unwrap_or(cheap);
            if should_skip_expected_process(pid, &info, target_pid, &spec) {
                continue;
            }

            let class = classify_watched_process(&info, &spec, target_pid, target_uid);
            if class == IdentityClass::Target {
                continue;
            }
            if seen.insert((pid, seen_key(class))) {
                if should_scrub_class(class) {
                    scrubbed_inherited_stage1_tail(pid);
                }
                log_classified_identity(watched_stage_name(class), &info, &spec, class);
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn scrubbed_inherited_stage1_tail(pid: i32) {
    match scrub_inherited_stage1_tail(pid) {
        Ok(0) => {}
        Ok(count) => log_verbose!("已清理疑似继承 stage1 tail: pid={} regions={}", pid, count),
        Err(e) => log_verbose!("清理继承 stage1 tail 失败: pid={} {}", pid, e),
    }
}

fn scrub_inherited_stage1_tail(pid: i32) -> Result<usize, String> {
    if pid <= 0 {
        return Ok(0);
    }

    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid)).map_err(|e| format!("读取 maps 失败: {}", e))?;
    let mem = ProcMem::open(pid as u32)?;
    let mut scrubbed = 0usize;

    for line in maps.lines() {
        let Some((start, end, perms)) = parse_map_range(line) else {
            continue;
        };
        if perms != "rw-p" || !line.contains(" 00:00 0") {
            continue;
        }
        let size = end.saturating_sub(start);
        if !(0x1000..=0x2_0000).contains(&size) {
            continue;
        }

        let mut buf = vec![0u8; size as usize];
        if mem.pread_exact(&mut buf, start).is_err() {
            continue;
        }
        if !has_stage1_tail_signature(&buf) {
            continue;
        }

        buf.fill(0);
        mem.pwrite_all(&buf, start)?;
        scrubbed += 1;
    }

    Ok(scrubbed)
}

fn classify_target_identity(info: &ProcIdentity, spec: &SpawnIdentitySpec) -> IdentityClass {
    if is_expected_process(&info.cmdline_first, spec) {
        IdentityClass::Target
    } else if info.uid >= 10000 {
        /*
         * This PID was delivered by the current zygote hello/session.  Hardened
         * apps such as BOCHK may rename it to a system-looking package; that is
         * an alias for this target session, not proof that RF attached to the
         * observed package name.
         */
        IdentityClass::TargetAlias
    } else {
        IdentityClass::ForeignProcess
    }
}

fn classify_watched_process(
    info: &ProcIdentity,
    spec: &SpawnIdentitySpec,
    target_pid: i32,
    target_uid: Option<i32>,
) -> IdentityClass {
    let same_uid = target_uid == Some(info.uid);
    let direct_child = info.ppid == target_pid;

    if info.pid == target_pid {
        return classify_target_identity(info, spec);
    }
    if same_uid && direct_child {
        return IdentityClass::SelfTraceChild;
    }
    if same_uid && (info.maps_has_package || is_target_family_name(&info.cmdline_first, &spec.package)) {
        return IdentityClass::TargetAlias;
    }
    if same_uid {
        return IdentityClass::TargetAlias;
    }
    if direct_child {
        return IdentityClass::UnmatchedChild;
    }
    IdentityClass::ForeignProcess
}

fn should_watch_process(pid: i32, info: &ProcIdentity, target_pid: i32, target_uid: Option<i32>) -> bool {
    pid == target_pid || target_uid == Some(info.uid) || info.ppid == target_pid
}

fn should_skip_expected_process(pid: i32, info: &ProcIdentity, target_pid: i32, spec: &SpawnIdentitySpec) -> bool {
    pid != target_pid && is_target_family_name(&info.cmdline_first, &spec.package)
}

fn seen_key(class: IdentityClass) -> &'static str {
    match class {
        IdentityClass::Target => "target",
        IdentityClass::TargetAlias => "target-alias",
        IdentityClass::SelfTraceChild => "self-trace-child",
        IdentityClass::UnmatchedChild => "unmatched-child",
        IdentityClass::ForeignProcess => "foreign-process",
    }
}

fn watched_stage_name(class: IdentityClass) -> &'static str {
    match class {
        IdentityClass::Target => "watch-target",
        IdentityClass::TargetAlias => "watch-target-alias",
        IdentityClass::SelfTraceChild => "watch-self-trace-child",
        IdentityClass::UnmatchedChild => "watch-unmatched-child",
        IdentityClass::ForeignProcess => "watch-foreign-process",
    }
}

fn should_scrub_class(class: IdentityClass) -> bool {
    matches!(
        class,
        IdentityClass::TargetAlias | IdentityClass::SelfTraceChild | IdentityClass::UnmatchedChild
    )
}

fn log_classified_identity(stage: &str, info: &ProcIdentity, spec: &SpawnIdentitySpec, class: IdentityClass) {
    if matches!(class, IdentityClass::TargetAlias | IdentityClass::SelfTraceChild) {
        log_identity_alias(stage, info, spec, class);
    } else {
        log_identity_mismatch(stage, info, spec, class);
    }
}

fn log_identity_alias(stage: &str, info: &ProcIdentity, spec: &SpawnIdentitySpec, class: IdentityClass) {
    log_info!(
        "identity_alias({}): class={:?} pid={} tgid={} ppid={} uid={} requested={} observed_cmdline={} status.Name={} tracer={}{}",
        stage,
        class,
        info.pid,
        info.tgid,
        info.ppid,
        info.uid,
        spec.package,
        printable(&info.cmdline_display),
        printable(&info.status_name),
        info.tracer_pid,
        maps_suffix(info)
    );
}

fn log_identity_mismatch(stage: &str, info: &ProcIdentity, spec: &SpawnIdentitySpec, class: IdentityClass) {
    log_warn!(
        "identity_mismatch({}): class={:?} pid={} tgid={} ppid={} uid={} requested={} observed_cmdline={} status.Name={} tracer={}{}",
        stage,
        class,
        info.pid,
        info.tgid,
        info.ppid,
        info.uid,
        spec.package,
        printable(&info.cmdline_display),
        printable(&info.status_name),
        info.tracer_pid,
        maps_suffix(info)
    );
}

fn parse_map_range(line: &str) -> Option<(u64, u64, &str)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    Some((start, end, perms))
}

fn has_stage1_tail_signature(buf: &[u8]) -> bool {
    const NEEDLES: [&[u8]; 4] = [
        b"agent-ctrl=loader",
        b"frida_send_ready failed",
        b"frida_receive_ack failed",
        b"rustfrida_loadjs_current_thread",
    ];
    NEEDLES.iter().any(|needle| contains_bytes(buf, needle))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn identity_watch_duration() -> Duration {
    std::env::var("RF_IDENTITY_WATCH_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(8))
}

fn sample_process(pid: i32, package: Option<&str>, include_maps: bool) -> Option<ProcIdentity> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    let status_name = status_field(&status, "Name").unwrap_or_default();
    let tgid = status_field(&status, "Tgid")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(pid);
    let ppid = status_field(&status, "PPid")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(-1);
    let uid = status_field(&status, "Uid")
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<i32>().ok()))
        .unwrap_or(-1);
    let tracer_pid = status_field(&status, "TracerPid")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);

    let cmdline = std::fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    let cmdline_first = cmdline
        .split(|&b| b == 0)
        .next()
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or("")
        .trim()
        .to_string();
    let cmdline_display = if cmdline.is_empty() {
        String::new()
    } else {
        String::from_utf8_lossy(&cmdline).replace('\0', " ").trim().to_string()
    };

    let (maps_has_package, maps_hint) = if include_maps {
        match package {
            Some(package) => maps_package_hint(pid, package),
            None => (false, None),
        }
    } else {
        (false, None)
    };

    Some(ProcIdentity {
        pid,
        tgid,
        ppid,
        uid,
        tracer_pid,
        status_name,
        cmdline_first,
        cmdline_display,
        maps_has_package,
        maps_hint,
    })
}

fn status_field(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{}:", key);
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(|value| value.trim().to_string()))
}

fn maps_package_hint(pid: i32, package: &str) -> (bool, Option<String>) {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) else {
        return (false, None);
    };

    for line in maps.lines() {
        if line.contains(package) {
            return (true, Some(trim_map_line(line)));
        }
    }

    (false, None)
}

fn trim_map_line(line: &str) -> String {
    let mut out = line.trim().to_string();
    if out.len() > 180 {
        out.truncate(180);
        out.push_str("...");
    }
    out
}

fn list_pids() -> Vec<i32> {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    proc_dir
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.chars().all(|c| c.is_ascii_digit()) {
                name.parse::<i32>().ok()
            } else {
                None
            }
        })
        .collect()
}

fn is_expected_process(name: &str, spec: &SpawnIdentitySpec) -> bool {
    name == spec.expected_process
}

fn is_target_family_name(name: &str, package: &str) -> bool {
    name == package || name.starts_with(&format!("{}:", package))
}

fn maps_suffix(info: &ProcIdentity) -> String {
    match &info.maps_hint {
        Some(hint) => format!(" maps_hint={}", hint),
        None => String::new(),
    }
}

fn printable(value: &str) -> String {
    if value.is_empty() {
        "<empty>".to_string()
    } else {
        value.to_string()
    }
}
