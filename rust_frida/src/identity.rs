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

    if !is_expected_process(&info.cmdline_first, spec) {
        log_warn!(
            "检测到目标进程身份伪装({}): pid={} zygote-name={} cmdline={} status.Name={} ppid={} uid={}{}",
            stage,
            pid,
            spec.expected_process,
            printable(&info.cmdline_display),
            printable(&info.status_name),
            info.ppid,
            info.uid,
            maps_suffix(&info)
        );
    }
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

            let is_target_pid = pid == target_pid;
            let same_uid = target_uid == Some(cheap.uid);
            let direct_child = cheap.ppid == target_pid;
            if !is_target_pid && !same_uid && !direct_child {
                continue;
            }

            let needs_maps = is_target_pid || same_uid || direct_child;
            let info = if needs_maps {
                sample_process(pid, Some(&spec.package), true).unwrap_or(cheap)
            } else {
                cheap
            };

            if is_target_pid && !is_expected_process(&info.cmdline_first, &spec) {
                if seen.insert((pid, "target-spoof")) {
                    log_warn!(
                        "检测到目标进程 cmdline 伪装: pid={} tgid={} expected={} cmdline={} status.Name={}{}",
                        info.pid,
                        info.tgid,
                        spec.expected_process,
                        printable(&info.cmdline_display),
                        printable(&info.status_name),
                        maps_suffix(&info)
                    );
                }
                continue;
            }

            if pid == target_pid || is_target_family_name(&info.cmdline_first, &spec.package) {
                continue;
            }

            if direct_child {
                if seen.insert((pid, "spoof-child")) {
                    scrubbed_inherited_stage1_tail(pid);
                    log_warn!(
                        "检测到疑似伪装 child: pid={} tgid={} ppid={} uid={} cmdline={} status.Name={} tracer={}{}",
                        info.pid,
                        info.tgid,
                        info.ppid,
                        info.uid,
                        printable(&info.cmdline_display),
                        printable(&info.status_name),
                        info.tracer_pid,
                        maps_suffix(&info)
                    );
                }
            } else if same_uid && info.maps_has_package {
                if seen.insert((pid, "package-maps-spoof")) {
                    scrubbed_inherited_stage1_tail(pid);
                    log_warn!(
                        "检测到同 UID 伪装进程归属: pid={} tgid={} uid={} cmdline={} status.Name={} maps 包含 {}{}",
                        info.pid,
                        info.tgid,
                        info.uid,
                        printable(&info.cmdline_display),
                        printable(&info.status_name),
                        spec.package,
                        maps_suffix(&info)
                    );
                }
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
