#![cfg(feature = "quickjs")]

use crate::communication::write_stream_raw;
use quickjs_hook::ffi::hook as hook_ffi;
use std::ffi::{c_void, CStr, CString};
use std::fmt::Write as _;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;

const HOOK_NORMAL: i32 = 0;
const HOOK_WXSHADOW: i32 = 1;
const HOOK_RECOMP: i32 = 2;
const HOOK_OK: i32 = 0;
const HOOK_ALREADY_HOOKED: i32 = -3;

static INSTALLED: AtomicBool = AtomicBool::new(false);
static PRCTL_LOGS: AtomicU32 = AtomicU32::new(0);
static PROC_LOGS: AtomicU32 = AtomicU32::new(0);
static LIB_LOGS: AtomicU32 = AtomicU32::new(0);

pub(crate) fn install_bochk_audit(profile: &str) -> Result<String, String> {
    if profile == "runtime" {
        audit_log(format!(
            "[bochk-native-audit] passive runtime probe profile={} hook-runtime=deferred\n",
            profile
        ));
        return Ok("bochk native audit passive runtime probe".to_string());
    }

    match profile {
        "resolve" => return resolve_probe(),
        "read-maps" => return read_proc_probe("/proc/self/maps"),
        "read-status" => return read_proc_probe("/proc/self/status"),
        "read-stat" => return read_proc_probe("/proc/self/stat"),
        "maps-dump" => return dump_maps_probe("maps-dump"),
        _ => {}
    }

    if let Some(probe) = byte_probe_profile(profile) {
        if probe.mode.is_none() {
            let libc = open_libc()?;
            return install_byte_probe(libc, probe);
        }
    }

    if INSTALLED.swap(true, Ordering::AcqRel) {
        return Ok("bochk native audit already installed".to_string());
    }

    crate::quickjs_loader::init_hook_runtime()?;
    audit_log(format!(
        "[bochk-native-audit] hook runtime initialized profile={}\n",
        profile
    ));

    let libc = match open_libc() {
        Ok(libc) => libc,
        Err(e) => {
            INSTALLED.store(false, Ordering::Release);
            return Err(e);
        }
    };

    if let Some(probe) = byte_probe_profile(profile) {
        let result = install_byte_probe(libc, probe);
        if result.is_err() {
            INSTALLED.store(false, Ordering::Release);
        }
        return result;
    }

    let dump_after_install = matches!(profile, "cold-dump" | "cold-wx-dump");
    let hook_profile = match profile {
        "cold-dump" => "cold",
        "cold-wx-dump" => "cold-wx",
        _ => profile,
    };

    let mut installed = 0usize;
    let (hooks, mode): (&[(&str, HookCallback)], i32) = match profile {
        "all" => (
            &[
                ("prctl", prctl_enter as HookCallback),
                ("open", open_enter as HookCallback),
                ("openat", openat_enter as HookCallback),
            ],
            HOOK_NORMAL,
        ),
        "all-wx" => (
            &[
                ("prctl", prctl_enter as HookCallback),
                ("open", open_enter as HookCallback),
                ("openat", openat_enter as HookCallback),
            ],
            HOOK_WXSHADOW,
        ),
        "prctl" => (&[("prctl", prctl_enter as HookCallback)], HOOK_NORMAL),
        "prctl-wx" => (&[("prctl", prctl_enter as HookCallback)], HOOK_WXSHADOW),
        "prctl-silent" => (&[("prctl", silent_enter as HookCallback)], HOOK_NORMAL),
        "prctl-wx-silent" => (&[("prctl", silent_enter as HookCallback)], HOOK_WXSHADOW),
        "open" => (
            &[
                ("open", open_enter as HookCallback),
                ("openat", openat_enter as HookCallback),
            ],
            HOOK_NORMAL,
        ),
        "open-wx" => (
            &[
                ("open", open_enter as HookCallback),
                ("openat", openat_enter as HookCallback),
            ],
            HOOK_WXSHADOW,
        ),
        "open-silent" => (
            &[
                ("open", silent_enter as HookCallback),
                ("openat", silent_enter as HookCallback),
            ],
            HOOK_NORMAL,
        ),
        "open-wx-silent" => (
            &[
                ("open", silent_enter as HookCallback),
                ("openat", silent_enter as HookCallback),
            ],
            HOOK_WXSHADOW,
        ),
        "open-only-wx" => (&[("open", open_enter as HookCallback)], HOOK_WXSHADOW),
        "openat-only-wx" => (&[("openat", openat_enter as HookCallback)], HOOK_WXSHADOW),
        "noop" => (&[("getpid", silent_enter as HookCallback)], HOOK_NORMAL),
        "noop-wx" => (&[("getpid", silent_enter as HookCallback)], HOOK_WXSHADOW),
        _ if hook_profile == "cold" => (&[("memmem", silent_enter as HookCallback)], HOOK_NORMAL),
        _ if hook_profile == "cold-wx" => (&[("memmem", silent_enter as HookCallback)], HOOK_WXSHADOW),
        "cold2" => (&[("ether_ntoa_r", silent_enter as HookCallback)], HOOK_NORMAL),
        "cold2-wx" => (&[("ether_ntoa_r", silent_enter as HookCallback)], HOOK_WXSHADOW),
        _ => {
            INSTALLED.store(false, Ordering::Release);
            return Err(format!("unsupported bochk native audit profile: {}", profile));
        }
    };

    for (symbol, callback) in hooks {
        let addr = unsafe { libc::dlsym(libc, cstr_ptr(symbol)) };
        if addr.is_null() {
            audit_log(format!("[bochk-native-audit] missing libc!{}\n", symbol));
            continue;
        }
        let rc = unsafe { hook_ffi::hook_attach(addr, Some(*callback), None, null_mut(), mode) };
        if rc == HOOK_OK || rc == HOOK_ALREADY_HOOKED {
            installed += 1;
            audit_log(format!(
                "[bochk-native-audit] hooked libc!{} @ 0x{:x} mode={}\n",
                symbol,
                addr as usize,
                hook_mode_name(mode)
            ));
        } else {
            audit_log(format!("[bochk-native-audit] hook libc!{} failed rc={}\n", symbol, rc));
        }
    }

    if installed == 0 {
        INSTALLED.store(false, Ordering::Release);
        Err("bochk native audit installed 0 hooks".to_string())
    } else {
        if dump_after_install {
            dump_maps_interest(profile);
        }
        Ok(format!("bochk native audit installed {} hooks", installed))
    }
}

fn open_libc() -> Result<*mut c_void, String> {
    let libc = unsafe { libc::dlopen(c"libc.so".as_ptr(), libc::RTLD_NOW) };
    if libc.is_null() {
        Err("dlopen(libc.so) failed".to_string())
    } else {
        Ok(libc)
    }
}

type HookCallback = unsafe extern "C" fn(*mut hook_ffi::HookContext, *mut c_void);

fn hook_mode_name(mode: i32) -> &'static str {
    match mode {
        HOOK_WXSHADOW => "wxshadow",
        HOOK_RECOMP => "recomp",
        _ => "normal",
    }
}

fn cstr_ptr(symbol: &str) -> *const u8 {
    match symbol {
        "prctl" => c"prctl".as_ptr(),
        "open" => c"open".as_ptr(),
        "openat" => c"openat".as_ptr(),
        "getpid" => c"getpid".as_ptr(),
        "memmem" => c"memmem".as_ptr(),
        "ether_ntoa_r" => c"ether_ntoa_r".as_ptr(),
        _ => c"".as_ptr(),
    }
}

#[derive(Clone, Copy)]
struct ByteProbe {
    symbol: &'static str,
    mode: Option<i32>,
    after: ByteAfterMode,
}

#[derive(Clone, Copy)]
enum ByteAfterMode {
    Full,
    MapOnly,
    AsyncMemoryOnly,
    None,
}

fn byte_probe_profile(profile: &str) -> Option<ByteProbe> {
    match profile {
        "bytes-getpid" => Some(ByteProbe {
            symbol: "getpid",
            mode: None,
            after: ByteAfterMode::Full,
        }),
        "bytes-noop" => Some(ByteProbe {
            symbol: "getpid",
            mode: Some(HOOK_NORMAL),
            after: ByteAfterMode::Full,
        }),
        "bytes-noop-wx" => Some(ByteProbe {
            symbol: "getpid",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::Full,
        }),
        "bytes-noop-recomp" => Some(ByteProbe {
            symbol: "getpid",
            mode: Some(HOOK_RECOMP),
            after: ByteAfterMode::Full,
        }),
        "bytes-cold" => Some(ByteProbe {
            symbol: "memmem",
            mode: Some(HOOK_NORMAL),
            after: ByteAfterMode::Full,
        }),
        "bytes-cold-wx" => Some(ByteProbe {
            symbol: "memmem",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::Full,
        }),
        "bytes-cold2" => Some(ByteProbe {
            symbol: "ether_ntoa_r",
            mode: Some(HOOK_NORMAL),
            after: ByteAfterMode::Full,
        }),
        "bytes-cold2-wx" => Some(ByteProbe {
            symbol: "ether_ntoa_r",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::Full,
        }),
        "bytes-cold2-wx-maponly" => Some(ByteProbe {
            symbol: "ether_ntoa_r",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::MapOnly,
        }),
        "bytes-cold2-wx-fast" => Some(ByteProbe {
            symbol: "ether_ntoa_r",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::AsyncMemoryOnly,
        }),
        "bytes-cold2-wx-patchonly" => Some(ByteProbe {
            symbol: "ether_ntoa_r",
            mode: Some(HOOK_WXSHADOW),
            after: ByteAfterMode::None,
        }),
        _ => None,
    }
}

fn install_byte_probe(libc: *mut c_void, probe: ByteProbe) -> Result<String, String> {
    let symbol = probe.symbol;
    let mode = probe.mode;
    let addr = unsafe { libc::dlsym(libc, cstr_ptr(symbol)) };
    if addr.is_null() {
        return Err(format!("missing libc!{}", symbol));
    }

    audit_log(format!(
        "[bochk-native-audit] bytes symbol=libc!{} addr=0x{:x} mode={}\n",
        symbol,
        addr as usize,
        mode.map(hook_mode_name).unwrap_or("none")
    ));
    snapshot_symbol_bytes(symbol, addr as usize, "before");

    let mut hooked = false;
    if let Some(mode) = mode {
        install_byte_hook(addr as usize, mode)?;
        hooked = true;
        audit_log(format!(
            "[bochk-native-audit] bytes hooked libc!{} @ 0x{:x} mode={}\n",
            symbol,
            addr as usize,
            hook_mode_name(mode)
        ));
    }

    match probe.after {
        ByteAfterMode::Full => snapshot_symbol_bytes(symbol, addr as usize, "after"),
        ByteAfterMode::MapOnly => snapshot_symbol_map(symbol, addr as usize, "after-map"),
        ByteAfterMode::AsyncMemoryOnly => {
            let addr = addr as usize;
            thread::spawn(move || {
                audit_log(format!(
                    "[bochk-native-audit] bytes after-async-start libc!{} addr=0x{:x}\n",
                    symbol, addr
                ));
                snapshot_symbol_memory_bytes(symbol, addr, "after-async");
            });
        }
        ByteAfterMode::None => {
            audit_log(format!("[bochk-native-audit] bytes after skipped libc!{}\n", symbol));
        }
    }
    Ok(format!(
        "bochk native audit bytes probe {}{}",
        symbol,
        if hooked { " hooked" } else { "" }
    ))
}

fn install_byte_hook(orig_addr: usize, mode: i32) -> Result<(), String> {
    let (hook_addr, engine_mode) = if mode == HOOK_RECOMP {
        quickjs_hook::recomp::ensure_and_translate(orig_addr)
            .map_err(|e| format!("recomp translate 0x{:x}: {}", orig_addr, e))?;
        let slot = quickjs_hook::recomp::alloc_trampoline_slot(orig_addr)
            .map_err(|e| format!("recomp slot 0x{:x}: {}", orig_addr, e))?;
        (slot, HOOK_NORMAL)
    } else {
        (orig_addr, mode)
    };

    let rc = unsafe {
        hook_ffi::hook_attach(
            hook_addr as *mut c_void,
            Some(silent_enter),
            None,
            null_mut(),
            engine_mode,
        )
    };
    if rc != HOOK_OK && rc != HOOK_ALREADY_HOOKED {
        if mode == HOOK_RECOMP {
            let _ = quickjs_hook::recomp::try_revert_slot_patch(orig_addr);
        }
        return Err(format!(
            "hook attach 0x{:x} mode={} failed rc={}",
            orig_addr,
            hook_mode_name(mode),
            rc
        ));
    }

    if mode != HOOK_RECOMP {
        return Ok(());
    }

    let trampoline = unsafe { hook_ffi::hook_get_trampoline(hook_addr as *mut c_void) };
    if trampoline.is_null() {
        unsafe {
            hook_ffi::hook_remove(hook_addr as *mut c_void);
        }
        let _ = quickjs_hook::recomp::try_revert_slot_patch(orig_addr);
        return Err(format!("recomp hook trampoline is null for 0x{:x}", orig_addr));
    }

    if let Err(e) = quickjs_hook::recomp::fixup_slot_trampoline(trampoline as *mut u8, orig_addr) {
        unsafe {
            hook_ffi::hook_remove(hook_addr as *mut c_void);
        }
        let _ = quickjs_hook::recomp::try_revert_slot_patch(orig_addr);
        return Err(format!("recomp fixup trampoline 0x{:x}: {}", orig_addr, e));
    }

    let mark_rc = unsafe { hook_ffi::hook_mark_recomp_hook(hook_addr as *mut c_void) };
    if mark_rc != HOOK_OK {
        unsafe {
            hook_ffi::hook_remove(hook_addr as *mut c_void);
        }
        let _ = quickjs_hook::recomp::try_revert_slot_patch(orig_addr);
        return Err(format!("recomp mark hook 0x{:x} failed rc={}", orig_addr, mark_rc));
    }

    if let Err(e) = quickjs_hook::recomp::commit_slot_patch(orig_addr) {
        unsafe {
            hook_ffi::hook_remove(hook_addr as *mut c_void);
        }
        let _ = quickjs_hook::recomp::try_revert_slot_patch(orig_addr);
        return Err(format!("recomp commit slot 0x{:x}: {}", orig_addr, e));
    }

    audit_log(format!(
        "[bochk-native-audit] bytes recomp slot orig=0x{:x} slot=0x{:x}\n",
        orig_addr, hook_addr
    ));
    Ok(())
}

fn snapshot_symbol_map(symbol: &str, addr: usize, tag: &str) {
    let Some(mapping) = find_mapping_for_addr(addr) else {
        audit_log(format!(
            "[bochk-native-audit] bytes {} libc!{} map=missing\n",
            tag, symbol
        ));
        return;
    };
    audit_log(format!(
        "[bochk-native-audit] bytes {} libc!{} map={} rel=0x{:x}\n",
        tag,
        symbol,
        mapping.line,
        addr - mapping.start
    ));
    dump_maps_matching(tag, "/apex/com.android.runtime/lib64/bionic/libc.so", 16);
}

fn snapshot_symbol_memory_bytes(symbol: &str, addr: usize, tag: &str) {
    const BYTE_LEN: usize = 32;

    let memory = unsafe { std::slice::from_raw_parts(addr as *const u8, BYTE_LEN) };
    let memory_hex = hex_bytes(memory);
    audit_log(format!(
        "[bochk-native-audit] bytes {} libc!{} mem={}\n",
        tag, symbol, memory_hex
    ));
}

fn snapshot_symbol_bytes(symbol: &str, addr: usize, tag: &str) {
    const BYTE_LEN: usize = 32;

    let memory = unsafe { std::slice::from_raw_parts(addr as *const u8, BYTE_LEN) };
    let memory_hex = hex_bytes(memory);

    let Some(mapping) = find_mapping_for_addr(addr) else {
        audit_log(format!(
            "[bochk-native-audit] bytes {} libc!{} mem={} map=missing\n",
            tag, symbol, memory_hex
        ));
        return;
    };

    let file_offset = mapping.offset + (addr - mapping.start);
    let disk = mapping
        .path
        .as_deref()
        .and_then(|path| read_file_at(path, file_offset, BYTE_LEN).ok());
    let disk_hex = disk
        .as_deref()
        .map(hex_bytes)
        .unwrap_or_else(|| "unreadable".to_string());
    let same = disk.as_deref().map(|bytes| bytes == memory).unwrap_or(false);

    audit_log(format!(
        "[bochk-native-audit] bytes {} libc!{} mem={} disk={} same={} file_off=0x{:x} map={}\n",
        tag, symbol, memory_hex, disk_hex, same, file_offset, mapping.line
    ));
}

struct MapInfo {
    start: usize,
    offset: usize,
    path: Option<String>,
    line: String,
}

fn find_mapping_for_addr(addr: usize) -> Option<MapInfo> {
    let data = read_proc_file("/proc/self/maps", 128 * 1024).ok()?;
    let text = std::str::from_utf8(&data).ok()?;

    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let _perms = parts.next()?;
        let offset = parts.next()?;
        let _dev = parts.next()?;
        let _inode = parts.next()?;
        let path = parts.next().map(ToOwned::to_owned);

        let (start, end) = parse_addr_range(range)?;
        if addr < start || addr >= end {
            continue;
        }
        let offset = usize::from_str_radix(offset, 16).ok()?;
        return Some(MapInfo {
            start,
            offset,
            path,
            line: line.to_string(),
        });
    }

    None
}

fn parse_addr_range(range: &str) -> Option<(usize, usize)> {
    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    Some((start, end))
}

fn read_file_at(path: &str, offset: usize, len: usize) -> Result<Vec<u8>, String> {
    let c_path = CString::new(path).map_err(|_| format!("invalid path: {}", path))?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open({}) failed", path));
    }

    let mut data = vec![0u8; len];
    let n = unsafe { libc::pread(fd, data.as_mut_ptr().cast(), data.len(), offset as libc::off_t) };
    unsafe {
        libc::close(fd);
    }
    if n < 0 {
        return Err(format!("pread({}) failed", path));
    }
    data.truncate(n as usize);
    Ok(data)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

unsafe extern "C" fn silent_enter(_ctx: *mut hook_ffi::HookContext, _user_data: *mut c_void) {}

unsafe extern "C" fn prctl_enter(ctx: *mut hook_ffi::HookContext, _user_data: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let count = PRCTL_LOGS.fetch_add(1, Ordering::Relaxed);
    if count >= 96 {
        return;
    }

    let ctx = unsafe { &*ctx };
    let op = ctx.x[0];
    let arg1 = ctx.x[1];
    let lr = ctx.x[30];
    audit_log(format!(
        "[bochk-native-audit] prctl op={} arg1=0x{:x} lr=0x{:x}\n",
        op, arg1, lr
    ));
}

unsafe extern "C" fn open_enter(ctx: *mut hook_ffi::HookContext, _user_data: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let path = unsafe { (*ctx).x[0] as *const u8 };
    audit_path("open", path);
}

unsafe extern "C" fn openat_enter(ctx: *mut hook_ffi::HookContext, _user_data: *mut c_void) {
    if ctx.is_null() {
        return;
    }
    let path = unsafe { (*ctx).x[1] as *const u8 };
    audit_path("openat", path);
}

fn audit_path(kind: &str, path: *const u8) {
    if path.is_null() {
        return;
    }
    let Ok(path) = (unsafe { CStr::from_ptr(path) }).to_str() else {
        return;
    };

    if path.contains("libbochk_aos.so") {
        let count = LIB_LOGS.fetch_add(1, Ordering::Relaxed);
        if count < 8 {
            audit_log(format!("[bochk-native-audit] {} {}\n", kind, path));
        }
        return;
    }

    if is_interesting_proc_path(path) {
        let count = PROC_LOGS.fetch_add(1, Ordering::Relaxed);
        if count < 64 {
            audit_log(format!("[bochk-native-audit] {} {}\n", kind, path));
        }
    }
}

fn is_interesting_proc_path(path: &str) -> bool {
    if !path.starts_with("/proc/") {
        return false;
    }
    path.ends_with("/cmdline")
        || path.ends_with("/status")
        || path.ends_with("/maps")
        || path.ends_with("/stat")
        || path == "/proc/self/cmdline"
        || path == "/proc/self/status"
        || path == "/proc/self/maps"
        || path == "/proc/self/stat"
}

fn audit_log(msg: String) {
    write_stream_raw(msg.as_bytes());
}

fn resolve_probe() -> Result<String, String> {
    let libc = open_libc()?;

    let symbols = ["prctl", "open", "openat", "getpid", "memmem", "ether_ntoa_r"];
    let mut resolved = 0usize;
    for symbol in symbols {
        let addr = unsafe { libc::dlsym(libc, cstr_ptr(symbol)) };
        audit_log(format!(
            "[bochk-native-audit] resolve libc!{} -> 0x{:x}\n",
            symbol, addr as usize
        ));
        if !addr.is_null() {
            resolved += 1;
        }
    }
    Ok(format!("bochk native audit resolved {} symbols", resolved))
}

fn read_proc_probe(path: &str) -> Result<String, String> {
    let Some(c_path) = proc_path_ptr(path) else {
        return Err(format!("unsupported proc probe path: {}", path));
    };

    let fd = unsafe { libc::open(c_path, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open({}) failed", path));
    }

    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe {
        libc::close(fd);
    }
    if n < 0 {
        return Err(format!("read({}) failed", path));
    }

    let preview_len = (n as usize).min(buf.len());
    let mut preview = String::from_utf8_lossy(&buf[..preview_len]).into_owned();
    if let Some(pos) = preview.find('\n') {
        preview.truncate(pos);
    }
    audit_log(format!(
        "[bochk-native-audit] read-proc {} bytes={} first={}\n",
        path, n, preview
    ));
    Ok(format!("bochk native audit read {}", path))
}

fn dump_maps_probe(tag: &str) -> Result<String, String> {
    dump_maps_interest(tag);
    Ok("bochk native audit dumped maps".to_string())
}

fn dump_maps_interest(tag: &str) {
    let Ok(data) = read_proc_file("/proc/self/maps", 128 * 1024) else {
        audit_log(format!("[bochk-native-audit] maps-dump {} read failed\n", tag));
        return;
    };
    let Ok(text) = std::str::from_utf8(&data) else {
        audit_log(format!("[bochk-native-audit] maps-dump {} utf8 failed\n", tag));
        return;
    };

    let mut total = 0usize;
    let mut emitted = 0usize;
    for line in text.lines() {
        if !is_interesting_maps_line(line) {
            continue;
        }
        total += 1;
        if emitted < 64 {
            audit_log(format!("[bochk-native-audit] maps-dump {} {}\n", tag, line));
            emitted += 1;
        }
    }
    audit_log(format!(
        "[bochk-native-audit] maps-dump {} total={} emitted={}\n",
        tag, total, emitted
    ));
}

fn dump_maps_matching(tag: &str, needle: &str, limit: usize) {
    let Ok(data) = read_proc_file("/proc/self/maps", 128 * 1024) else {
        audit_log(format!("[bochk-native-audit] maps-match {} read failed\n", tag));
        return;
    };
    let Ok(text) = std::str::from_utf8(&data) else {
        audit_log(format!("[bochk-native-audit] maps-match {} utf8 failed\n", tag));
        return;
    };

    let mut total = 0usize;
    let mut emitted = 0usize;
    for line in text.lines() {
        if !line.contains(needle) {
            continue;
        }
        total += 1;
        if emitted < limit {
            audit_log(format!("[bochk-native-audit] maps-match {} {}\n", tag, line));
            emitted += 1;
        }
    }
    audit_log(format!(
        "[bochk-native-audit] maps-match {} needle={} total={} emitted={}\n",
        tag, needle, total, emitted
    ));
}

fn read_proc_file(path: &str, max_len: usize) -> Result<Vec<u8>, String> {
    let Some(c_path) = proc_path_ptr(path) else {
        return Err(format!("unsupported proc path: {}", path));
    };
    let fd = unsafe { libc::open(c_path, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(format!("open({}) failed", path));
    }

    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while data.len() < max_len {
        let want = buf.len().min(max_len - data.len());
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), want) };
        if n < 0 {
            unsafe {
                libc::close(fd);
            }
            return Err(format!("read({}) failed", path));
        }
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n as usize]);
    }
    unsafe {
        libc::close(fd);
    }
    Ok(data)
}

fn proc_path_ptr(path: &str) -> Option<*const libc::c_char> {
    match path {
        "/proc/self/maps" => Some(c"/proc/self/maps".as_ptr()),
        "/proc/self/status" => Some(c"/proc/self/status".as_ptr()),
        "/proc/self/stat" => Some(c"/proc/self/stat".as_ptr()),
        _ => None,
    }
}

fn is_interesting_maps_line(line: &str) -> bool {
    let line_lower = line.to_ascii_lowercase();
    if line_lower.contains("memfd")
        || line_lower.contains("frida")
        || line_lower.contains("hook")
        || line_lower.contains("quickjs")
        || line_lower.contains("wx")
        || line_lower.contains("rwxp")
    {
        return true;
    }

    let executable = line.contains("r-xp") || line.contains("--xp");
    executable
        && !line.contains("/apex/")
        && !line.contains("/system/")
        && !line.contains("/vendor/")
        && !line.contains("/product/")
        && !line.contains("/system_ext/")
        && !line.contains("/data/app/")
}
