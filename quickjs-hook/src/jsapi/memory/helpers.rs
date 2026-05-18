//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::jsapi::util::{proc_maps_entries, read_proc_self_maps};
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// 从 NativePointer this 或 argv[0] 取地址，返回 (addr, remaining_argv, remaining_argc)。
/// 适配两种调用风格:
///   - `Memory.readU32(addr)` → this 不是 NativePointer, addr = argv[0]
///   - `ptr(addr).readU32()` → this 是 NativePointer, addr = this
pub(super) unsafe fn get_addr_this_or_arg(
    ctx: *mut ffi::JSContext,
    this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Option<(u64, *mut ffi::JSValue, i32)> {
    // 先尝试从 this 取（NativePointer 方法风格）
    if let Some(addr) = get_native_pointer_addr(ctx, JSValue(this)) {
        return Some((addr, argv, argc));
    }
    // Fallback: Memory.readXxx(addr, ...) 风格，argv[0] 是地址
    if argc < 1 {
        return None;
    }
    let addr = get_addr_from_arg(ctx, JSValue(*argv))?;
    Some((addr, argv.add(1), argc - 1))
}

/// Parse page permissions for `addr` from /proc/self/maps.
/// Returns the libc PROT_* flags for the page, or `None` if not found.
fn is_range_writable(addr: u64, size: usize) -> bool {
    if addr == 0 || size == 0 {
        return false;
    }
    let end = match addr.checked_add(size as u64) {
        Some(v) => v,
        None => return false,
    };
    let Some(maps) = read_proc_self_maps() else {
        return false;
    };
    let mut cursor = addr;

    for entry in proc_maps_entries(&maps) {
        if entry.end <= cursor {
            continue;
        }
        if entry.start > cursor {
            return false;
        }
        if (entry.prot_flags() & libc::PROT_WRITE) == 0 {
            return false;
        }
        cursor = entry.end.min(end);
        if cursor >= end {
            return true;
        }
    }

    false
}

/// 尝试在 `addr` 处执行 `write_fn`。**不再自动 mprotect** — 避免跨页限制、
/// 权限恢复失败等隐性问题。行为明确:
///   - 目标范围完整落在 `PROT_WRITE` VMA 中 (rw- / rwx) → 直接执行 write
///   - `/proc/self/maps` 查不到完整范围或任一覆盖 VMA 不可写 → 返回 false,
///     调用方应抛错提示 user
///     先调 `Memory.protect(addr, size, "rwx")` 或 `p.protect(size, "rwx")`
///
/// 返回 `true` = 写入已执行; `false` = 目标页不可写, 未执行。
pub(super) unsafe fn write_with_perm(addr: u64, size: usize, write_fn: impl FnOnce()) -> bool {
    if is_range_writable(addr, size) {
        write_fn();
        return true;
    }
    false
}
