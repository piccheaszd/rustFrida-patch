use libc::{c_int, c_long, c_void, pthread_t, timespec, SYS_nanosleep};
use std::arch::asm;

#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    _thread: *mut pthread_t,
    _attr: *const c_void,
    _start: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
    _arg: *mut c_void,
) -> c_int {
    libc::ENOSYS
}

#[no_mangle]
pub unsafe extern "C" fn pthread_detach(_thread: pthread_t) -> c_int {
    0
}

#[no_mangle]
pub unsafe extern "C" fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    let mut result: c_long;
    asm!(
        "svc 0x0",
        in("x8") SYS_nanosleep,
        inout("x0") req as usize => result,
        in("x1") rem as usize,
        options(nostack, preserves_flags),
    );
    if result < 0 {
        -1
    } else {
        result as c_int
    }
}
