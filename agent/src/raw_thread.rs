use crate::gumlibc::gum_libc_syscall_4;
use libc::{
    c_int, c_long, mmap, pid_t, timespec, SYS_clone, SYS_exit, SYS_nanosleep, CLONE_FILES, CLONE_FS, CLONE_SIGHAND,
    CLONE_SYSVSEM, CLONE_THREAD, CLONE_VM, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE, PR_SET_NAME,
};
use std::arch::asm;
use std::ptr::null_mut;

const STACK_SIZE: usize = 1024 * 1024;

struct RawThreadStart {
    name: &'static [u8],
    func: Option<Box<dyn FnOnce() + Send>>,
}

struct PthreadStart {
    name: &'static [u8],
    func: Option<Box<dyn FnOnce() + Send>>,
}

pub(crate) fn spawn_detached<F>(name: &'static [u8], func: F) -> Result<pid_t, String>
where
    F: FnOnce() + Send + 'static,
{
    let stack_base = unsafe {
        mmap(
            null_mut(),
            STACK_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if stack_base == libc::MAP_FAILED {
        return Err("raw thread stack mmap failed".into());
    }

    let start = Box::into_raw(Box::new(RawThreadStart {
        name,
        func: Some(Box::new(func)),
    }));
    let child_stack = unsafe { (stack_base as *mut u8).add(STACK_SIZE) as *mut usize };
    let flags = (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM) as u64;

    match unsafe { raw_clone(raw_thread_entry as *mut usize, start as usize, flags, child_stack) } {
        Ok(tid) => Ok(tid),
        Err(e) => {
            unsafe {
                drop(Box::from_raw(start));
            }
            Err(e)
        }
    }
}

#[cfg(feature = "quickjs")]
pub(crate) fn spawn_pthread_detached<F>(name: &'static [u8], func: F) -> Result<pid_t, String>
where
    F: FnOnce() + Send + 'static,
{
    type PthreadCreateFn = unsafe extern "C" fn(
        *mut libc::pthread_t,
        *const libc::pthread_attr_t,
        extern "C" fn(*mut libc::c_void) -> *mut libc::c_void,
        *mut libc::c_void,
    ) -> libc::c_int;
    type PthreadDetachFn = unsafe extern "C" fn(libc::pthread_t) -> libc::c_int;

    let create_addr = crate::linker::resolve_loaded_symbol("libc.so", "pthread_create")
        .ok_or_else(|| "resolve libc pthread_create failed".to_string())?;
    let detach_addr = crate::linker::resolve_loaded_symbol("libc.so", "pthread_detach")
        .ok_or_else(|| "resolve libc pthread_detach failed".to_string())?;
    let pthread_create: PthreadCreateFn = unsafe { std::mem::transmute(create_addr) };
    let pthread_detach: PthreadDetachFn = unsafe { std::mem::transmute(detach_addr) };

    let start = Box::into_raw(Box::new(PthreadStart {
        name,
        func: Some(Box::new(func)),
    }));

    let mut thread: libc::pthread_t = unsafe { std::mem::zeroed() };
    let ret = unsafe { pthread_create(&mut thread, std::ptr::null(), pthread_thread_entry, start as *mut _) };
    if ret != 0 {
        unsafe {
            drop(Box::from_raw(start));
        }
        return Err(format!("direct pthread_create failed: {}", ret));
    }
    let _ = unsafe { pthread_detach(thread) };

    Ok(0)
}

pub(crate) fn sleep_ms(ms: i64) {
    let req = timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    };
    unsafe {
        gum_libc_syscall_4(SYS_nanosleep as c_long, &req as *const timespec as usize, 0, 0, 0);
    }
}

unsafe fn raw_clone(child_func: *mut usize, arg: usize, flags: u64, child_stack: *mut usize) -> Result<pid_t, String> {
    let mut result: i64;

    *(child_stack.sub(1)) = child_func as usize;
    *(child_stack.sub(2)) = arg;

    asm!(
        "svc 0x0",
        "cbnz x0, 1f",
        "ldp x0, x1, [sp], #16",
        "blr x1",
        "mov x8, {exit_syscall}",
        "mov x0, #0",
        "svc 0x0",
        "1:",
        in("x8") SYS_clone,
        inout("x0") flags => result,
        in("x1") child_stack.sub(2),
        in("x2") 0usize,
        in("x3") 0usize,
        in("x4") 0usize,
        exit_syscall = const SYS_exit,
        options(nostack, preserves_flags),
        clobber_abi("C"),
    );

    if result < 0 {
        Err(format!("raw clone failed: {}", -result))
    } else {
        Ok(result as pid_t)
    }
}

extern "C" fn raw_thread_entry(arg: usize) -> c_int {
    let mut start = unsafe { Box::from_raw(arg as *mut RawThreadStart) };
    unsafe {
        gum_libc_syscall_4(
            libc::SYS_prctl as c_long,
            PR_SET_NAME as usize,
            start.name.as_ptr() as usize,
            0,
            0,
        );
    }

    if let Some(func) = start.func.take() {
        func();
    }

    0
}

#[cfg(feature = "quickjs")]
extern "C" fn pthread_thread_entry(arg: *mut libc::c_void) -> *mut libc::c_void {
    let mut start = unsafe { Box::from_raw(arg as *mut PthreadStart) };
    unsafe {
        gum_libc_syscall_4(
            libc::SYS_prctl as c_long,
            PR_SET_NAME as usize,
            start.name.as_ptr() as usize,
            0,
            0,
        );
    }

    if let Some(func) = start.func.take() {
        func();
    }

    std::ptr::null_mut()
}
