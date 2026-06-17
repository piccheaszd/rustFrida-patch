#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, uprobe},
    maps::PerfEventArray,
    programs::ProbeContext,
    EbpfContext,
};
use ldmonitor_common::{DlopenEvent, MAX_PATH_LEN};

#[map]
static EVENTS: PerfEventArray<DlopenEvent> = PerfEventArray::new(0);

#[uprobe]
pub fn ldmonitor(ctx: ProbeContext) -> u32 {
    match try_ldmonitor(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ldmonitor(ctx: &ProbeContext) -> Result<u32, u32> {
    // android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo)
    // 第一个参数是路径指针
    let path_ptr: *const u8 = ctx.arg(0).ok_or(1u32)?;

    let mut event = DlopenEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        path_len: 0,
        path: [0u8; MAX_PATH_LEN],
    };

    // 从用户空间读取路径字符串
    if let Ok(path_bytes) = unsafe { bpf_probe_read_user_str_bytes(path_ptr, &mut event.path) } {
        event.path_len = path_bytes.len() as u32;
    }

    EVENTS.output(ctx, &event, 0);
    Ok(0)
}

#[cfg(all(not(test), target_arch = "bpf"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
