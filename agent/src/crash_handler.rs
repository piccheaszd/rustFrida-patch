//! crash/panic 处理模块 - 安装信号处理器和 panic hook
//!
//! 关键设计: 不能直接覆盖 ART/libsigchain 的 SIGSEGV 链。
//! ART 运行时依赖 signal chain 实现隐式空指针检查、栈溢出检测等。
//! 这里通过我们自己的 linker 解析 libsigchain special handler API，
//! 只消费 agent 明确处理的信号，其余信号交回原链。
//! SIGSEGV/SIGBUS 属于 ART 隐式异常关键路径，当前目标 app 对 claim 这条链敏感，
//! 所以默认不安装这两个信号，避免破坏启动阶段的 managed null-check。

use crate::{
    communication::{log_msg, write_stream_raw},
    linker,
};
use libc::{c_int, c_void, siginfo_t, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV, SIGTRAP};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// ============================================================================
// 信号处理器状态
// ============================================================================
const MAX_AGENT_MEMFD_RANGES: usize = 16;
const CRASH_SIGNALS: [c_int; 4] = [SIGABRT, SIGFPE, SIGILL, SIGTRAP];

static CRASH_HANDLERS_INSTALLED: AtomicBool = AtomicBool::new(false);

static AGENT_MEMFD_RANGE_START: [AtomicUsize; MAX_AGENT_MEMFD_RANGES] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; MAX_AGENT_MEMFD_RANGES]
};

static AGENT_MEMFD_RANGE_END: [AtomicUsize; MAX_AGENT_MEMFD_RANGES] = {
    const INIT: AtomicUsize = AtomicUsize::new(0);
    [INIT; MAX_AGENT_MEMFD_RANGES]
};

#[repr(C)]
struct SigchainAction {
    sc_sigaction: Option<unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void) -> bool>,
    sc_mask: libc::sigset_t,
    sc_flags: u64,
}

fn refresh_agent_memfd_ranges() {
    for i in 0..MAX_AGENT_MEMFD_RANGES {
        AGENT_MEMFD_RANGE_START[i].store(0, Ordering::Release);
        AGENT_MEMFD_RANGE_END[i].store(0, Ordering::Release);
    }

    for (i, (start, end)) in linker::memfd_ranges(MAX_AGENT_MEMFD_RANGES).into_iter().enumerate() {
        AGENT_MEMFD_RANGE_START[i].store(start, Ordering::Release);
        AGENT_MEMFD_RANGE_END[i].store(end, Ordering::Release);
    }
}

// _Unwind_Backtrace 相关定义
type UnwindReasonCode = c_int;
type UnwindContext = c_void;

extern "C" {
    fn _Unwind_Backtrace(
        trace_fn: extern "C" fn(*mut UnwindContext, *mut c_void) -> UnwindReasonCode,
        data: *mut c_void,
    ) -> UnwindReasonCode;
    fn _Unwind_GetIP(ctx: *mut UnwindContext) -> usize;
}

struct BacktraceData {
    frames: Vec<usize>,
    max_frames: usize,
}

extern "C" fn unwind_callback(ctx: *mut UnwindContext, data: *mut c_void) -> UnwindReasonCode {
    unsafe {
        let bt_data = &mut *(data as *mut BacktraceData);
        if bt_data.frames.len() >= bt_data.max_frames {
            return 5; // _URC_END_OF_STACK
        }
        let ip = _Unwind_GetIP(ctx);
        if ip != 0 {
            bt_data.frames.push(ip);
        }
        0 // _URC_NO_REASON (continue)
    }
}

/// 使用 _Unwind_Backtrace 获取调用栈
fn collect_backtrace() -> Vec<usize> {
    let mut data = BacktraceData {
        frames: Vec::with_capacity(64),
        max_frames: 64,
    };
    unsafe {
        _Unwind_Backtrace(unwind_callback, &mut data as *mut _ as *mut c_void);
    }
    data.frames
}

/// 从 ucontext 提取 ARM64 寄存器状态
unsafe fn dump_registers(ucontext: *mut c_void) -> String {
    if ucontext.is_null() {
        return "  (ucontext is NULL)\n".to_string();
    }
    // ucontext_t on aarch64-linux-android (bionic):
    //   uc_flags(8) + uc_link(8) + uc_stack(24) + uc_sigmask(8) + __padding(120) = 168
    //   + 8 bytes alignment padding → mcontext_t at offset 176
    //   mcontext_t (struct sigcontext):
    //     fault_address(8) + regs[31](248) + sp(8) + pc(8) + pstate(8)
    let uc = ucontext as *const u8;
    let mctx = 176usize; // mcontext_t offset in ucontext_t
    let regs = uc.add(mctx + 8) as *const u64; // regs[0..31]
    let sp = *(uc.add(mctx + 256) as *const u64); // sp
    let pc = *(uc.add(mctx + 264) as *const u64); // pc
    let pstate = *(uc.add(mctx + 272) as *const u64); // pstate

    let mut s = String::new();
    // PC with symbol resolution
    let resolved = linker::resolve_symbol(pc as usize);
    s.push_str(&format!("  PC:  0x{:016x}", pc));
    match (resolved.module, resolved.symbol) {
        (Some(lib), Some(sym)) => s.push_str(&format!(" ({} {}+0x{:x})", lib, sym, resolved.offset)),
        (Some(lib), None) => s.push_str(&format!(" ({} +0x{:x})", lib, resolved.offset)),
        _ => {}
    }
    s.push('\n');
    s.push_str(&format!("  SP:  0x{:016x}  PSTATE: 0x{:x}\n", sp, pstate));

    // x0-x30 in rows of 4
    for row in 0..8 {
        for col in 0..4 {
            let i = row * 4 + col;
            if i > 30 {
                break;
            }
            s.push_str(&format!("  x{:<2}=0x{:016x}", i, *regs.add(i)));
        }
        s.push('\n');
    }
    s
}

unsafe fn extract_pc_from_ucontext(ucontext: *mut c_void) -> Option<usize> {
    if ucontext.is_null() {
        return None;
    }
    let uc = ucontext as *const u8;
    let mctx = 176usize;
    Some(*(uc.add(mctx + 264) as *const u64) as usize)
}

unsafe fn dump_code_bytes(addr: usize, label: &str) -> String {
    if addr == 0 {
        return String::new();
    }

    let start = addr.saturating_sub(32);
    let mut s = String::new();
    s.push_str(&format!("\n=== {} BYTES ===\n", label));

    for line_start in (start..start + 64).step_by(16) {
        s.push_str(&format!("  0x{line_start:016x}:"));
        for i in 0..16 {
            let cur = line_start + i;
            let byte = *(cur as *const u8);
            s.push_str(&format!(" {:02x}", byte));
        }
        if addr >= line_start && addr < line_start + 16 {
            s.push_str("  <==");
        }
        s.push('\n');
    }

    s
}

// ============================================================================
// 信号处理函数
// ============================================================================

/// 64 字节全零 dummy OAT header — WalkStack NULL header 修复用
static DUMMY_OAT_HEADER_BUF: [u8; 64] = [0u8; 64];

/// 判断崩溃 PC 是否在 agent 代码（memfd 加载的 SO）中。
unsafe fn is_crash_in_agent(ucontext: *mut c_void) -> bool {
    let pc = match extract_pc_from_ucontext(ucontext) {
        Some(pc) => pc,
        None => return false,
    };

    for i in 0..MAX_AGENT_MEMFD_RANGES {
        let start = AGENT_MEMFD_RANGE_START[i].load(Ordering::Acquire);
        let end = AGENT_MEMFD_RANGE_END[i].load(Ordering::Acquire);
        if start != 0 && pc >= start && pc < end {
            return true;
        }
    }

    false
}

unsafe extern "C" fn crash_signal_handler(sig: c_int, info: *mut siginfo_t, ucontext: *mut c_void) -> bool {
    unsafe {
        if !CRASH_HANDLERS_INSTALLED.load(Ordering::Acquire) {
            return false;
        }

        // --- WalkStack/GetDexPc NULL OatQuickMethodHeader 修复 (API 36) ---
        // ART 的 WalkStack/GetDexPc/DecodeGcMasksOnly 在处理被 hook 方法的栈帧时，
        // 可能对 NULL OatQuickMethodHeader 执行字段读取，既可能是 NULL+0x18，
        // 也可能是 NULL+0x0 等前 64 字节访问。
        // 修复: 解码当前 load 指令找到 base 寄存器 Xn，将其指向全零 dummy buffer。
        if sig == SIGSEGV && !info.is_null() && !ucontext.is_null() {
            let fault_addr = (*info).si_addr() as u64;
            if fault_addr < DUMMY_OAT_HEADER_BUF.len() as u64 {
                // bionic ucontext_t 布局: mcontext_t at offset 176
                // regs[0..30] at +8, sp at +256, pc at +264
                let uc_raw = ucontext as *mut u8;
                let regs_ptr = uc_raw.add(176 + 8) as *mut u64;
                let pc = *(uc_raw.add(176 + 264) as *const u64);
                // 读取崩溃指令 (ARM64 little-endian 4 bytes)
                let insn = *(pc as *const u32);
                // 解码 LDR (unsigned offset): 1x11 1001 01ii iiii iiii iinn nnnt tttt
                // 或 LDR Wt: 1011 1001 01.. ....
                // 提取 Rn (base register): bits [9:5]
                let is_ldr_unsigned = (insn & 0x3B000000) == 0x39000000;
                if is_ldr_unsigned {
                    let rn = ((insn >> 5) & 0x1F) as usize;
                    if rn < 31 && *regs_ptr.add(rn) == 0 {
                        *regs_ptr.add(rn) = DUMMY_OAT_HEADER_BUF.as_ptr() as u64;
                        return true; // 恢复执行
                    }
                }
            }
        }

        // libsigchain special handler 语义: true 表示已处理，false 表示继续原链。
        // 非 agent 信号必须直接放行，避免干扰 ART 隐式 null check / suspend check。

        let in_agent = is_crash_in_agent(ucontext);

        if !in_agent {
            return false;
        }

        // --- Crash 报告 ---
        // 仅在 agent 代码崩溃时执行，然后继续原链生成 tombstone。

        let sig_name = match sig {
            SIGSEGV => "SIGSEGV (Segmentation Fault)",
            SIGBUS => "SIGBUS (Bus Error)",
            SIGABRT => "SIGABRT (Abort)",
            SIGFPE => "SIGFPE (Floating Point Exception)",
            SIGILL => "SIGILL (Illegal Instruction)",
            SIGTRAP => "SIGTRAP (Trap)",
            _ => "Unknown signal",
        };

        let fault_addr = if !info.is_null() { (*info).si_addr() as usize } else { 0 };

        // 构建崩溃信息
        let mut crash_msg = format!(
            "\n\n=== CRASH DETECTED ===\n\
             Signal: {} ({})\n\
             Fault Address: 0x{:x}\n\
             PID: {}\n\
             TID: {}\n",
            sig_name,
            sig,
            fault_addr,
            process::id(),
            libc::gettid()
        );

        // 如果是 SIGABRT，尝试获取 abort message
        if sig == SIGABRT {
            if let Some(abort_msg) = linker::get_abort_message() {
                crash_msg.push_str(&format!("Abort Message: {}\n", abort_msg));
            }
        }

        // 打印寄存器状态
        crash_msg.push_str("\n=== REGISTERS ===\n");
        crash_msg.push_str(&dump_registers(ucontext));

        if let Some(pc) = extract_pc_from_ucontext(ucontext) {
            crash_msg.push_str(&dump_code_bytes(pc, "PC"));
        }
        crash_msg.push_str("\n=== BACKTRACE ===\n");

        // 使用 _Unwind_Backtrace 获取调用栈
        let frames = collect_backtrace();

        {
            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                let resolved = linker::resolve_symbol(addr);

                match (resolved.module, resolved.symbol) {
                    (Some(lib), Some(sym)) => {
                        if linker::is_module_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd) {}+0x{:x}", sym, resolved.offset));
                        } else {
                            crash_msg.push_str(&format!(" {} ({}+0x{:x})", lib, sym, resolved.offset));
                        }
                    }
                    (Some(lib), None) => {
                        if linker::is_module_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd+0x{:x})", resolved.offset));
                        } else {
                            crash_msg.push_str(&format!(" {} +0x{:x}", lib, resolved.offset));
                        }
                    }
                    _ => {
                        crash_msg.push_str(" <unknown>");
                    }
                }
                crash_msg.push('\n');
            }
        }

        crash_msg.push_str("=== END BACKTRACE ===\n\n");

        // 尝试通过 socket 发送
        write_stream_raw(crash_msg.as_bytes());

        false
    }
}

/// 安装崩溃信号处理器
///
/// 关键: 使用 libsigchain special handler，不直接调用 sigaction 覆盖原 handler。
/// libsigchain 符号由 agent::linker 自解析，避免依赖系统 linker API。
/// 不 claim SIGSEGV/SIGBUS，避免影响 ART FaultManager 的隐式异常处理。
pub(crate) fn install_crash_handlers() {
    refresh_agent_memfd_ranges();

    if CRASH_HANDLERS_INSTALLED.load(Ordering::Acquire) {
        return;
    }

    let Some(add_addr) = linker::resolve_loaded_symbol("libsigchain.so", "AddSpecialSignalHandlerFn") else {
        log_msg("crash handler skipped: AddSpecialSignalHandlerFn not found via custom linker\n".to_string());
        return;
    };

    let ensure_front_addr = linker::resolve_loaded_symbol("libsigchain.so", "EnsureFrontOfChain");

    unsafe {
        type AddSpecialSignalHandlerFn = unsafe extern "C" fn(c_int, *mut SigchainAction);
        type EnsureFrontOfChainFn = unsafe extern "C" fn(c_int);

        let add_fn: AddSpecialSignalHandlerFn = std::mem::transmute(add_addr);
        let ensure_front_fn: Option<EnsureFrontOfChainFn> = ensure_front_addr.map(|addr| std::mem::transmute(addr));

        for &sig in &CRASH_SIGNALS {
            let mut action: SigchainAction = std::mem::zeroed();
            action.sc_sigaction = Some(crash_signal_handler);
            libc::sigemptyset(&mut action.sc_mask);
            action.sc_flags = 0;

            add_fn(sig, &mut action as *mut SigchainAction);

            if let Some(ensure_front) = ensure_front_fn {
                ensure_front(sig);
            }
        }
    }

    CRASH_HANDLERS_INSTALLED.store(true, Ordering::Release);
    log_msg("crash handler installed through libsigchain via custom linker (SIGSEGV/SIGBUS skipped)\n".to_string());
}

/// 停用崩溃信号处理器。
/// libsigchain special handler 不覆盖原 sigaction；停用后 handler 直接返回 false。
pub(crate) fn uninstall_crash_handlers() {
    if !CRASH_HANDLERS_INSTALLED.swap(false, Ordering::AcqRel) {
        return;
    }
}

/// 安装Rust panic hook，捕获panic并输出带符号的backtrace
pub(crate) fn install_panic_hook() {
    use std::backtrace::Backtrace;

    std::panic::set_hook(Box::new(|panic_info| {
        // 强制捕获backtrace，无视环境变量
        let bt = Backtrace::force_capture();

        // 获取panic位置
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // 获取panic消息
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic_info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("unknown panic");

        let msg = format!(
            "\n\n=== RUST PANIC ===\n\
             Location: {}\n\
             Message: {}\n\
             PID: {}, TID: {}\n\n\
             Backtrace:\n{}\n\
             =================\n\n",
            location,
            payload,
            process::id(),
            unsafe { libc::gettid() },
            bt
        );

        log_msg(msg);
    }));
}
