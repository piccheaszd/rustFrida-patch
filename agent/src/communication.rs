//! agent 端 socket 通信模块
//!
//! 日志消息 (FRAME_KIND_LOG) 通过非阻塞 socket 写发送，拿不到锁时直接丢弃，
//! 避免为日志保留后台线程影响自定义 linker 卸载。
//! 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 仍走同步路径（低频且需要保序）。

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

const FRAME_KIND_CMD: u8 = 1;
const FRAME_KIND_QBDI_HELPER: u8 = 2;

const FRAME_KIND_HELLO: u8 = 0x80;
const FRAME_KIND_LOG: u8 = 0x81;
const FRAME_KIND_COMPLETE: u8 = 0x82;
const FRAME_KIND_EVAL_OK: u8 = 0x83;
const FRAME_KIND_EVAL_ERR: u8 = 0x84;
const FRAME_KIND_RPC_OK: u8 = 0x85;
const FRAME_KIND_RPC_ERR: u8 = 0x86;
const FRAME_KIND_BYE: u8 = 0x87;

/// Write-half of the agent↔host socket, protected by Mutex to serialize messages.
/// 控制消息 (HELLO/COMPLETE/EVAL_OK/EVAL_ERR) 直接走此 stream。
pub static GLOBAL_STREAM: OnceLock<Mutex<UnixStream>> = OnceLock::new();
pub static GLOBAL_STREAM_FD: OnceLock<i32> = OnceLock::new();

#[inline(always)]
unsafe fn raw_write_syscall(fd: i32, buf: *const u8, len: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "svc #0",
        inlateout("x0") fd as isize => ret,
        in("x1") buf,
        in("x2") len,
        in("x8") 64usize,
        options(nostack)
    );
    ret
}

fn write_frame(stream: &mut UnixStream, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    write_frame_raw_fd(stream.as_raw_fd(), kind, payload)
}

fn write_all_raw_fd(fd: i32, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let wrote = unsafe { raw_write_syscall(fd, data.as_ptr(), data.len()) };
        if wrote < 0 {
            let err = std::io::Error::from_raw_os_error((-wrote) as i32);
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if wrote == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "socket write returned zero",
            ));
        }
        data = &data[wrote as usize..];
    }
    Ok(())
}

fn write_frame_raw_fd(fd: i32, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    write_all_raw_fd(fd, &header)?;
    write_all_raw_fd(fd, payload)
}

pub(crate) fn send_hello_raw_fd(fd: i32) -> std::io::Result<()> {
    write_frame_raw_fd(fd, FRAME_KIND_HELLO, &[])
}

pub(crate) fn write_log_raw_fd(fd: i32, data: &[u8]) -> std::io::Result<()> {
    write_frame_raw_fd(fd, FRAME_KIND_LOG, data)
}

pub(crate) fn read_frame(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    stream.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

/// 保留调用点但不创建后台线程；agent 卸载前不能留下仍在执行 agent 代码的线程。
pub(crate) fn start_log_writer() {}

/// 非阻塞写日志：控制消息持锁或 socket 短时不可写时直接丢弃日志。
pub(crate) fn write_stream(data: &[u8]) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let mut stream = match m.try_lock() {
            Ok(s) => s,
            Err(std::sync::TryLockError::WouldBlock) => return,
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        };
        let _ = write_frame(&mut stream, FRAME_KIND_LOG, data);
    }
}

pub(crate) fn write_stream_sync(data: &[u8]) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_LOG, data);
    }
}

pub(crate) fn shutdown_log_writer() {}

/// 直接通过原始 fd 写 socket，供崩溃处理等场景使用。
pub(crate) fn write_stream_raw(data: &[u8]) {
    if let Some(fd) = GLOBAL_STREAM_FD.get() {
        let mut header = [0u8; 5];
        header[0] = FRAME_KIND_LOG;
        header[1..].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let _ = unsafe { raw_write_syscall(*fd, header.as_ptr(), header.len()) };
        let mut offset = 0usize;
        while offset < data.len() {
            let wrote = unsafe { raw_write_syscall(*fd, data[offset..].as_ptr(), data.len() - offset) };
            if wrote <= 0 {
                break;
            }
            offset += wrote as usize;
        }
    }
}

pub(crate) fn send_complete(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_COMPLETE,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_eval_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_EVAL_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_ok(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_OK,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_rpc_err(text: &str) {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(
            &mut m.lock().unwrap_or_else(|e| e.into_inner()),
            FRAME_KIND_RPC_ERR,
            text.as_bytes(),
        );
    }
}

pub(crate) fn send_bye() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let _ = write_frame(&mut m.lock().unwrap_or_else(|e| e.into_inner()), FRAME_KIND_BYE, &[]);
    }
}

pub(crate) fn is_cmd_frame(kind: u8) -> bool {
    kind == FRAME_KIND_CMD
}

pub(crate) fn is_qbdi_helper_frame(kind: u8) -> bool {
    kind == FRAME_KIND_QBDI_HELPER
}

pub(crate) static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// 日志函数：socket未连接时缓存，连接后走非阻塞 socket 写
/// 自动添加 [agent] 前缀
pub(crate) fn log_msg(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream(prefixed.as_bytes());
    } else {
        // Socket未连接，缓存日志
        if let Ok(mut cache) = CACHE_LOG.lock() {
            cache.push(prefixed);
        }
    }
}

pub(crate) fn log_msg_sync(msg: String) {
    let prefixed = format!("[agent] {}", msg);
    if GLOBAL_STREAM.get().is_some() {
        write_stream_sync(prefixed.as_bytes());
    } else if let Ok(mut cache) = CACHE_LOG.lock() {
        cache.push(prefixed);
    }
}

/// 关闭 socket 写端。用 SHUT_WR 保留已排队的 LOG/BYE frame，避免 host 读到 reset。
pub(crate) fn shutdown_stream() {
    if let Some(m) = GLOBAL_STREAM.get() {
        let mut stream = m.lock().unwrap_or_else(|e| e.into_inner());
        let _ = stream.flush();
        let fd = stream.as_raw_fd();
        unsafe {
            libc::shutdown(fd, libc::SHUT_WR);
        }
    }
}

pub(crate) fn register_stream_fd(stream: &UnixStream) {
    let _ = GLOBAL_STREAM_FD.set(stream.as_raw_fd());
}

/// 刷新缓存的日志，在socket连接后调用
pub(crate) fn flush_cached_logs() {
    if GLOBAL_STREAM.get().is_some() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                write_stream(msg.as_bytes());
            }
        }
    }
}
