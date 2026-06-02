/*
 * zymbiote_restore.c - restore-only stage-1 for unmatched noptrace children.
 *
 * This code is streamed to the child over the zymbiote socket and executed from
 * an anonymous mapping. It waits until stage-0 has returned, then restores the
 * inherited zymbiote payload page and hook slots without ptrace or /proc/pid/mem.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#define __NR_close     57
#define __NR_write     64
#define __NR_nanosleep 101
#define __NR_clone     220
#define __NR_mmap      222
#define __NR_mprotect  226

#define MY_MAP_PRIVATE   0x02
#define MY_MAP_ANONYMOUS 0x20

#define MY_CLONE_VM      0x00000100
#define MY_CLONE_FS      0x00000200
#define MY_CLONE_FILES   0x00000400
#define MY_CLONE_SIGHAND 0x00000800
#define MY_CLONE_THREAD  0x00010000
#define MY_CLONE_SYSVSEM 0x00040000

#define RUSTFRIDA_RESTORE_STATUS_MAGIC 0x52534652u /* "RFSR" */
#define RUSTFRIDA_RESTORE_OK           0u
#define RUSTFRIDA_RESTORE_NO_THREAD    1u
#define RUSTFRIDA_RESTORE_PARTIAL      2u

#define RUSTFRIDA_RESTORE_PAYLOAD      0x00000001u
#define RUSTFRIDA_RESTORE_SETARGV0     0x00000002u
#define RUSTFRIDA_RESTORE_SETCONTEXT   0x00000004u
#define RUSTFRIDA_RESTORE_CAPSET       0x00000008u

#define RF_CTX_SETARGV0_SLOT              232u
#define RF_CTX_SETARGV0_ORIGINAL          240u
#define RF_CTX_SETARGV0_PROTECTION        264u
#define RF_CTX_SETCONTEXT_GOT_SLOT        272u
#define RF_CTX_SETCONTEXT_ORIGINAL        280u
#define RF_CTX_SETCONTEXT_GOT_PROTECTION  288u
#define RF_CTX_CAPSET_GOT_SLOT            296u
#define RF_CTX_CAPSET_ORIGINAL            304u
#define RF_CTX_CAPSET_GOT_PROTECTION      312u

typedef struct
{
    int ctrlfds[2];
    uint64_t resume_flag;
    uint64_t stage0_done_flag;
    uint64_t payload_base;
    uint64_t payload_size;
    uint64_t payload_backup;
    uint64_t payload_protection;
    uint64_t page_size;
    uint64_t payload_context_offset;
    uint64_t setargv0_slot;
    uint64_t setargv0_original;
    uint64_t setargv0_protection;
    uint64_t setcontext_got_slot;
    uint64_t setcontext_original;
    uint64_t setcontext_got_protection;
    uint64_t capset_got_slot;
    uint64_t capset_original;
    uint64_t capset_got_protection;
} RustFridaRestoreContext;

typedef struct
{
    uint32_t magic;
    uint32_t status;
    uint32_t restored;
    uint32_t failed;
} RustFridaRestoreStatus;

static inline long raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
static long rustfrida_clone_thread(size_t flags, void *child_stack, void (*child_func)(void *), void *child_arg);
static void rustfrida_restore_thread(void *user_data);
static void rustfrida_sleep_ms(uint32_t millis);
static RustFridaRestoreStatus rustfrida_restore_cleanup(RustFridaRestoreContext *ctx);
static void rustfrida_fill_slots_from_payload_context(RustFridaRestoreContext *ctx);
static bool rustfrida_restore_memory(uint64_t address, const void *backup, uint64_t size,
                                     uint64_t protection, uint64_t page_size, bool executable);
static bool rustfrida_restore_slot(uint64_t slot, uint64_t value, uint64_t protection, uint64_t page_size);
static uint64_t rustfrida_load_ctx_u64(const RustFridaRestoreContext *ctx, uint64_t offset);
static void rustfrida_send_status(RustFridaRestoreContext *ctx, const RustFridaRestoreStatus *status);
static void rustfrida_memcpy(void *dst, const void *src, size_t size);
static void rustfrida_clear_icache(uintptr_t start, uintptr_t end);

__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
void
rustfrida_restore_stage1_entry(RustFridaRestoreContext *ctx)
{
    const size_t stack_size = 64 * 1024;
    const size_t flags = MY_CLONE_VM | MY_CLONE_FS | MY_CLONE_FILES |
        MY_CLONE_SIGHAND | MY_CLONE_THREAD | MY_CLONE_SYSVSEM;
    void *stack;
    void *stack_top;
    long clone_result = -1;

    if (ctx == NULL)
        return;

    stack = (void *)raw_syscall6(__NR_mmap, 0, (long)stack_size,
                                 PROT_READ | PROT_WRITE,
                                 MY_MAP_PRIVATE | MY_MAP_ANONYMOUS,
                                 -1, 0);
    if ((long)stack >= 0)
    {
        stack_top = (void *)(((uintptr_t)stack + stack_size) & ~(uintptr_t)15);
        clone_result = rustfrida_clone_thread(flags, stack_top, rustfrida_restore_thread, ctx);
    }

    if (clone_result < 0)
    {
        RustFridaRestoreStatus status;

        status.magic = RUSTFRIDA_RESTORE_STATUS_MAGIC;
        status.status = RUSTFRIDA_RESTORE_NO_THREAD;
        status.restored = 0;
        status.failed = RUSTFRIDA_RESTORE_PAYLOAD;
        rustfrida_send_status(ctx, &status);
    }

    if (ctx->resume_flag != 0)
        *(volatile uint64_t *)(uintptr_t)ctx->resume_flag = 1;
}

static void
rustfrida_restore_thread(void *user_data)
{
    RustFridaRestoreContext *ctx = (RustFridaRestoreContext *)user_data;
    volatile uint64_t *stage0_done_flag;
    RustFridaRestoreStatus status;

    if (ctx == NULL || ctx->stage0_done_flag == 0)
        return;

    stage0_done_flag = (volatile uint64_t *)(uintptr_t)ctx->stage0_done_flag;
    while (*stage0_done_flag == 0)
        rustfrida_sleep_ms(2);

    rustfrida_sleep_ms(1);
    status = rustfrida_restore_cleanup(ctx);
    rustfrida_send_status(ctx, &status);
}

static RustFridaRestoreStatus
rustfrida_restore_cleanup(RustFridaRestoreContext *ctx)
{
    uint64_t page_size = ctx->page_size != 0 ? ctx->page_size : 4096;
    RustFridaRestoreStatus status;

    status.magic = RUSTFRIDA_RESTORE_STATUS_MAGIC;
    status.status = RUSTFRIDA_RESTORE_OK;
    status.restored = 0;
    status.failed = 0;

    rustfrida_fill_slots_from_payload_context(ctx);

    if (rustfrida_restore_memory(ctx->payload_base,
                                 (const void *)(uintptr_t)ctx->payload_backup,
                                 ctx->payload_size, ctx->payload_protection,
                                 page_size, true))
    {
        status.restored |= RUSTFRIDA_RESTORE_PAYLOAD;
    }
    else
    {
        status.failed |= RUSTFRIDA_RESTORE_PAYLOAD;
    }

    if (ctx->setargv0_slot != 0)
    {
        if (rustfrida_restore_slot(ctx->setargv0_slot, ctx->setargv0_original,
                                   ctx->setargv0_protection, page_size))
            status.restored |= RUSTFRIDA_RESTORE_SETARGV0;
        else
            status.failed |= RUSTFRIDA_RESTORE_SETARGV0;
    }

    if (ctx->setcontext_got_slot != 0)
    {
        if (rustfrida_restore_slot(ctx->setcontext_got_slot, ctx->setcontext_original,
                                   ctx->setcontext_got_protection, page_size))
            status.restored |= RUSTFRIDA_RESTORE_SETCONTEXT;
        else
            status.failed |= RUSTFRIDA_RESTORE_SETCONTEXT;
    }

    if (ctx->capset_got_slot != 0)
    {
        if (rustfrida_restore_slot(ctx->capset_got_slot, ctx->capset_original,
                                   ctx->capset_got_protection, page_size))
            status.restored |= RUSTFRIDA_RESTORE_CAPSET;
        else
            status.failed |= RUSTFRIDA_RESTORE_CAPSET;
    }

    if (status.failed != 0 || (status.restored & RUSTFRIDA_RESTORE_PAYLOAD) == 0)
        status.status = RUSTFRIDA_RESTORE_PARTIAL;

    return status;
}

static void
rustfrida_fill_slots_from_payload_context(RustFridaRestoreContext *ctx)
{
    if (ctx == NULL || ctx->payload_base == 0 || ctx->payload_context_offset == 0)
        return;

    if (ctx->setargv0_slot == 0)
    {
        ctx->setargv0_slot = rustfrida_load_ctx_u64(ctx, RF_CTX_SETARGV0_SLOT);
        ctx->setargv0_original = rustfrida_load_ctx_u64(ctx, RF_CTX_SETARGV0_ORIGINAL);
        ctx->setargv0_protection = rustfrida_load_ctx_u64(ctx, RF_CTX_SETARGV0_PROTECTION);
    }

    if (ctx->setcontext_got_slot == 0)
    {
        ctx->setcontext_got_slot = rustfrida_load_ctx_u64(ctx, RF_CTX_SETCONTEXT_GOT_SLOT);
        ctx->setcontext_original = rustfrida_load_ctx_u64(ctx, RF_CTX_SETCONTEXT_ORIGINAL);
        ctx->setcontext_got_protection = rustfrida_load_ctx_u64(ctx, RF_CTX_SETCONTEXT_GOT_PROTECTION);
    }

    if (ctx->capset_got_slot == 0)
    {
        ctx->capset_got_slot = rustfrida_load_ctx_u64(ctx, RF_CTX_CAPSET_GOT_SLOT);
        ctx->capset_original = rustfrida_load_ctx_u64(ctx, RF_CTX_CAPSET_ORIGINAL);
        ctx->capset_got_protection = rustfrida_load_ctx_u64(ctx, RF_CTX_CAPSET_GOT_PROTECTION);
    }
}

static bool
rustfrida_restore_slot(uint64_t slot, uint64_t value, uint64_t protection, uint64_t page_size)
{
    return rustfrida_restore_memory(slot, &value, sizeof(value), protection, page_size, false);
}

static uint64_t
rustfrida_load_ctx_u64(const RustFridaRestoreContext *ctx, uint64_t offset)
{
    uintptr_t base = (uintptr_t)ctx->payload_base + (uintptr_t)ctx->payload_context_offset;
    return *(volatile uint64_t *)(base + (uintptr_t)offset);
}

static void
rustfrida_send_status(RustFridaRestoreContext *ctx, const RustFridaRestoreStatus *status)
{
    const unsigned char *cursor;
    size_t remaining;

    if (ctx == NULL || status == NULL || ctx->ctrlfds[1] == -1)
        return;

    cursor = (const unsigned char *)status;
    remaining = sizeof(*status);
    while (remaining != 0)
    {
        long written = raw_syscall6(__NR_write, ctx->ctrlfds[1], (long)cursor,
                                    (long)remaining, 0, 0, 0);
        if (written <= 0)
            break;

        cursor += (size_t)written;
        remaining -= (size_t)written;
    }

    raw_syscall6(__NR_close, ctx->ctrlfds[1], 0, 0, 0, 0, 0);
    ctx->ctrlfds[1] = -1;
}

static bool
rustfrida_restore_memory(uint64_t address, const void *backup, uint64_t size,
                         uint64_t protection, uint64_t page_size, bool executable)
{
    uintptr_t page_start;
    uintptr_t page_end;
    uint64_t write_protection;

    if (address == 0 || backup == NULL || size == 0)
        return false;

    if (page_size == 0)
        page_size = 4096;

    page_start = ((uintptr_t)address) & ~((uintptr_t)page_size - 1u);
    page_end = ((uintptr_t)address + (uintptr_t)size + (uintptr_t)page_size - 1u) &
        ~((uintptr_t)page_size - 1u);

    write_protection = protection | PROT_WRITE;
    if (executable)
        write_protection |= PROT_EXEC;

    if (raw_syscall6(__NR_mprotect, (long)page_start, (long)(page_end - page_start),
                     (long)write_protection, 0, 0, 0) != 0)
        return false;

    rustfrida_memcpy((void *)(uintptr_t)address, backup, (size_t)size);

    if (executable)
        rustfrida_clear_icache((uintptr_t)address, (uintptr_t)address + (uintptr_t)size);

    if (protection != 0)
    {
        (void)raw_syscall6(__NR_mprotect, (long)page_start, (long)(page_end - page_start),
                           (long)protection, 0, 0, 0);
    }

    return true;
}

static void
rustfrida_sleep_ms(uint32_t millis)
{
    struct
    {
        long tv_sec;
        long tv_nsec;
    } ts;

    ts.tv_sec = millis / 1000;
    ts.tv_nsec = (long)(millis % 1000) * 1000000L;
    raw_syscall6(__NR_nanosleep, (long)&ts, 0, 0, 0, 0, 0);
}

static void
rustfrida_memcpy(void *dst, const void *src, size_t size)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    while (size != 0)
    {
        *d++ = *s++;
        size--;
    }
}

static void
rustfrida_clear_icache(uintptr_t start, uintptr_t end)
{
    uintptr_t line;

    for (line = start & ~(uintptr_t)63; line < end; line += 64)
        __asm__ volatile("dc cvau, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish" ::: "memory");
    for (line = start & ~(uintptr_t)63; line < end; line += 64)
        __asm__ volatile("ic ivau, %0" :: "r"(line) : "memory");
    __asm__ volatile("dsb ish\nisb" ::: "memory");
}

static long
rustfrida_clone_thread(size_t flags, void *child_stack, void (*child_func)(void *), void *child_arg)
{
    register size_t x8 __asm__("x8") = __NR_clone;
    register size_t x0 __asm__("x0") = flags;
    register size_t x1 __asm__("x1") = (size_t)child_stack;
    register size_t x2 __asm__("x2") = 0;
    register size_t x3 __asm__("x3") = 0;
    register size_t x4 __asm__("x4") = 0;
    register size_t x5 __asm__("x5") = (size_t)child_func;
    register size_t x6 __asm__("x6") = (size_t)child_arg;

    __asm__ volatile(
        "svc 0x0\n\t"
        "cbnz x0, 1f\n\t"
        "mov x0, x6\n\t"
        "blr x5\n\t"
        "mov x8, #93\n\t"
        "mov x0, #0\n\t"
        "svc 0x0\n\t"
        "1:\n\t"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6), "r"(x8)
        : "memory", "cc", "x30");

    return (long)x0;
}

static inline long
raw_syscall6(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    register long x8 __asm__("x8") = nr;

    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "memory");

    return x0;
}
