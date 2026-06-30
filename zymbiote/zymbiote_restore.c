/*
 * zymbiote_restore.c - restore-only stage-1 for unmatched noptrace children.
 *
 * This code is streamed to the child over the zymbiote socket and executed from
 * an anonymous mapping. It waits until stage-0 has returned, then restores the
 * inherited zymbiote payload page without ptrace or /proc/pid/mem. Hook slots
 * are restored only when the host passes trusted slot backups from the parent
 * zygote patch record.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#define __NR_openat    56
#define __NR_close     57
#define __NR_read      63
#define __NR_write     64
#define __NR_nanosleep 101
#define __NR_munmap    215
#define __NR_clone     220
#define __NR_mmap      222
#define __NR_mprotect  226

#define MY_AT_FDCWD      -100
#define MY_O_RDONLY      0
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
    uint64_t trust_payload_context;
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
static void rustfrida_scrub_inherited_stage1_tail(void);
static bool rustfrida_restore_memory(uint64_t address, const void *backup, uint64_t size,
                                     uint64_t protection, uint64_t page_size, bool executable);
static bool rustfrida_restore_slot(uint64_t slot, uint64_t value, uint64_t protection, uint64_t page_size);
static uint64_t rustfrida_load_ctx_u64(const RustFridaRestoreContext *ctx, uint64_t offset);
static void rustfrida_send_status(RustFridaRestoreContext *ctx, const RustFridaRestoreStatus *status);
static void rustfrida_memcpy(void *dst, const void *src, size_t size);
static void rustfrida_bzero_volatile(uintptr_t start, size_t size);
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

    rustfrida_scrub_inherited_stage1_tail();

    if (status.failed != 0 || (status.restored & RUSTFRIDA_RESTORE_PAYLOAD) == 0)
        status.status = RUSTFRIDA_RESTORE_PARTIAL;

    return status;
}

static int
rustfrida_hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static const char *
rustfrida_parse_hex(const char *p, uintptr_t *value)
{
    uintptr_t result = 0;
    int digit;

    if (p == NULL || value == NULL)
        return NULL;

    digit = rustfrida_hex_value(*p);
    if (digit < 0)
        return NULL;

    while ((digit = rustfrida_hex_value(*p)) >= 0)
    {
        result = (result << 4) | (uintptr_t)digit;
        p++;
    }

    *value = result;
    return p;
}

static bool
rustfrida_line_contains(const char *line, const char *needle)
{
    const char *p;
    const char *n;

    if (line == NULL || needle == NULL || *needle == '\0')
        return false;

    for (p = line; *p != '\0'; p++)
    {
        n = needle;
        while (*n != '\0' && p[n - needle] == *n)
            n++;
        if (*n == '\0')
            return true;
    }

    return false;
}

static bool
rustfrida_region_contains(uintptr_t start, size_t size, const char *needle)
{
    const unsigned char *region = (const unsigned char *)start;
    const unsigned char *pat = (const unsigned char *)needle;
    size_t pat_len = 0;
    size_t i;
    size_t j;

    while (pat[pat_len] != '\0')
        pat_len++;
    if (pat_len == 0 || size < pat_len)
        return false;

    for (i = 0; i <= size - pat_len; i++)
    {
        for (j = 0; j < pat_len; j++)
        {
            if (region[i + j] != pat[j])
                break;
        }
        if (j == pat_len)
            return true;
    }

    return false;
}

static bool
rustfrida_region_has_stage1_tail_signature(uintptr_t start, size_t size)
{
    return rustfrida_region_contains(start, size, "agent-ctrl=loader") ||
        rustfrida_region_contains(start, size, "frida_send_ready failed") ||
        rustfrida_region_contains(start, size, "frida_receive_ack failed") ||
        rustfrida_region_contains(start, size, "rustfrida_loadjs_current_thread");
}

static void
rustfrida_process_maps_line_for_stage1_tail(const char *line)
{
    const char *p;
    uintptr_t start;
    uintptr_t end;
    size_t size;

    p = rustfrida_parse_hex(line, &start);
    if (p == NULL || *p != '-')
        return;
    p = rustfrida_parse_hex(p + 1, &end);
    if (p == NULL || *p != ' ')
        return;
    p++;

    if (!(p[0] == 'r' && p[1] == 'w' && p[2] == '-' && p[3] == 'p'))
        return;
    if (!rustfrida_line_contains(line, " 00:00 0"))
        return;
    if (end <= start)
        return;

    size = (size_t)(end - start);
    if (size < 4096u || size > (128u * 1024u))
        return;

    if (!rustfrida_region_has_stage1_tail_signature(start, size))
        return;

    rustfrida_bzero_volatile(start, size);
    raw_syscall6(__NR_munmap, (long)start, (long)size, 0, 0, 0, 0);
}

static void
rustfrida_scrub_inherited_stage1_tail(void)
{
    int fd;
    char read_buf[1024];
    char line[512];
    size_t line_len = 0;

    fd = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD, (long)"/proc/self/maps",
                           MY_O_RDONLY, 0, 0, 0);
    if (fd < 0)
        return;

    for (;;)
    {
        long n = raw_syscall6(__NR_read, fd, (long)read_buf, sizeof(read_buf), 0, 0, 0);
        long i;

        if (n <= 0)
            break;

        for (i = 0; i < n; i++)
        {
            char c = read_buf[i];
            if (c == '\n')
            {
                line[line_len] = '\0';
                rustfrida_process_maps_line_for_stage1_tail(line);
                line_len = 0;
            }
            else if (line_len + 1 < sizeof(line))
            {
                line[line_len++] = c;
            }
            else
            {
                line_len = 0;
            }
        }
    }

    if (line_len != 0)
    {
        line[line_len] = '\0';
        rustfrida_process_maps_line_for_stage1_tail(line);
    }

    raw_syscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

static void
rustfrida_fill_slots_from_payload_context(RustFridaRestoreContext *ctx)
{
    if (ctx == NULL || ctx->trust_payload_context == 0 ||
        ctx->payload_base == 0 || ctx->payload_context_offset == 0)
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
rustfrida_bzero_volatile(uintptr_t start, size_t size)
{
    volatile unsigned char *p = (volatile unsigned char *)start;

    while (size != 0)
    {
        *p++ = 0;
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
