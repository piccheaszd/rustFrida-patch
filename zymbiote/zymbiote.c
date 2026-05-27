/*
 * zymbiote.c — rustFrida Zymbiote 载荷
 *
 * 注入到 Zygote 进程，hook setArgV0 和 selinux_android_setcontext。
 * 当新 App 从 Zygote fork 出来时，zymbiote 触发并暂停子进程，
 * 等待 rustFrida 注入 agent 后再恢复。
 *
 * 基于 Frida 的 frida-core/src/linux/helpers/zymbiote.c 改写。
 */

#include <errno.h>
#include <jni.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#define RUSTFRIDA_ZYMBIOTE_CMD_RESUME      0x42
#define RUSTFRIDA_ZYMBIOTE_CMD_LOAD_NATIVE 0x4e
#define RUSTFRIDA_NATIVE_MAX_LOADER_SIZE   (128u * 1024u)
#define RUSTFRIDA_NATIVE_MAX_STRING_SIZE   8192u

typedef struct _RustFridaNativeLoadHeader RustFridaNativeLoadHeader;
typedef struct _RustFridaNativeStringTable RustFridaNativeStringTable;
typedef struct _RustFridaNativeLoaderContext RustFridaNativeLoaderContext;

struct _RustFridaNativeLoadHeader
{
    uint32_t loader_size;
    uint32_t entrypoint_size;
    uint32_t agent_data_size;
    uint32_t current_thread_eval_size;
    uint32_t sym_name_size;
    uint32_t pthread_err_size;
    uint32_t dlsym_err_size;
    uint32_t cmdline_size;
    uint32_t output_path_size;
};

struct _RustFridaNativeStringTable
{
    uint64_t sym_name;
    uint32_t sym_name_len;
    uint32_t _pad0;
    uint64_t pthread_err;
    uint32_t pthread_err_len;
    uint32_t _pad1;
    uint64_t dlsym_err;
    uint32_t dlsym_err_len;
    uint32_t _pad2;
    uint64_t cmdline;
    uint32_t cmdline_len;
    uint32_t _pad3;
    uint64_t output_path;
    uint32_t output_path_len;
    uint32_t _pad4;
};

struct _RustFridaNativeLoaderContext
{
    int32_t ctrlfds[2];
    const char *agent_entrypoint;
    const char *agent_data;
    const char *fallback_address;
    void *libc;
    uint64_t string_table_addr;
    const char *agent_current_thread_eval;
    const uint64_t *resolver_module_bases;
    uint64_t resolver_module_count;
    void *worker;
    void *agent_handle;
    void *agent_entrypoint_impl;
    void *agent_current_thread_eval_impl;
};

/* ========== ZymbioteContext ========== */
/* 此结构体的布局必须与 Rust 侧（spawn.rs）写入顺序完全一致 */
typedef struct _ZymbioteContext ZymbioteContext;

struct _ZymbioteContext
{
    char socket_path[64];           /* 0:   abstract Unix socket 路径 */

    void *payload_base;             /* 64:  payload 写入的基地址 */
    size_t payload_size;            /* 72:  payload 大小 */
    size_t payload_original_protection; /* 80: 原始页保护位 */

    char *package_name;             /* 88:  NULL（由 setcontext hook 运行时填充）*/

    int     (*original_setcontext)(uid_t uid, bool is_system_server, const char *seinfo, const char *name);
    void    (*original_set_argv0)(JNIEnv *env, jobject clazz, jstring name);

    /* 12 个 libc 函数指针 */
    int     (*mprotect)(void *addr, size_t len, int prot);
    char *  (*strdup)(const char *s);
    void    (*free)(void *ptr);
    int     (*socket)(int domain, int type, int protocol);
    int     (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int *   (*__errno)(void);
    pid_t   (*getpid)(void);
    pid_t   (*getppid)(void);
    ssize_t (*sendmsg)(int sockfd, const struct msghdr *msg, int flags);
    ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags);
    int     (*close)(int fd);
    int     (*raise)(int sig);

    /* 控制标志（由 Rust 侧填充） */
    uint64_t prop_remap;            /* 非零 = 启用属性 remap */
    uint64_t block_in_setcontext;   /* 非零 = 降级模式：在 setcontext 阻塞（setArgV0 slot 未找到） */
};

/* 全局上下文实例（运行时由 Rust 侧通过 /proc/pid/mem 填充） */
ZymbioteContext zymbiote =
{
    .socket_path = "/rustfrida-zymbiote-00000000000000000000000000000000",
};

/* 前向声明 */
int rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name);
int rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name);
struct cap_header;
struct cap_data;
int rustfrida_zymbiote_replacement_capset(struct cap_header *hdrp, struct cap_data *datap);

static void rustfrida_wait_for_permission_to_resume(const char *package_name, bool *revert_now);
static int rustfrida_stop_and_return_from_setargv0(JNIEnv *env, jobject clazz, jstring name);
static int rustfrida_get_errno(void);
static int rustfrida_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t rustfrida_sendmsg(int sockfd, const struct msghdr *msg, int flags);
static bool rustfrida_sendmsg_all(int sockfd, struct iovec *iov, size_t iovlen, int flags);
static ssize_t rustfrida_recv(int sockfd, void *buf, size_t len, int flags);
static void rustfrida_patch_build_fields(JNIEnv *env);
static bool rustfrida_recv_exact(int fd, void *buf, size_t len);
static int rustfrida_recv_fd(int fd);
static bool rustfrida_start_native_loader(int gate_fd);
static void *rustfrida_raw_mmap(void *addr, size_t length, int prot, int flags, int fd, unsigned long offset);
static unsigned long rustfrida_align_up(unsigned long value, unsigned long alignment);

/* ========== ARM64 raw syscall ========== */
/* 不依赖 libc，直接 svc #0 */

#define __NR_mount    40
#define __NR_openat   56
#define __NR_close    57
#define __NR_lseek    62
#define __NR_read     63
#define __NR_write    64
#define __NR_recvmsg  212
#define __NR_mprotect 226
#define __NR_mmap     222


#define MY_AT_FDCWD   (-100)
#define MY_O_RDONLY    0
#define MY_MS_BIND     4096
#define MY_MAP_SHARED  0x01
#define MY_MAP_PRIVATE 0x02
#define MY_MAP_FIXED   0x10
#define MY_MAP_ANONYMOUS 0x20

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

static unsigned long
rustfrida_align_up(unsigned long value, unsigned long alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static void *
rustfrida_raw_mmap(void *addr, size_t length, int prot, int flags, int fd, unsigned long offset)
{
    long res = raw_syscall6(__NR_mmap, (long)addr, (long)length, prot, flags, fd, (long)offset);
    if (res < 0 && res > -4096)
        return (void *)-1;
    return (void *)res;
}

static bool
rustfrida_recv_exact(int fd, void *buf, size_t len)
{
    uint8_t *cursor = (uint8_t *)buf;

    while (len != 0)
    {
        ssize_t n = rustfrida_recv(fd, cursor, len, 0);
        if (n <= 0)
            return false;

        cursor += n;
        len -= (size_t)n;
    }

    return true;
}

static int
rustfrida_recv_fd(int fd)
{
    uint8_t dummy;
    struct iovec iov;
    union
    {
        struct cmsghdr header;
        uint8_t storage[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr msg;
    long res;
    struct cmsghdr *cmsg;

    iov.iov_base = &dummy;
    iov.iov_len = sizeof(dummy);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);
    msg.msg_flags = 0;

    res = raw_syscall6(__NR_recvmsg, fd, (long)&msg, 0, 0, 0, 0);
    if (res <= 0 || msg.msg_controllen == 0)
        return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        return -1;

    return *((int *)CMSG_DATA(cmsg));
}

static bool
rustfrida_valid_native_header(const RustFridaNativeLoadHeader *h)
{
    uint32_t string_sizes[5];

    if (h->loader_size == 0 || h->loader_size > RUSTFRIDA_NATIVE_MAX_LOADER_SIZE)
        return false;
    if (h->entrypoint_size == 0 || h->agent_data_size == 0 || h->current_thread_eval_size == 0)
        return false;
    if (h->entrypoint_size > RUSTFRIDA_NATIVE_MAX_STRING_SIZE ||
        h->agent_data_size > RUSTFRIDA_NATIVE_MAX_STRING_SIZE ||
        h->current_thread_eval_size > RUSTFRIDA_NATIVE_MAX_STRING_SIZE)
        return false;

    string_sizes[0] = h->sym_name_size;
    string_sizes[1] = h->pthread_err_size;
    string_sizes[2] = h->dlsym_err_size;
    string_sizes[3] = h->cmdline_size;
    string_sizes[4] = h->output_path_size;

    for (unsigned int i = 0; i != 5; i++)
    {
        if (string_sizes[i] == 0 || string_sizes[i] > RUSTFRIDA_NATIVE_MAX_STRING_SIZE)
            return false;
    }

    return true;
}

static bool
rustfrida_start_native_loader(int gate_fd)
{
    RustFridaNativeLoadHeader header;
    int loader_ctrlfd;
    unsigned long loader_size_aligned;
    unsigned long data_size;
    unsigned long total_size;
    uint8_t *base;
    uint8_t *cursor;
    RustFridaNativeLoaderContext *ctx;
    RustFridaNativeStringTable *table;
    char *entrypoint;
    char *agent_data;
    char *current_thread_eval;
    char *sym_name;
    char *pthread_err;
    char *dlsym_err;
    char *cmdline;
    char *output_path;
    typedef void (*RustFridaLoadFunc)(RustFridaNativeLoaderContext *ctx);

    loader_ctrlfd = rustfrida_recv_fd(gate_fd);
    if (loader_ctrlfd == -1)
        return false;

    if (!rustfrida_recv_exact(gate_fd, &header, sizeof(header)))
        return false;
    if (!rustfrida_valid_native_header(&header))
        return false;

    loader_size_aligned = rustfrida_align_up(header.loader_size, 16);
    data_size = sizeof(RustFridaNativeLoaderContext) +
        sizeof(RustFridaNativeStringTable) +
        header.entrypoint_size +
        header.agent_data_size +
        header.current_thread_eval_size +
        header.sym_name_size +
        header.pthread_err_size +
        header.dlsym_err_size +
        header.cmdline_size +
        header.output_path_size;
    total_size = loader_size_aligned + rustfrida_align_up(data_size, 16);

    base = (uint8_t *)rustfrida_raw_mmap(NULL, total_size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MY_MAP_PRIVATE | MY_MAP_ANONYMOUS, -1, 0);
    if (base == (void *)-1)
        return false;

    if (!rustfrida_recv_exact(gate_fd, base, header.loader_size))
        return false;

    cursor = base + loader_size_aligned;
    ctx = (RustFridaNativeLoaderContext *)cursor;
    cursor += sizeof(RustFridaNativeLoaderContext);
    table = (RustFridaNativeStringTable *)cursor;
    cursor += sizeof(RustFridaNativeStringTable);

    entrypoint = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, entrypoint, header.entrypoint_size))
        return false;
    cursor += header.entrypoint_size;

    agent_data = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, agent_data, header.agent_data_size))
        return false;
    cursor += header.agent_data_size;

    current_thread_eval = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, current_thread_eval, header.current_thread_eval_size))
        return false;
    cursor += header.current_thread_eval_size;

    sym_name = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, sym_name, header.sym_name_size))
        return false;
    cursor += header.sym_name_size;

    pthread_err = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, pthread_err, header.pthread_err_size))
        return false;
    cursor += header.pthread_err_size;

    dlsym_err = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, dlsym_err, header.dlsym_err_size))
        return false;
    cursor += header.dlsym_err_size;

    cmdline = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, cmdline, header.cmdline_size))
        return false;
    cursor += header.cmdline_size;

    output_path = (char *)cursor;
    if (!rustfrida_recv_exact(gate_fd, output_path, header.output_path_size))
        return false;

    table->sym_name = (uint64_t)(uintptr_t)sym_name;
    table->sym_name_len = header.sym_name_size;
    table->pthread_err = (uint64_t)(uintptr_t)pthread_err;
    table->pthread_err_len = header.pthread_err_size;
    table->dlsym_err = (uint64_t)(uintptr_t)dlsym_err;
    table->dlsym_err_len = header.dlsym_err_size;
    table->cmdline = (uint64_t)(uintptr_t)cmdline;
    table->cmdline_len = header.cmdline_size;
    table->output_path = (uint64_t)(uintptr_t)output_path;
    table->output_path_len = header.output_path_size;

    ctx->ctrlfds[0] = -1;
    ctx->ctrlfds[1] = loader_ctrlfd;
    ctx->agent_entrypoint = entrypoint;
    ctx->agent_data = agent_data;
    ctx->fallback_address = NULL;
    ctx->libc = NULL;
    ctx->string_table_addr = (uint64_t)(uintptr_t)table;
    ctx->agent_current_thread_eval = current_thread_eval;
    ctx->resolver_module_bases = NULL;
    ctx->resolver_module_count = 0;
    ctx->worker = NULL;
    ctx->agent_handle = NULL;
    ctx->agent_entrypoint_impl = NULL;
    ctx->agent_current_thread_eval_impl = NULL;

    ((RustFridaLoadFunc)base)(ctx);
    return true;
}

/* ========== prop spoofing 辅助函数 ========== */

/* 简易十六进制解析 */
static unsigned long
parse_hex(const char *s, const char **out)
{
    unsigned long val = 0;
    for (;;)
    {
        char c = *s;
        if (c >= '0' && c <= '9')
            val = (val << 4) | (unsigned long)(c - '0');
        else if (c >= 'a' && c <= 'f')
            val = (val << 4) | (unsigned long)(c - 'a' + 10);
        else
            break;
        s++;
    }
    if (out)
        *out = s;
    return val;
}

/* 在 haystack 中查找 needle 子串，返回起始指针 */
static const char *
str_find(const char *haystack, const char *needle)
{
    while (*haystack)
    {
        const char *h = haystack, *n = needle;
        while (*n && *h == *n)
        {
            h++;
            n++;
        }
        if (!*n)
            return haystack;
        haystack++;
    }
    return NULL;
}

/* 解析 /proc/self/maps 一行: addr_start-addr_end perms offset ... path
 * 返回 0 失败，1 成功 */
static int
parse_maps_line(const char *line, unsigned long *start, unsigned long *end,
                int *prot, unsigned long *offset)
{
    const char *p = line;

    *start = parse_hex(p, &p);
    if (*p != '-')
        return 0;
    p++;
    *end = parse_hex(p, &p);
    if (*p != ' ')
        return 0;
    p++;

    /* 解析权限 rwxs/p → PROT_* */
    *prot = 0;
    if (*p == 'r') *prot |= PROT_READ;
    p++;
    if (*p == 'w') *prot |= PROT_WRITE;
    p++;
    if (*p == 'x') *prot |= PROT_EXEC;
    p++;
    p++; /* skip s/p */
    if (*p != ' ')
        return 0;
    p++;

    *offset = parse_hex(p, &p);
    return 1;
}

/* 收集到的属性映射条目 */
#define MAX_PROP_ENTRIES 512

struct prop_remap_entry
{
    unsigned long addr;
    unsigned long size;
    unsigned long offset;
    int prot;
    char filename[48]; /* e.g., "u:object_r:build_prop:s0" */
};

/* 收集一行 maps 中的属性映射信息（不做 remap，仅存储） */
static int
collect_prop_map_line(const char *line, struct prop_remap_entry *entries, int count)
{
    static const char prop_prefix[] = "/dev/__properties__/";
    static const unsigned int prefix_len = sizeof(prop_prefix) - 1;

    const char *prop = str_find(line, prop_prefix);
    if (!prop)
        return count;

    unsigned long start, end, offset;
    int prot;
    if (!parse_maps_line(line, &start, &end, &prot, &offset))
        return count;

    const char *filename = prop + prefix_len;
    if (*filename == '\0' || count >= MAX_PROP_ENTRIES)
        return count;

    entries[count].addr = start;
    entries[count].size = end - start;
    entries[count].offset = offset;
    entries[count].prot = prot;

    /* 复制文件名 */
    unsigned int fi = 0;
    while (filename[fi] && fi < sizeof(entries[count].filename) - 1)
    {
        entries[count].filename[fi] = filename[fi];
        fi++;
    }
    entries[count].filename[fi] = '\0';

    return count + 1;
}

/* ========== 属性伪装: remap 已映射区域 (path 方式) ========== */
/* noinline: 独立栈帧，避免与调用者栈帧叠加 */
__attribute__((noinline))
static void
rustfrida_remap_prop_areas_by_path(const char *profile_dir)
{
    /* Phase 1: 收集所有 /dev/__properties__/ 映射 */
    struct prop_remap_entry entries[MAX_PROP_ENTRIES];
    int entry_count = 0;

    int maps_fd = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD,
                                     (long)"/proc/self/maps",
                                     MY_O_RDONLY, 0, 0, 0);
    if (maps_fd < 0)
        return;

    {
        char buf[512];
        int leftover = 0;

        for (;;)
        {
            long n = raw_syscall6(__NR_read, (long)maps_fd,
                                  (long)(buf + leftover),
                                  (long)(sizeof(buf) - 1 - (unsigned)leftover),
                                  0, 0, 0);
            if (n <= 0)
            {
                if (leftover > 0)
                {
                    buf[leftover] = '\0';
                    entry_count = collect_prop_map_line(buf, entries, entry_count);
                }
                break;
            }

            int total = leftover + (int)n;
            buf[total] = '\0';

            char *line_start = buf;
            char *p = buf;
            while (p < buf + total)
            {
                if (*p == '\n')
                {
                    *p = '\0';
                    entry_count = collect_prop_map_line(line_start, entries, entry_count);
                    line_start = p + 1;
                }
                p++;
            }

            leftover = (int)((buf + total) - line_start);
            if (leftover > 0 && line_start != buf)
            {
                for (int i = 0; i < leftover; i++)
                    buf[i] = line_start[i];
            }
            if (leftover >= (int)sizeof(buf) - 1)
                leftover = 0;
        }
    }

    raw_syscall6(__NR_close, (long)maps_fd, 0, 0, 0, 0, 0);

    /* Phase 2: 拼接 profile_dir/filename → openat → mmap(MAP_FIXED) */
    for (int i = 0; i < entry_count; i++)
    {
        char path[256];
        {
            unsigned int pi = 0, fi = 0;
            while (profile_dir[pi] && pi < 126)
            {
                path[pi] = profile_dir[pi];
                pi++;
            }
            path[pi++] = '/';
            while (entries[i].filename[fi] && (pi + fi) < 254)
            {
                path[pi + fi] = entries[i].filename[fi];
                fi++;
            }
            path[pi + fi] = '\0';
        }

        int fd = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD, (long)path,
                                   MY_O_RDONLY, 0, 0, 0);
        if (fd < 0)
            continue;

        raw_syscall6(__NR_mmap, (long)entries[i].addr, (long)entries[i].size,
                     (long)entries[i].prot, MY_MAP_SHARED | MY_MAP_FIXED,
                     (long)fd, (long)entries[i].offset);
        raw_syscall6(__NR_close, (long)fd, 0, 0, 0, 0, 0);
    }
}

/* ========== 属性伪装: remap (mounted 路径) ========== */
/* mount 已生效，从 /dev/__properties__/ openat → maps 路径正常 */
__attribute__((noinline))
static void
rustfrida_remap_prop_areas_mounted(void)
{
    char active[] = "/dev/__properties__/.profiles/.active";

    /* 检查 .active 是否存在（判断 prop spoofing 是否启用）
     * mount 覆盖了 /dev/__properties__/，但 .active 在 .profiles/ 子目录
     * mount 后 .profiles/ 被隐藏 → openat 失败 → 说明 mount 成功
     * 实际判断: 检查 .profiles 目录是否被 mount 覆盖（即 mount 已生效）*/

    /* 直接从 /proc/self/maps 读取 /dev/__properties__/ 映射并 remap */
    struct prop_remap_entry entries[MAX_PROP_ENTRIES];
    int entry_count = 0;

    int maps_fd = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD,
                                     (long)"/proc/self/maps",
                                     MY_O_RDONLY, 0, 0, 0);
    if (maps_fd < 0)
        return;

    {
        char buf[512];
        int leftover = 0;

        for (;;)
        {
            long n = raw_syscall6(__NR_read, (long)maps_fd,
                                  (long)(buf + leftover),
                                  (long)(sizeof(buf) - 1 - (unsigned)leftover),
                                  0, 0, 0);
            if (n <= 0)
            {
                if (leftover > 0)
                {
                    buf[leftover] = '\0';
                    entry_count = collect_prop_map_line(buf, entries, entry_count);
                }
                break;
            }

            int total = leftover + (int)n;
            buf[total] = '\0';

            char *line_start = buf;
            char *p = buf;
            while (p < buf + total)
            {
                if (*p == '\n')
                {
                    *p = '\0';
                    entry_count = collect_prop_map_line(line_start, entries, entry_count);
                    line_start = p + 1;
                }
                p++;
            }

            leftover = (int)((buf + total) - line_start);
            if (leftover > 0 && line_start != buf)
            {
                for (int i = 0; i < leftover; i++)
                    buf[i] = line_start[i];
            }
            if (leftover >= (int)sizeof(buf) - 1)
                leftover = 0;
        }
    }

    raw_syscall6(__NR_close, (long)maps_fd, 0, 0, 0, 0, 0);

    /* remap: 拼接 /dev/__properties__/ + filename → openat → mmap(MAP_FIXED)
     * mount 已生效，openat 读到 profile 文件，maps 路径正常 */
    for (int i = 0; i < entry_count; i++)
    {
        char path[128];
        {
            unsigned int bi = 0, fi = 0;
            char base[] = "/dev/__properties__/";
            while (base[bi])
            {
                path[bi] = base[bi];
                bi++;
            }
            while (entries[i].filename[fi] && (bi + fi) < sizeof(path) - 1)
            {
                path[bi + fi] = entries[i].filename[fi];
                fi++;
            }
            path[bi + fi] = '\0';
        }

        int fd = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD, (long)path,
                                   MY_O_RDONLY, 0, 0, 0);
        if (fd < 0)
            continue;

        raw_syscall6(__NR_mmap, (long)entries[i].addr, (long)entries[i].size,
                     (long)entries[i].prot, MY_MAP_SHARED | MY_MAP_FIXED,
                     (long)fd, (long)entries[i].offset);
        raw_syscall6(__NR_close, (long)fd, 0, 0, 0, 0, 0);
    }
}

/* ========== Java Build 字段伪装 ========== */

static jstring
get_system_property(JNIEnv *env, jclass system_properties, jmethodID get_method, const char *key)
{
    jstring jkey;
    jstring value;

    if (env == NULL || system_properties == NULL || get_method == NULL || key == NULL)
        return NULL;

    jkey = (*env)->NewStringUTF(env, key);
    if (jkey == NULL)
    {
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        return NULL;
    }

    value = (jstring)(*env)->CallStaticObjectMethod(env, system_properties, get_method, jkey);
    (*env)->DeleteLocalRef(env, jkey);

    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        return NULL;
    }

    return value;
}

static void
set_static_string_field_from_prop(JNIEnv *env, jclass cls, const char *field_name,
                                  jclass system_properties, jmethodID get_method,
                                  const char *prop_key)
{
    jfieldID fid;
    jstring value;

    if (cls == NULL || field_name == NULL)
        return;

    fid = (*env)->GetStaticFieldID(env, cls, field_name, "Ljava/lang/String;");
    if (fid == NULL)
    {
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        return;
    }

    value = get_system_property(env, system_properties, get_method, prop_key);
    if (value == NULL)
        return;

    (*env)->SetStaticObjectField(env, cls, fid, value);
    (*env)->DeleteLocalRef(env, value);

    if ((*env)->ExceptionCheck(env))
        (*env)->ExceptionClear(env);
}

static void
rustfrida_patch_build_fields(JNIEnv *env)
{
    jclass build;
    jclass system_properties;
    jmethodID get_method = NULL;

    if (env == NULL)
        return;

    system_properties = (*env)->FindClass(env, "android/os/SystemProperties");
    if (system_properties != NULL)
    {
        get_method = (*env)->GetStaticMethodID(env, system_properties, "get",
                                               "(Ljava/lang/String;)Ljava/lang/String;");
        if (get_method == NULL && (*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
    }
    else if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
    }

    build = (*env)->FindClass(env, "android/os/Build");
    if (build != NULL)
    {
        if (get_method != NULL)
        {
            set_static_string_field_from_prop(env, build, "MODEL", system_properties, get_method, "ro.product.model");
            set_static_string_field_from_prop(env, build, "DEVICE", system_properties, get_method, "ro.product.device");
            set_static_string_field_from_prop(env, build, "PRODUCT", system_properties, get_method, "ro.product.name");
            set_static_string_field_from_prop(env, build, "BOARD", system_properties, get_method, "ro.product.board");
            set_static_string_field_from_prop(env, build, "HARDWARE", system_properties, get_method, "ro.hardware");
            set_static_string_field_from_prop(env, build, "FINGERPRINT", system_properties, get_method, "ro.build.fingerprint");
            set_static_string_field_from_prop(env, build, "TAGS", system_properties, get_method, "ro.build.tags");
            set_static_string_field_from_prop(env, build, "TYPE", system_properties, get_method, "ro.build.type");
        }
        (*env)->DeleteLocalRef(env, build);
    }
    else if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
    }

    if (system_properties != NULL)
        (*env)->DeleteLocalRef(env, system_properties);
}

/* ========== prctl 替换函数 ========== */
/* DropCapabilitiesBoundingSet 通过 prctl(PR_CAPBSET_DROP, cap) 逐个 drop。
 * 拦截 CAP_SYS_ADMIN(21) 的 drop，保留 mount 能力。 */
#define MY_PR_CAPBSET_DROP 24
#define MY_CAP_SYS_ADMIN   21

/* capset 替换: 拦截 capability drop，保留 CAP_SYS_ADMIN
 * capset(header, data) — data 包含 effective/permitted/inheritable 3 组 cap 位图
 * 在调用前把 CAP_SYS_ADMIN 位加回去 */
struct cap_header {
    unsigned int version;
    int pid;
};
struct cap_data {
    unsigned int effective;
    unsigned int permitted;
    unsigned int inheritable;
};
/* Linux capability v3 使用 2 组 cap_data（每组 32 位）。
 * CAP_SYS_ADMIN = 21，在第一组（caps[0]）中。 */

__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_capset(struct cap_header *hdrp, struct cap_data *datap)
{
    /* 在 cap drop 前执行 mount --bind
     * 先 unshare(CLONE_NEWNS) 确保 mount 不传播到 zygote
     * （Android 16 此时 ns 已隔离，unshare 幂等无害；
     *  Android 12 此时 ns 未隔离，必须先 unshare） */
    if (datap != NULL)
    {
        char ap[] = "/dev/__properties__/.profiles/.active";
        char pd[128];
        int af = (int)raw_syscall6(__NR_openat, MY_AT_FDCWD, (long)ap, MY_O_RDONLY, 0, 0, 0);
        if (af >= 0)
        {
            long nr = raw_syscall6(__NR_read, (long)af, (long)pd, sizeof(pd) - 1, 0, 0, 0);
            raw_syscall6(__NR_close, (long)af, 0, 0, 0, 0, 0);
            if (nr > 0)
            {
                while (nr > 0 && (pd[nr-1] == '\n' || pd[nr-1] == '\r')) nr--;
                pd[nr] = '\0';
                /* 无条件 unshare mount namespace，确保 mount 不传播到 zygote。
                 * unshare 幂等：已隔离时再次调用无副作用。
                 * 之前用 ns inode 比较判断是否需要 unshare，但 Android 16 的
                 * mount propagation (master:N) 仍会传播回 zygote，导致
                 * zygote 的 /dev/__properties__/ 被污染。 */
                raw_syscall6(97 /*__NR_unshare*/, 0x00020000 /*CLONE_NEWNS*/, 0, 0, 0, 0, 0);
                raw_syscall6(__NR_mount, (long)pd, (long)"/dev/__properties__",
                             0, MY_MS_BIND, 0, 0);
            }
        }
    }

    /* 不修改 cap data，正常 drop CAP_SYS_ADMIN */
    return (int)raw_syscall6(91 /*__NR_capset*/, (long)hdrp, (long)datap, 0, 0, 0, 0);
}

/* ========== setcontext 替换函数 ========== */
__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name)
{
    int res;

    res = zymbiote.original_setcontext(uid, is_system_server, seinfo, name);
    if (res == -1)
        return -1;

    if (zymbiote.package_name == NULL)
    {
        zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC);
        /* mount 已在 capset hook 中完成（cap drop 前） */
        zymbiote.package_name = zymbiote.strdup(name);
    }

    /* 降级模式：setArgV0 slot 未找到时在这里阻塞。
     * 时序比 setArgV0 稍早（Java init 之前），但 seinfo 上下文已应用、
     * caps 已 drop、package_name 已确定，足够用于 agent 注入。 */
    if (zymbiote.block_in_setcontext && zymbiote.package_name != NULL)
    {
        bool revert_now;

        if (zymbiote.prop_remap)
            rustfrida_remap_prop_areas_mounted();

        rustfrida_wait_for_permission_to_resume(zymbiote.package_name, &revert_now);

        /* 还原状态：释放 package_name、恢复页保护 */
        zymbiote.free(zymbiote.package_name);
        zymbiote.package_name = NULL;
        zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                          zymbiote.payload_original_protection);

        if (revert_now)
        {
            /* setcontext 无法尾调 raise(SIGSTOP) 后再返回 int（签名不匹配），
             * 直接同步 raise 然后继续返回 res（与 setArgV0 的尾调等价）。 */
            zymbiote.raise(SIGSTOP);
        }
    }

    return res;
}

/* ========== setArgV0 替换函数 ========== */
__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name)
{
    const char *name_utf8;
    bool revert_now;

    zymbiote.original_set_argv0(env, clazz, name);

    /* 降级模式：阻塞已在 setcontext 完成（setArgV0 slot 未找到时的兼容路径） */
    if (zymbiote.block_in_setcontext)
        return 0;

    if (zymbiote.package_name != NULL)
        name_utf8 = zymbiote.package_name;
    else
        name_utf8 = (*env)->GetStringUTFChars(env, name, NULL);

    /* 属性伪装: remap（仅当 Rust 侧设置 prop_remap 标志时） */
    if (zymbiote.prop_remap)
    {
        rustfrida_remap_prop_areas_mounted();
        rustfrida_patch_build_fields(env);
    }

    rustfrida_wait_for_permission_to_resume(name_utf8, &revert_now);

    if (zymbiote.package_name != NULL)
    {
        zymbiote.free(zymbiote.package_name);
        zymbiote.package_name = NULL;
        zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                          zymbiote.payload_original_protection);
    }
    else
    {
        (*env)->ReleaseStringUTFChars(env, name, name_utf8);
    }

    if (revert_now)
    {
        __attribute__((musttail))
        return rustfrida_stop_and_return_from_setargv0(env, clazz, name);
    }

    return 0;
}

/* ========== 等待 rustFrida 允许恢复 ========== */
static void
rustfrida_wait_for_permission_to_resume(const char *package_name, bool *revert_now)
{
    int fd;
    struct sockaddr_un addr;
    socklen_t addrlen;
    unsigned int name_len;

    *revert_now = false;

    fd = zymbiote.socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        goto beach;

    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';

    name_len = 0;
    for (unsigned int i = 0; i != sizeof(zymbiote.socket_path); i++)
    {
        if (zymbiote.socket_path[i] == '\0')
            break;

        if (1u + i >= sizeof(addr.sun_path))
            break;

        addr.sun_path[1u + i] = zymbiote.socket_path[i];
        name_len++;
    }

    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1u + name_len);

    if (rustfrida_connect(fd, (const struct sockaddr *)&addr, addrlen) == -1)
        goto beach;

    /* 发送 hello 消息: {pid, ppid, name_len, name} */
    {
        struct
        {
            uint32_t pid;
            uint32_t ppid;
            uint32_t package_name_len;
        } header;
        struct iovec iov[2];

        header.pid = zymbiote.getpid();
        header.ppid = zymbiote.getppid();

        header.package_name_len = 0;
        while (package_name[header.package_name_len] != '\0')
            header.package_name_len++;

        iov[0].iov_base = &header;
        iov[0].iov_len = sizeof(header);

        iov[1].iov_base = (void *)package_name;
        iov[1].iov_len = header.package_name_len;

        if (!rustfrida_sendmsg_all(fd, iov, 2, MSG_NOSIGNAL))
            goto beach;
    }

    /* 阻塞等待命令：0x42 = resume，0x4e = 子进程内 native loader */
    {
        uint8_t rx;

        if (rustfrida_recv(fd, &rx, 1, 0) != 1)
            goto beach;

        if (rx == RUSTFRIDA_ZYMBIOTE_CMD_LOAD_NATIVE)
        {
            if (!rustfrida_start_native_loader(fd))
                goto beach;

            if (rustfrida_recv(fd, &rx, 1, 0) != 1)
                goto beach;
        }

        if (rx != RUSTFRIDA_ZYMBIOTE_CMD_RESUME)
            goto beach;
    }

    *revert_now = true;

beach:
    if (fd != -1)
        zymbiote.close(fd);
}

/* ========== 停止并从 setArgV0 返回 ========== */
/* raise(SIGSTOP) 用尾调用实现，确保栈帧正确 */
#define RUSTFRIDA_TAILCALL_TO_RAISE_SIGSTOP()                               \
    __asm__ __volatile__(                                                   \
        "mov    w0, #%[sig]\n"                                              \
                                                                            \
        "adrp   x16, zymbiote\n"                                            \
        "add    x16, x16, :lo12:zymbiote\n"                                 \
        "ldr    x16, [x16, %[raise_off]]\n"                                 \
                                                                            \
        "br     x16\n"                                                      \
      :                                                                     \
      : [sig] "i"(SIGSTOP),                                                 \
        [raise_off] "i"(offsetof(ZymbioteContext, raise))                    \
      : "x16", "memory"                                                     \
    )

__attribute__((naked, noinline))
static int
rustfrida_stop_and_return_from_setargv0(JNIEnv *env, jobject clazz, jstring name)
{
    RUSTFRIDA_TAILCALL_TO_RAISE_SIGSTOP();
}

/* ========== errno 辅助 ========== */
static int
rustfrida_get_errno(void)
{
    return *zymbiote.__errno();
}

/* ========== EINTR 安全的 socket 操作 ========== */
static int
rustfrida_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    for (;;)
    {
        if (zymbiote.connect(sockfd, addr, addrlen) == 0)
            return 0;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}

static ssize_t
rustfrida_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    for (;;)
    {
        ssize_t n = zymbiote.sendmsg(sockfd, msg, flags);
        if (n != -1)
            return n;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}

static bool
rustfrida_sendmsg_all(int sockfd, struct iovec *iov, size_t iovlen, int flags)
{
    size_t idx = 0;

    while (idx != iovlen)
    {
        struct msghdr m;

        m.msg_name = NULL;
        m.msg_namelen = 0;
        m.msg_iov = &iov[idx];
        m.msg_iovlen = iovlen - idx;
        m.msg_control = NULL;
        m.msg_controllen = 0;
        m.msg_flags = 0;

        ssize_t n = rustfrida_sendmsg(sockfd, &m, flags);
        if (n == -1)
            return false;

        size_t remaining = n;

        while (remaining != 0)
        {
            size_t avail = iov[idx].iov_len;

            if (remaining < avail)
            {
                iov[idx].iov_base = (char *)iov[idx].iov_base + remaining;
                iov[idx].iov_len -= remaining;
                remaining = 0;
            }
            else
            {
                remaining -= avail;
                idx++;
                if (idx == iovlen)
                    break;
            }
        }
    }

    return true;
}

static ssize_t
rustfrida_recv(int sockfd, void *buf, size_t len, int flags)
{
    for (;;)
    {
        ssize_t n = zymbiote.recv(sockfd, buf, len, flags);
        if (n != -1)
            return n;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}
