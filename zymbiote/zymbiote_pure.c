/*
 * zymbiote_pure.c - minimal noptrace stage-0 payload.
 *
 * This payload only gates the child, receives the in-process stage-1 loader
 * over the existing zymbiote socket, maps it, jumps to it, and lets stage-1
 * restore the overwritten code page after the app is resumed.
 */

#include <errno.h>
#include <jni.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

typedef struct _ZymbioteContext ZymbioteContext;

struct _ZymbioteContext
{
    char socket_path[64];

    void *payload_base;
    size_t payload_size;
    size_t payload_original_protection;

    char *package_name;

    int     (*original_setcontext)(uid_t uid, bool is_system_server, const char *seinfo, const char *name);
    void    (*original_set_argv0)(JNIEnv *env, jobject clazz, jstring name);

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

    uint64_t prop_remap;
    uint64_t block_in_setcontext;
    uint64_t pure_spawn_done;
    uint64_t setargv0_slot;
    uint64_t setargv0_original;
    uint64_t child_hooks_restored;
    uint64_t page_size;
    uint64_t setargv0_protection;
    uint64_t setcontext_got_slot;
    uint64_t setcontext_original;
    uint64_t setcontext_got_protection;
    uint64_t capset_got_slot;
    uint64_t capset_original;
    uint64_t capset_got_protection;
};

ZymbioteContext zymbiote =
{
    .socket_path = "/rustfrida-zymbiote-00000000000000000000000000000000",
};

int rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name);
int rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name);

static bool rustfrida_wait_for_stage1(const char *package_name);
static int rustfrida_get_errno(void);
static int rustfrida_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t rustfrida_sendmsg(int sockfd, const struct msghdr *msg, int flags);
static bool rustfrida_sendmsg_all(int sockfd, struct iovec *iov, size_t iovlen, int flags);
static ssize_t rustfrida_recv(int sockfd, void *buf, size_t len, int flags);
static bool rustfrida_recv_all(int sockfd, void *buf, size_t len);
static bool rustfrida_receive_and_run_stage1(int sockfd);
static void rustfrida_clear_package_name(void);
static bool rustfrida_make_payload_writable(void);
static void rustfrida_restore_payload_protection(void);
static void rustfrida_restore_child_hooks(void);
static void rustfrida_restore_u64_slot(uint64_t slot, uint64_t value, uint64_t protection);

#define __NR_nanosleep 101
#define __NR_mmap     222

#define MY_MAP_PRIVATE 0x02
#define MY_MAP_ANONYMOUS 0x20

#define RUSTFRIDA_SELF_RESTORE 0x43
#define RUSTFRIDA_PURE_STAGE1 0x50

typedef struct
{
    uint64_t image_size;
    uint64_t code_size;
    uint64_t ctx_offset;
    uint64_t resume_flag_offset;
    uint64_t stage0_done_flag_offset;
    uint64_t reloc_count;
} RustFridaPureStage1Header;

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

static bool
rustfrida_sleep_until_resume(volatile uint64_t *flag)
{
    struct
    {
        long tv_sec;
        long tv_nsec;
    } ts;

    ts.tv_sec = 0;
    ts.tv_nsec = 5000000L;
    while (*flag == 0)
        raw_syscall6(__NR_nanosleep, (long)&ts, 0, 0, 0, 0, 0);

    return true;
}

static bool
rustfrida_receive_and_run_stage1(int sockfd)
{
    RustFridaPureStage1Header h;
    char *mapping;
    int *ctrlfds;
    volatile uint64_t *resume_flag;
    volatile uint64_t *stage0_done_flag;
    void (*loader_entry)(void *);
    bool resumed;

    if (!rustfrida_recv_all(sockfd, &h, sizeof(h)))
        return false;

    if (h.image_size == 0 || h.image_size > (2u * 1024u * 1024u) ||
        h.code_size == 0 || h.code_size > h.image_size ||
        h.ctx_offset + 8u > h.image_size ||
        h.resume_flag_offset + 8u > h.image_size ||
        h.stage0_done_flag_offset + 8u > h.image_size ||
        h.reloc_count > 64u)
        return false;

    mapping = (char *)raw_syscall6(__NR_mmap, 0, (long)h.image_size,
                                   PROT_READ | PROT_WRITE | PROT_EXEC,
                                   MY_MAP_PRIVATE | MY_MAP_ANONYMOUS,
                                   -1, 0);
    if ((long)mapping < 0)
        return false;

    if (!rustfrida_recv_all(sockfd, mapping, (size_t)h.image_size))
        return false;

    for (uint64_t i = 0; i != h.reloc_count; i++)
    {
        uint32_t off;
        uint64_t *slot;

        if (!rustfrida_recv_all(sockfd, &off, sizeof(off)) || (uint64_t)off + 8u > h.image_size)
            return false;

        slot = (uint64_t *)(mapping + off);
        *slot += (uint64_t)mapping;
    }

    ctrlfds = (int *)(mapping + h.ctx_offset);
    ctrlfds[0] = -1;
    ctrlfds[1] = sockfd;
    resume_flag = (volatile uint64_t *)(mapping + h.resume_flag_offset);
    *resume_flag = 0;
    stage0_done_flag = (volatile uint64_t *)(mapping + h.stage0_done_flag_offset);
    *stage0_done_flag = 0;

    loader_entry = (void (*)(void *))mapping;
    loader_entry(mapping + h.ctx_offset);

    resumed = rustfrida_sleep_until_resume(resume_flag);
    *stage0_done_flag = 1;
    return resumed;
}

__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name)
{
    int res;

    if (zymbiote.original_setcontext == NULL)
        return 0;

    res = zymbiote.original_setcontext(uid, is_system_server, seinfo, name);
    if (res == -1 || zymbiote.pure_spawn_done)
        return res;

    if (zymbiote.package_name == NULL && name != NULL && rustfrida_make_payload_writable())
        zymbiote.package_name = zymbiote.strdup(name);

    if (zymbiote.block_in_setcontext && zymbiote.package_name != NULL)
    {
        bool stage1_started = rustfrida_wait_for_stage1(zymbiote.package_name);
        rustfrida_clear_package_name();
        if (!stage1_started)
            rustfrida_restore_payload_protection();
    }

    return res;
}

__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name)
{
    const char *name_utf8;
    bool release_name;

    zymbiote.original_set_argv0(env, clazz, name);

    if (zymbiote.pure_spawn_done || zymbiote.block_in_setcontext)
        return 0;

    if (zymbiote.package_name != NULL)
    {
        name_utf8 = zymbiote.package_name;
        release_name = false;
    }
    else
    {
        name_utf8 = (*env)->GetStringUTFChars(env, name, NULL);
        if (name_utf8 == NULL)
            return 0;
        release_name = true;
    }

    bool stage1_started = rustfrida_wait_for_stage1(name_utf8);

    if (release_name)
        (*env)->ReleaseStringUTFChars(env, name, name_utf8);
    else
        rustfrida_clear_package_name();

    if (!stage1_started)
        rustfrida_restore_payload_protection();

    return 0;
}

static bool
rustfrida_wait_for_stage1(const char *package_name)
{
    int fd = -1;
    bool stage1_started = false;
    struct sockaddr_un addr;
    socklen_t addrlen;
    unsigned int name_len;

    if (!rustfrida_make_payload_writable())
        return false;

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

    {
        uint8_t rx;

        if (rustfrida_recv(fd, &rx, 1, 0) != 1)
            goto beach;

        if (rx == RUSTFRIDA_PURE_STAGE1)
        {
            zymbiote.pure_spawn_done = 1;
            if (rustfrida_receive_and_run_stage1(fd))
            {
                stage1_started = true;
                fd = -1;
            }
            else
            {
                zymbiote.pure_spawn_done = 0;
            }
            goto beach;
        }

        if (rx == RUSTFRIDA_SELF_RESTORE)
        {
            rustfrida_restore_child_hooks();
            goto beach;
        }
    }

beach:
    if (fd != -1)
        zymbiote.close(fd);
    return stage1_started;
}

static void
rustfrida_clear_package_name(void)
{
    if (zymbiote.package_name == NULL)
        return;

    zymbiote.free(zymbiote.package_name);
    zymbiote.package_name = NULL;
}

static bool
rustfrida_make_payload_writable(void)
{
    if (zymbiote.payload_base == NULL || zymbiote.payload_size == 0 || zymbiote.mprotect == NULL)
        return false;

    return zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                             PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

static void
rustfrida_restore_payload_protection(void)
{
    if (zymbiote.payload_base == NULL || zymbiote.payload_size == 0 ||
        zymbiote.payload_original_protection == 0 || zymbiote.mprotect == NULL)
        return;

    zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                      (int)zymbiote.payload_original_protection);
}

static void
rustfrida_restore_child_hooks(void)
{
    if (zymbiote.child_hooks_restored)
        return;

    zymbiote.child_hooks_restored = 1;

    rustfrida_restore_u64_slot(zymbiote.setargv0_slot,
                               zymbiote.setargv0_original,
                               zymbiote.setargv0_protection);

    rustfrida_restore_u64_slot(zymbiote.setcontext_got_slot,
                               zymbiote.setcontext_original,
                               zymbiote.setcontext_got_protection);
}

static void
rustfrida_restore_u64_slot(uint64_t slot, uint64_t value, uint64_t protection)
{
    bool temporarily_writable = false;

    if (slot == 0)
        return;

    if (protection != 0 && (protection & PROT_WRITE) == 0)
    {
        size_t page_size = (zymbiote.page_size != 0) ? (size_t)zymbiote.page_size : 4096u;
        uintptr_t page_start = ((uintptr_t)slot) & ~((uintptr_t)page_size - 1u);
        uintptr_t slot_end = (uintptr_t)slot + sizeof(uint64_t);
        uintptr_t page_end = (slot_end + page_size - 1u) & ~((uintptr_t)page_size - 1u);
        size_t span = page_end - page_start;

        if (zymbiote.mprotect((void *)page_start, span, (int)(protection | PROT_WRITE)) != 0)
            return;

        temporarily_writable = true;
    }

    *(uint64_t *)(uintptr_t)slot = value;

    if (temporarily_writable)
    {
        size_t page_size = (zymbiote.page_size != 0) ? (size_t)zymbiote.page_size : 4096u;
        uintptr_t page_start = ((uintptr_t)slot) & ~((uintptr_t)page_size - 1u);
        uintptr_t slot_end = (uintptr_t)slot + sizeof(uint64_t);
        uintptr_t page_end = (slot_end + page_size - 1u) & ~((uintptr_t)page_size - 1u);
        zymbiote.mprotect((void *)page_start, page_end - page_start, (int)protection);
    }
}

static int
rustfrida_get_errno(void)
{
    return *zymbiote.__errno();
}

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
        if (n <= 0)
            return false;

        size_t remaining = (size_t)n;
        while (remaining != 0 && idx != iovlen)
        {
            if (remaining < iov[idx].iov_len)
            {
                iov[idx].iov_base = (char *)iov[idx].iov_base + remaining;
                iov[idx].iov_len -= remaining;
                remaining = 0;
            }
            else
            {
                remaining -= iov[idx].iov_len;
                idx++;
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

static bool
rustfrida_recv_all(int sockfd, void *buf, size_t len)
{
    char *p = (char *)buf;
    size_t remaining = len;

    while (remaining != 0)
    {
        ssize_t n = rustfrida_recv(sockfd, p, remaining, MSG_WAITALL);
        if (n <= 0)
            return false;

        p += n;
        remaining -= (size_t)n;
    }

    return true;
}
