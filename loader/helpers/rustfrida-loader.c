/*
 * rustfrida-loader.c — Frida-style loader adapted for rustFrida's agent ABI
 *
 * Based on Frida's loader.c (frida-core/src/linux/helpers/loader.c).
 * Runs as position-independent code in the target process after bootstrap.
 * Entry point creates a worker thread via raw clone; the worker receives the
 * agent SO either as a diagnostic control-socket stream or as an SCM_RIGHTS
 * memfd, with the host currently defaulting to the memfd path,
 * links the agent with rustFrida's minimal ELF linker, and calls
 * hello_entry(&AgentArgs) which blocks in the agent's command loop.
 */

#include "inject-context.h"
#include "syscall.h"

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <time.h>
#include <ucontext.h>

#ifndef SOCK_CLOEXEC
# define SOCK_CLOEXEC 0x80000
#endif
#ifndef __NR_read
# define __NR_read 63
#endif
#ifndef __NR_openat
# define __NR_openat 56
#endif
#ifndef __NR_close
# define __NR_close 57
#endif
#ifndef __NR_exit
# define __NR_exit 93
#endif
#ifndef __NR_lseek
# define __NR_lseek 62
#endif
#ifndef __NR_fcntl
# define __NR_fcntl 25
#endif
#ifndef __NR_mmap
# define __NR_mmap 222
#endif
#ifndef __NR_munmap
# define __NR_munmap 215
#endif
#ifndef __NR_mprotect
# define __NR_mprotect 226
#endif
#ifndef __NR_prctl
# define __NR_prctl 167
#endif
#ifndef __NR_rt_sigaction
# define __NR_rt_sigaction 134
#endif
#ifndef __NR_nanosleep
# define __NR_nanosleep 101
#endif
#ifndef __NR_socket
# define __NR_socket 198
#endif
#ifndef __NR_connect
# define __NR_connect 203
#endif
#ifndef __NR_recvmsg
# define __NR_recvmsg 212
#endif
#ifndef __NR_sendto
# define __NR_sendto 206
#endif
#ifndef AT_FDCWD
# define AT_FDCWD -100
#endif
#ifndef O_RDONLY
# define O_RDONLY 0
#endif
#ifndef SEEK_END
# define SEEK_END 2
#endif
#ifndef R_AARCH64_ABS64
# define R_AARCH64_ABS64 257
#endif
#ifndef R_AARCH64_GLOB_DAT
# define R_AARCH64_GLOB_DAT 1025
#endif
#ifndef R_AARCH64_JUMP_SLOT
# define R_AARCH64_JUMP_SLOT 1026
#endif
#ifndef R_AARCH64_RELATIVE
# define R_AARCH64_RELATIVE 1027
#endif
#ifndef STT_GNU_IFUNC
# define STT_GNU_IFUNC 10
#endif
#ifndef CLONE_VM
# define CLONE_VM 0x00000100
#endif
#ifndef CLONE_FS
# define CLONE_FS 0x00000200
#endif
#ifndef CLONE_FILES
# define CLONE_FILES 0x00000400
#endif
#ifndef CLONE_SIGHAND
# define CLONE_SIGHAND 0x00000800
#endif
#ifndef CLONE_THREAD
# define CLONE_THREAD 0x00010000
#endif
#ifndef CLONE_SYSVSEM
# define CLONE_SYSVSEM 0x00040000
#endif
#ifndef PR_SET_VMA
# define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
# define PR_SET_VMA_ANON_NAME 0
#endif
#ifndef PROT_BTI
# define PROT_BTI 0x10
#endif
#ifndef PT_GNU_PROPERTY
# define PT_GNU_PROPERTY 0x6474e553
#endif
#ifndef NT_GNU_PROPERTY_TYPE_0
# define NT_GNU_PROPERTY_TYPE_0 5
#endif
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_AND
# define GNU_PROPERTY_AARCH64_FEATURE_1_AND 0xc0000000
#endif
#ifndef GNU_PROPERTY_AARCH64_FEATURE_1_BTI
# define GNU_PROPERTY_AARCH64_FEATURE_1_BTI 1
#endif

/* ========== rustFrida types ========== */

typedef int FridaUnloadPolicy;
typedef union _FridaControlMessage FridaControlMessage;

enum _FridaUnloadPolicy
{
  FRIDA_UNLOAD_POLICY_IMMEDIATE,
  FRIDA_UNLOAD_POLICY_RESIDENT,
  FRIDA_UNLOAD_POLICY_DEFERRED,
};

union _FridaControlMessage
{
  struct cmsghdr header;
  uint8_t storage[CMSG_SPACE (sizeof (int))];
};

/*
 * RustFridaLoaderContext — extends FridaLoaderContext with rustFrida fields.
 *
 * The first 5 fields must match FridaLoaderContext layout exactly so that
 * the bootstrap code (which populates them) works unchanged.
 */
typedef struct {
  /* Standard Frida fields (must match FridaLoaderContext layout) */
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  FridaLibcApi * libc;

  /* rustFrida extensions */
  uint64_t string_table_addr;  /* Remote StringTable address for agent */
  const char * agent_current_thread_eval;
  const ElfW(Addr) * resolver_module_bases;
  size_t resolver_module_count;
  void * libc_base;
  void * linker_base;

  /* Runtime state (filled by loader) */
  uintptr_t worker;
  void * agent_handle;
  void * agent_entrypoint_impl;
  void * agent_current_thread_eval_impl;
  void * loader_stack;
  size_t loader_stack_size;
  uint64_t spawn_resume_flag;
  uint64_t spawn_stage0_done_flag;
  uint64_t spawn_cleanup_payload_base;
  uint64_t spawn_cleanup_payload_size;
  uint64_t spawn_cleanup_payload_backup;
  uint64_t spawn_cleanup_payload_protection;
  uint64_t spawn_cleanup_page_size;
  uint64_t spawn_cleanup_setargv0_slot;
  uint64_t spawn_cleanup_setargv0_original;
  uint64_t spawn_cleanup_setargv0_protection;
  uint64_t spawn_cleanup_setcontext_got_slot;
  uint64_t spawn_cleanup_setcontext_original;
  uint64_t spawn_cleanup_setcontext_got_protection;
  uint64_t spawn_cleanup_capset_got_slot;
  uint64_t spawn_cleanup_capset_original;
  uint64_t spawn_cleanup_capset_got_protection;
} RustFridaLoaderContext;

/*
 * AgentArgs — passed to hello_entry().
 * Must match agent/src/lib.rs AgentArgs layout exactly.
 */
typedef struct {
  uint64_t table;       /* *const StringTable */
  int32_t  ctrl_fd;     /* REPL socketpair fd */
  int32_t  agent_memfd; /* -1 (unused in this path) */
  uint64_t resume_flag; /* pure spawn resume flag, 0 otherwise */
} AgentArgs;

typedef void * (* hello_entry_fn) (void *);

/*
 * Android/bionic's public struct sigaction differs from the 64-bit kernel ABI.
 * The loader runs in a raw clone thread, so use rt_sigaction directly and pass
 * the kernel layout instead of relying on libc/TLS state.
 */
typedef struct {
  void (* handler) (int);
  unsigned long flags;
  void (* restorer) (void);
  unsigned long mask;
} RustFridaKernelSigaction;

#define RUSTFRIDA_MAX_MODULES 384

typedef struct {
  ElfW(Addr) base;
  const ElfW(Sym) * symtab;
  const char * strtab;
  size_t strsz;
  const uint32_t * gnu_hash;
  const uint32_t * sysv_hash;
  size_t nsyms;
} RustFridaExportModule;

typedef struct {
  RustFridaExportModule modules[RUSTFRIDA_MAX_MODULES];
  size_t count;
} RustFridaSymbolResolver;

typedef struct {
  RustFridaSymbolResolver * resolver;
  int diagfd;
  const FridaLibcApi * libc;
} RustFridaDlIterateContext;

typedef struct {
  ElfW(Addr) base;
  ElfW(Addr) load_start;
  ElfW(Addr) load_end;
  ElfW(Addr) veneer_start;
  ElfW(Addr) veneer_end;
  size_t veneer_count;
  size_t veneer_capacity;
  bool uses_bti;
  ElfW(Dyn) * dynamic;
  const ElfW(Phdr) * phdrs;
  ElfW(Half) phdr_count;
  const ElfW(Sym) * symtab;
  const char * strtab;
  size_t strsz;
  const uint32_t * gnu_hash;
  size_t nsyms;
  RustFridaSymbolResolver resolver;
  bool initialized;
  bool finalized;
  char error[160];
} RustFridaLinkedModule;

static bool rustfrida_loader_debug_enabled = false;

/* ========== Forward declarations ========== */

static void * frida_main (void * user_data);

static int frida_connect (const char * address, const FridaLibcApi * libc);
static bool frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc);
static bool frida_send_ready (int sockfd, const FridaLibcApi * libc);
static bool frida_receive_ack (int sockfd, const FridaLibcApi * libc);
static bool frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc);
static bool frida_send_debug (int sockfd, const char * message, const FridaLibcApi * libc);
static bool frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc);
static bool frida_send_log (int sockfd, const char * message, const FridaLibcApi * libc);
static bool rustfrida_send_agent_log (int sockfd, const char * message, const FridaLibcApi * libc);
static void rustfrida_send_entry_signal_log (int sockfd, int sig, int code, const void * fault_address,
    ElfW(Addr) pc, ElfW(Addr) sp, ElfW(Addr) lr);

static bool frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * api);
static int frida_receive_fd (int sockfd, const FridaLibcApi * libc);
static int frida_receive_fd_diag (int sockfd, const FridaLibcApi * libc, char * diag_buf);
static bool frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc);
static void frida_enable_close_on_exec (int fd, const FridaLibcApi * libc);

static bool rustfrida_link_agent (int fd, int diagfd, const FridaLibcApi * libc, RustFridaLinkedModule * module,
    const ElfW(Addr) * resolver_module_bases, size_t resolver_module_count,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base, const char * agent_vma_name, bool catch_link_signals, bool stream_agent);
static void * rustfrida_find_export (RustFridaLinkedModule * module, const char * symbol);
static void rustfrida_close_module (RustFridaLinkedModule * module, const FridaLibcApi * libc);
static void rustfrida_unmap_module (RustFridaLinkedModule * module, const FridaLibcApi * libc);
static bool rustfrida_build_symbol_resolver (RustFridaLinkedModule * module, int diagfd, const FridaLibcApi * libc,
    const ElfW(Addr) * resolver_module_bases, size_t resolver_module_count,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base);
static int rustfrida_dl_iterate_add_module (struct dl_phdr_info * info, size_t size, void * user_data);
static void rustfrida_set_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * message);
static void rustfrida_set_symbol_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * prefix, const char * name);
static bool rustfrida_protect_load_segments (RustFridaLinkedModule * module, const FridaLibcApi * libc, bool enable_bti);
static void rustfrida_name_load_segments (RustFridaLinkedModule * module, const char * name);
static void rustfrida_get_fd_vma_name (int fd, char * name, size_t name_size, const FridaLibcApi * libc);
static void rustfrida_set_vma_name (ElfW(Addr) address, size_t size, const char * name);
static bool rustfrida_address_is_executable (ElfW(Addr) address);
static bool rustfrida_try_resolve_local_symbol (const char * name, ElfW(Addr) * value);
static bool rustfrida_try_resolve_aarch64_builtin (const char * name, ElfW(Addr) * value);
static void rustfrida_clear_cache (char * begin, char * end);
static void * rustfrida_emutls_get_address (void * object);
static uint8_t rustfrida_atomic_ldadd1 (uint8_t value, volatile uint8_t * address);
static uint16_t rustfrida_atomic_ldadd2 (uint16_t value, volatile uint16_t * address);
static uint32_t rustfrida_atomic_ldadd4 (uint32_t value, volatile uint32_t * address);
static uint64_t rustfrida_atomic_ldadd8 (uint64_t value, volatile uint64_t * address);
static uint8_t rustfrida_atomic_ldclr1 (uint8_t value, volatile uint8_t * address);
static uint16_t rustfrida_atomic_ldclr2 (uint16_t value, volatile uint16_t * address);
static uint32_t rustfrida_atomic_ldclr4 (uint32_t value, volatile uint32_t * address);
static uint64_t rustfrida_atomic_ldclr8 (uint64_t value, volatile uint64_t * address);
static uint8_t rustfrida_atomic_ldset1 (uint8_t value, volatile uint8_t * address);
static uint16_t rustfrida_atomic_ldset2 (uint16_t value, volatile uint16_t * address);
static uint32_t rustfrida_atomic_ldset4 (uint32_t value, volatile uint32_t * address);
static uint64_t rustfrida_atomic_ldset8 (uint64_t value, volatile uint64_t * address);
static uint8_t rustfrida_atomic_ldeor1 (uint8_t value, volatile uint8_t * address);
static uint16_t rustfrida_atomic_ldeor2 (uint16_t value, volatile uint16_t * address);
static uint32_t rustfrida_atomic_ldeor4 (uint32_t value, volatile uint32_t * address);
static uint64_t rustfrida_atomic_ldeor8 (uint64_t value, volatile uint64_t * address);
static uint8_t rustfrida_atomic_swp1 (uint8_t value, volatile uint8_t * address);
static uint16_t rustfrida_atomic_swp2 (uint16_t value, volatile uint16_t * address);
static uint32_t rustfrida_atomic_swp4 (uint32_t value, volatile uint32_t * address);
static uint64_t rustfrida_atomic_swp8 (uint64_t value, volatile uint64_t * address);
static uint8_t rustfrida_atomic_cas1 (uint8_t expected, uint8_t desired, volatile uint8_t * address);
static uint16_t rustfrida_atomic_cas2 (uint16_t expected, uint16_t desired, volatile uint16_t * address);
static uint32_t rustfrida_atomic_cas4 (uint32_t expected, uint32_t desired, volatile uint32_t * address);
static uint64_t rustfrida_atomic_cas8 (uint64_t expected, uint64_t desired, volatile uint64_t * address);
static bool rustfrida_alloc_call_veneers (RustFridaLinkedModule * module, size_t capacity, const FridaLibcApi * libc);
static ElfW(Addr) rustfrida_emit_call_veneer (RustFridaLinkedModule * module, ElfW(Addr) target, const FridaLibcApi * libc);
static bool rustfrida_protect_call_veneers (RustFridaLinkedModule * module, const FridaLibcApi * libc);
static bool rustfrida_install_entry_signal_handlers (RustFridaLinkedModule * module, int loader_ctrlfd, int agent_ctrlfd,
    const FridaLibcApi * libc);
static void rustfrida_entry_signal_handler (int sig, siginfo_t * info, void * ucontext);
static bool rustfrida_raw_install_entry_signal_handler (int sig);

static void frida_main_raw (void * user_data);
static void rustfrida_spawn_cleanup_raw (void * user_data);
static void rustfrida_start_spawn_cleanup (RustFridaLoaderContext * ctx);
static void rustfrida_restore_spawn_cleanup (RustFridaLoaderContext * ctx);
static bool rustfrida_restore_cleanup_memory (uint64_t address, const void * backup, uint64_t size,
    uint64_t protection, uint64_t page_size, bool executable);
static bool rustfrida_restore_cleanup_slot (uint64_t slot, uint64_t value, uint64_t protection, uint64_t page_size);
static void * frida_raw_mmap (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
static int frida_raw_munmap (void * addr, size_t length);
static int frida_raw_close (int fd);
static int frida_raw_socket (int domain, int type, int protocol);
static int frida_raw_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
static ssize_t frida_raw_recvmsg (int sockfd, struct msghdr * msg, int flags);
static ssize_t frida_raw_send (int sockfd, const void * buf, size_t len, int flags);
static int frida_raw_fcntl (int fd, int cmd, size_t arg);
static void frida_sleep_ms (uint32_t millis);

static size_t frida_strlen (const char * str);
static int frida_strcmp (const char * a, const char * b);
static bool frida_streq (const char * a, const char * b);
static bool frida_str_has_suffix (const char * str, const char * suffix);
static int frida_strncmp (const char * a, const char * b, size_t n);
static char * frida_strchr (const char * str, int c);
static char * frida_strrchr (const char * str, int c);
static char * frida_strstr (const char * haystack, const char * needle);
static char * frida_strcpy (char * dst, const char * src);
static char * frida_strncpy (char * dst, const char * src, size_t n);
static void * frida_memchr (const void * ptr, int c, size_t n);
static void * frida_memcpy (void * dst, const void * src, size_t n);
static void * frida_memmove (void * dst, const void * src, size_t n);
static void * frida_memset (void * dst, int c, size_t n);
static int frida_memcmp (const void * a, const void * b, size_t n);

static bool frida_agent_data_has_token (const char * data, const char * token);
static const char * frida_agent_data_get_last_value (const char * data, const char * key);

static pid_t frida_gettid (void);

static int rustfrida_entry_signal_fd = -1;
static ElfW(Addr) rustfrida_entry_agent_base = 0;
static ElfW(Addr) rustfrida_entry_agent_load_start = 0;
static ElfW(Addr) rustfrida_entry_agent_load_end = 0;

/* ========== Entry point ========== */

static bool
frida_agent_data_has_token (const char * data, const char * token)
{
  size_t token_len;
  const char * cursor;

  if (data == NULL || token == NULL || *data == '\0')
    return false;

  token_len = frida_strlen (token);
  cursor = data;

  while (*cursor != '\0')
  {
    const char * end = frida_strchr (cursor, ';');
    size_t current_len;

    if (end == NULL)
      end = cursor + frida_strlen (cursor);

    current_len = (size_t) (end - cursor);
    if (current_len == token_len && frida_strncmp (cursor, token, token_len) == 0)
      return true;

    cursor = (*end == ';') ? end + 1 : end;
  }

  return false;
}

static const char *
frida_agent_data_get_last_value (const char * data, const char * key)
{
  size_t key_len;
  const char * cursor;

  if (data == NULL || key == NULL || *data == '\0')
    return NULL;

  key_len = frida_strlen (key);
  cursor = data;

  while (*cursor != '\0')
  {
    const char * end = frida_strchr (cursor, ';');

    if (end == NULL)
      end = cursor + frida_strlen (cursor);

    if (frida_strncmp (cursor, key, key_len) == 0 && cursor[key_len] == '=')
    {
      const char * value = cursor + key_len + 1;

      if (value == end)
        return NULL;

      return *end == '\0' ? value : NULL;
    }

    cursor = (*end == ';') ? end + 1 : end;
  }

  return NULL;
}

__attribute__ ((section (".text.entrypoint")))
__attribute__ ((visibility ("default")))
void
frida_load (RustFridaLoaderContext * ctx)
{
  const size_t stack_size = 1024 * 1024;
  const size_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
  const FridaLibcApi * libc = ctx->libc;
  void * stack;
  void * stack_top;
  ssize_t tid;

  stack = frida_raw_mmap (NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    return;

  ctx->loader_stack = stack;
  ctx->loader_stack_size = stack_size;
  stack_top = (void *) (((uintptr_t) stack + stack_size) & ~(uintptr_t) 15);
  tid = frida_clone_thread (flags, stack_top, frida_main_raw, ctx);
  if (tid > 0)
    ctx->worker = (uintptr_t) tid;
}

static void
frida_main_raw (void * user_data)
{
  (void) frida_main (user_data);
}

static void
rustfrida_spawn_cleanup_raw (void * user_data)
{
  RustFridaLoaderContext * ctx = user_data;
  volatile uint64_t * stage0_done_flag;

  stage0_done_flag = (volatile uint64_t *) (uintptr_t) ctx->spawn_stage0_done_flag;
  if (stage0_done_flag == NULL)
    return;

  while (*stage0_done_flag == 0)
    frida_sleep_ms (2);

  frida_sleep_ms (1);
  rustfrida_restore_spawn_cleanup (ctx);
}

static void
rustfrida_start_spawn_cleanup (RustFridaLoaderContext * ctx)
{
  const size_t stack_size = 64 * 1024;
  const size_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
  void * stack;
  void * stack_top;

  if (ctx->spawn_stage0_done_flag == 0 || ctx->spawn_cleanup_payload_base == 0 ||
      ctx->spawn_cleanup_payload_backup == 0 || ctx->spawn_cleanup_payload_size == 0)
    return;

  stack = frida_raw_mmap (NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack == MAP_FAILED)
    return;

  stack_top = (void *) (((uintptr_t) stack + stack_size) & ~(uintptr_t) 15);
  (void) frida_clone_thread (flags, stack_top, rustfrida_spawn_cleanup_raw, ctx);
}

static void
rustfrida_restore_spawn_cleanup (RustFridaLoaderContext * ctx)
{
  uint64_t page_size = ctx->spawn_cleanup_page_size != 0 ? ctx->spawn_cleanup_page_size : 4096;

  (void) rustfrida_restore_cleanup_memory (ctx->spawn_cleanup_payload_base,
      (const void *) (uintptr_t) ctx->spawn_cleanup_payload_backup,
      ctx->spawn_cleanup_payload_size, ctx->spawn_cleanup_payload_protection, page_size, true);

  (void) rustfrida_restore_cleanup_slot (ctx->spawn_cleanup_setargv0_slot,
      ctx->spawn_cleanup_setargv0_original, ctx->spawn_cleanup_setargv0_protection, page_size);
  (void) rustfrida_restore_cleanup_slot (ctx->spawn_cleanup_setcontext_got_slot,
      ctx->spawn_cleanup_setcontext_original, ctx->spawn_cleanup_setcontext_got_protection, page_size);
  (void) rustfrida_restore_cleanup_slot (ctx->spawn_cleanup_capset_got_slot,
      ctx->spawn_cleanup_capset_original, ctx->spawn_cleanup_capset_got_protection, page_size);
}

static bool
rustfrida_restore_cleanup_memory (uint64_t address, const void * backup, uint64_t size,
    uint64_t protection, uint64_t page_size, bool executable)
{
  uintptr_t page_start, page_end;
  uint64_t write_protection;

  if (address == 0 || backup == NULL || size == 0)
    return false;
  if (page_size == 0 || (page_size & (page_size - 1)) != 0)
    page_size = 4096;
  if (protection == 0)
    protection = executable ? (PROT_READ | PROT_EXEC) : PROT_READ;

  page_start = ((uintptr_t) address) & ~((uintptr_t) page_size - 1);
  page_end = (((uintptr_t) address + (uintptr_t) size + (uintptr_t) page_size - 1) &
      ~((uintptr_t) page_size - 1));
  write_protection = protection | PROT_WRITE;
  if (write_protection == 0)
    write_protection = PROT_READ | PROT_WRITE;

  if (frida_syscall_3 (__NR_mprotect, page_start, page_end - page_start, write_protection) != 0)
    return false;

  frida_memcpy ((void *) (uintptr_t) address, backup, (size_t) size);
  if (executable)
    rustfrida_clear_cache ((char *) (uintptr_t) address, (char *) (uintptr_t) (address + size));

  return frida_syscall_3 (__NR_mprotect, page_start, page_end - page_start, protection) == 0;
}

static bool
rustfrida_restore_cleanup_slot (uint64_t slot, uint64_t value, uint64_t protection, uint64_t page_size)
{
  if (slot == 0)
    return false;

  return rustfrida_restore_cleanup_memory (slot, &value, sizeof (value), protection, page_size, false);
}

static void *
frida_raw_mmap (void * addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  return (void *) frida_syscall_6 (__NR_mmap, (size_t) addr, length, prot, flags, fd, offset);
}

static int
frida_raw_munmap (void * addr, size_t length)
{
  return frida_syscall_2 (__NR_munmap, (size_t) addr, length);
}

static int
frida_raw_close (int fd)
{
  return frida_syscall_1 (__NR_close, fd);
}

static int
frida_raw_socket (int domain, int type, int protocol)
{
  return frida_syscall_3 (__NR_socket, domain, type, protocol);
}

static int
frida_raw_connect (int sockfd, const struct sockaddr * addr, socklen_t addrlen)
{
  return frida_syscall_3 (__NR_connect, sockfd, (size_t) addr, addrlen);
}

static ssize_t
frida_raw_recvmsg (int sockfd, struct msghdr * msg, int flags)
{
  return frida_syscall_3 (__NR_recvmsg, sockfd, (size_t) msg, flags);
}

static ssize_t
frida_raw_send (int sockfd, const void * buf, size_t len, int flags)
{
  return frida_syscall_6 (__NR_sendto, sockfd, (size_t) buf, len, flags, 0, 0);
}

static int
frida_raw_fcntl (int fd, int cmd, size_t arg)
{
  return frida_syscall_3 (__NR_fcntl, fd, cmd, arg);
}

static void
frida_sleep_ms (uint32_t millis)
{
  struct timespec ts;

  ts.tv_sec = millis / 1000;
  ts.tv_nsec = (long) (millis % 1000) * 1000000L;
  frida_syscall_2 (__NR_nanosleep, (size_t) &ts, 0);
}

/* ========== Minimal in-process ELF linker for agent.so ========== */

static ElfW(Addr)
rustfrida_align_down (ElfW(Addr) value, ElfW(Addr) alignment)
{
  return value & ~(alignment - 1);
}

static ElfW(Addr)
rustfrida_align_up (ElfW(Addr) value, ElfW(Addr) alignment)
{
  return (value + alignment - 1) & ~(alignment - 1);
}

static size_t
rustfrida_align_size_up (size_t value, size_t alignment)
{
  return (value + alignment - 1) & ~(alignment - 1);
}

static int
rustfrida_phdr_prot (const ElfW(Phdr) * phdr)
{
  int prot = 0;

  if ((phdr->p_flags & PF_R) != 0)
    prot |= PROT_READ;
  if ((phdr->p_flags & PF_W) != 0)
    prot |= PROT_WRITE;
  if ((phdr->p_flags & PF_X) != 0)
    prot |= PROT_EXEC;

  return prot;
}

static bool
rustfrida_is_valid_elf (const ElfW(Ehdr) * ehdr)
{
  return ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
      ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
      ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
      ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
      ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
      ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
      ehdr->e_machine == EM_AARCH64 &&
      ehdr->e_type == ET_DYN;
}

static bool
rustfrida_gnu_property_has_bti (const uint8_t * desc, size_t desc_size)
{
  const uint8_t * cursor = desc;
  const uint8_t * end = desc + desc_size;

  while ((size_t) (end - cursor) >= 8)
  {
    uint32_t type;
    uint32_t data_size;
    size_t padded_data_size;

    frida_memcpy (&type, cursor, sizeof (type));
    frida_memcpy (&data_size, cursor + sizeof (type), sizeof (data_size));
    cursor += 8;

    if (data_size > (size_t) (end - cursor))
      return false;

    if (type == GNU_PROPERTY_AARCH64_FEATURE_1_AND && data_size >= sizeof (uint32_t))
    {
      uint32_t features;

      frida_memcpy (&features, cursor, sizeof (features));
      if ((features & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) != 0)
        return true;
    }

    padded_data_size = rustfrida_align_size_up (data_size, sizeof (ElfW(Addr)));
    if (padded_data_size > (size_t) (end - cursor))
      return false;
    cursor += padded_data_size;
  }

  return false;
}

static bool
rustfrida_elf_has_bti_property (const void * file_map, size_t file_size, const ElfW(Phdr) * phdrs, ElfW(Half) phdr_count)
{
  ElfW(Half) i;

  for (i = 0; i != phdr_count; i++)
  {
    const ElfW(Phdr) * phdr = &phdrs[i];
    const uint8_t * cursor;
    const uint8_t * end;

    if (phdr->p_type != PT_GNU_PROPERTY && phdr->p_type != PT_NOTE)
      continue;
    if (phdr->p_offset > (ElfW(Off)) file_size ||
        phdr->p_filesz > (ElfW(Xword)) ((size_t) file_size - (size_t) phdr->p_offset))
      continue;

    cursor = (const uint8_t *) file_map + phdr->p_offset;
    end = cursor + phdr->p_filesz;

    while ((size_t) (end - cursor) >= sizeof (ElfW(Nhdr)))
    {
      const ElfW(Nhdr) * note = (const ElfW(Nhdr) *) cursor;
      const uint8_t * name;
      const uint8_t * desc;
      size_t padded_name_size;
      size_t padded_desc_size;

      cursor += sizeof (ElfW(Nhdr));
      if (note->n_namesz > (size_t) (end - cursor))
        break;

      name = cursor;
      padded_name_size = rustfrida_align_size_up (note->n_namesz, 4);
      if (padded_name_size > (size_t) (end - cursor))
        break;

      desc = cursor + padded_name_size;
      if (note->n_descsz > (size_t) (end - desc))
        break;

      padded_desc_size = rustfrida_align_size_up (note->n_descsz, 4);
      if (padded_desc_size > (size_t) (end - desc))
        break;

      if (note->n_type == NT_GNU_PROPERTY_TYPE_0 &&
          note->n_namesz == 4 &&
          frida_memcmp (name, "GNU", 4) == 0 &&
          rustfrida_gnu_property_has_bti (desc, note->n_descsz))
        return true;

      cursor = desc + padded_desc_size;
    }
  }

  return false;
}

static bool
rustfrida_is_mapped_elf (const ElfW(Ehdr) * ehdr)
{
  return ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
      ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
      ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
      ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
      ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
      ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
      ehdr->e_phoff >= sizeof (ElfW(Ehdr)) &&
      ehdr->e_phentsize == sizeof (ElfW(Phdr)) &&
      ehdr->e_phnum != 0 &&
      ehdr->e_phnum < 128;
}

static size_t
rustfrida_gnu_hash_nsyms (const uint32_t * gnu_hash)
{
  uint32_t nbuckets, symoffset, bloom_size;
  const uint32_t * buckets;
  const uint32_t * chains;
  uint32_t max_sym = 0;
  uint32_t i;

  if (gnu_hash == NULL)
    return 0;

  nbuckets = gnu_hash[0];
  symoffset = gnu_hash[1];
  bloom_size = gnu_hash[2];
  buckets = gnu_hash + 4 + (bloom_size * (sizeof (ElfW(Addr)) / sizeof (uint32_t)));
  chains = buckets + nbuckets;

  for (i = 0; i != nbuckets; i++)
  {
    if (buckets[i] > max_sym)
      max_sym = buckets[i];
  }

  if (max_sym < symoffset)
    return symoffset;

  i = max_sym - symoffset;
  while ((chains[i] & 1) == 0)
    i++;

  return symoffset + i + 1;
}

static size_t
rustfrida_sysv_hash_nsyms (const uint32_t * sysv_hash)
{
  if (sysv_hash == NULL)
    return 0;

  return sysv_hash[1];
}

static int
rustfrida_hex_value (char ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static const char *
rustfrida_parse_hex (const char * cursor, ElfW(Addr) * value)
{
  ElfW(Addr) result = 0;
  int digit;

  digit = rustfrida_hex_value (*cursor);
  if (digit == -1)
    return NULL;

  do
  {
    result = (result << 4) | (ElfW(Addr)) digit;
    cursor++;
    digit = rustfrida_hex_value (*cursor);
  }
  while (digit != -1);

  *value = result;
  return cursor;
}

static const char *
rustfrida_skip_spaces (const char * cursor)
{
  while (*cursor == ' ' || *cursor == '\t')
    cursor++;
  return cursor;
}

static const char *
rustfrida_next_field (const char * cursor)
{
  while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t' && *cursor != '\n')
    cursor++;
  return rustfrida_skip_spaces (cursor);
}

static bool
rustfrida_export_module_init (ElfW(Addr) candidate_base, RustFridaExportModule * module)
{
  ElfW(Ehdr) * ehdr = (ElfW(Ehdr) *) candidate_base;
  ElfW(Phdr) * phdrs;
  ElfW(Half) i;
  ElfW(Addr) load_bias = candidate_base;
  ElfW(Dyn) * dynamic = NULL;
  ElfW(Dyn) * dyn;

  if (!rustfrida_is_mapped_elf (ehdr))
    return false;

  phdrs = (ElfW(Phdr) *) (candidate_base + ehdr->e_phoff);
  for (i = 0; i != ehdr->e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_LOAD)
    {
      load_bias = candidate_base - phdr->p_vaddr;
      break;
    }
  }

  for (i = 0; i != ehdr->e_phnum; i++)
  {
    ElfW(Phdr) * phdr = &phdrs[i];

    if (phdr->p_type == PT_DYNAMIC)
    {
      dynamic = (ElfW(Dyn) *) (load_bias + phdr->p_vaddr);
    }
  }

  if (dynamic == NULL)
    return false;

  frida_memset (module, 0, sizeof (*module));
  module->base = load_bias;

  for (dyn = dynamic; dyn->d_tag != DT_NULL; dyn++)
  {
    ElfW(Addr) ptr = dyn->d_un.d_ptr;

    switch (dyn->d_tag)
    {
      case DT_SYMTAB:
        module->symtab = (const ElfW(Sym) *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_STRTAB:
        module->strtab = (const char *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_STRSZ:
        module->strsz = dyn->d_un.d_val;
        break;
      case DT_GNU_HASH:
        module->gnu_hash = (const uint32_t *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      case DT_HASH:
        module->sysv_hash = (const uint32_t *) ((ptr >= load_bias) ? ptr : load_bias + ptr);
        break;
      default:
        break;
    }
  }

  if (module->symtab == NULL || module->strtab == NULL || module->strsz == 0)
    return false;

  module->nsyms = rustfrida_gnu_hash_nsyms (module->gnu_hash);
  if (module->nsyms == 0)
    module->nsyms = rustfrida_sysv_hash_nsyms (module->sysv_hash);
  if ((ElfW(Addr)) module->strtab > (ElfW(Addr)) module->symtab)
  {
    size_t by_layout = ((ElfW(Addr)) module->strtab - (ElfW(Addr)) module->symtab) / sizeof (ElfW(Sym));

    if (by_layout > module->nsyms && by_layout < 65536)
      module->nsyms = by_layout;
  }

  return module->nsyms != 0;
}

static bool
rustfrida_address_is_executable (ElfW(Addr) address)
{
  static const char maps_path[] = "/proc/self/maps";
  char buffer[8192];
  char line[512];
  size_t line_len = 0;
  int fd;
  ssize_t n;
  bool result = false;

  fd = frida_syscall_4 (__NR_openat, AT_FDCWD, (size_t) maps_path, O_RDONLY, 0);
  if (fd < 0)
    return false;

  while (!result && (n = frida_syscall_3 (__NR_read, fd, (size_t) buffer, sizeof (buffer))) > 0)
  {
    ssize_t i;

    for (i = 0; i != n; i++)
    {
      char ch = buffer[i];

      if (ch == '\n' || line_len == sizeof (line) - 1)
      {
        ElfW(Addr) start;
        ElfW(Addr) end;
        const char * cursor;

        line[line_len] = '\0';
        line_len = 0;

        cursor = rustfrida_parse_hex (line, &start);
        if (cursor == NULL || *cursor != '-')
          continue;
        cursor++;
        cursor = rustfrida_parse_hex (cursor, &end);
        if (cursor == NULL || address < start || address >= end)
          continue;

        cursor = rustfrida_skip_spaces (cursor);
        result = cursor[2] == 'x';
        break;
      }
      else
      {
        line[line_len++] = ch;
      }
    }
  }

  if (!result && line_len != 0)
  {
    ElfW(Addr) start;
    ElfW(Addr) end;
    const char * cursor;

    line[line_len] = '\0';
    cursor = rustfrida_parse_hex (line, &start);
    if (cursor != NULL && *cursor == '-')
    {
      cursor++;
      cursor = rustfrida_parse_hex (cursor, &end);
      if (cursor != NULL && address >= start && address < end)
      {
        cursor = rustfrida_skip_spaces (cursor);
        result = cursor[2] == 'x';
      }
    }
  }

  frida_syscall_1 (__NR_close, fd);
  return result;
}

static bool
rustfrida_resolver_add_module (RustFridaSymbolResolver * resolver, ElfW(Addr) base)
{
  RustFridaExportModule module;
  size_t i;

  if (resolver->count == RUSTFRIDA_MAX_MODULES)
    return false;

  for (i = 0; i != resolver->count; i++)
  {
    if (resolver->modules[i].base == base)
      return true;
  }

  if (!rustfrida_export_module_init (base, &module))
    return false;

  resolver->modules[resolver->count++] = module;
  return true;
}

static bool
rustfrida_maps_line_add_module (RustFridaSymbolResolver * resolver, const char * line)
{
  ElfW(Addr) start;
  ElfW(Addr) ignored;
  ElfW(Addr) offset;
  const char * cursor = line;
  const char * path;

  cursor = rustfrida_parse_hex (cursor, &start);
  if (cursor == NULL || *cursor != '-')
    return false;
  cursor++;
  cursor = rustfrida_parse_hex (cursor, &ignored);
  if (cursor == NULL)
    return false;

  cursor = rustfrida_skip_spaces (cursor);
  if (cursor[0] != 'r')
    return false;
  cursor = rustfrida_next_field (cursor);

  cursor = rustfrida_parse_hex (cursor, &offset);
  if (cursor == NULL)
    return false;
  cursor = rustfrida_next_field (cursor);
  cursor = rustfrida_next_field (cursor);
  cursor = rustfrida_next_field (cursor);

  path = cursor;
  if (*path != '/')
    return false;
  /*
   * Only index the platform modules needed by the agent's imports. Scanning
   * every app .so is both noisy and unsafe in hardened apps with unusual
   * mappings or intentionally hostile ELF layouts.
   */
  if (!frida_str_has_suffix (path, "/libc.so") &&
      !frida_str_has_suffix (path, "/libdl.so") &&
      !frida_str_has_suffix (path, "/libm.so") &&
      !frida_str_has_suffix (path, "/linker64"))
  {
    return false;
  }

  if (offset > start)
    return false;

  return rustfrida_resolver_add_module (resolver, start - offset);
}

static bool
rustfrida_build_symbol_resolver (RustFridaLinkedModule * module, int diagfd, const FridaLibcApi * libc,
    const ElfW(Addr) * resolver_module_bases, size_t resolver_module_count,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base)
{
  static const char maps_path[] = "/proc/self/maps";
  char buffer[16384];
  char line[512];
  size_t line_len = 0;
  int fd;
  ssize_t n;

  frida_memset (&module->resolver, 0, sizeof (module->resolver));

  if (resolver_module_bases != NULL && resolver_module_count != 0)
  {
    size_t i;

    frida_send_debug (diagfd, "resolver:host-bases-begin", libc);
    for (i = 0; i != resolver_module_count; i++)
      rustfrida_resolver_add_module (&module->resolver, resolver_module_bases[i]);
    frida_send_debug (diagfd, "resolver:host-bases-end", libc);

    if (module->resolver.count != 0)
      return true;

    rustfrida_set_error (module, libc, "host resolver module list unusable");
    return false;
  }

  if (libc_base != 0)
    rustfrida_resolver_add_module (&module->resolver, libc_base);
  if (linker_base != 0)
    rustfrida_resolver_add_module (&module->resolver, linker_base);

  if (libc->dl_iterate_phdr != NULL)
  {
    RustFridaDlIterateContext ctx;

    ctx.resolver = &module->resolver;
    ctx.diagfd = diagfd;
    ctx.libc = libc;

    frida_send_debug (diagfd, "resolver:dl_iterate-begin", libc);
    libc->dl_iterate_phdr (rustfrida_dl_iterate_add_module, &ctx);
    frida_send_debug (diagfd, "resolver:dl_iterate-end", libc);

    if (module->resolver.count != 0)
      return true;

    frida_send_debug (diagfd, "resolver:dl_iterate-empty", libc);
  }

  frida_send_debug (diagfd, "resolver:maps-open", libc);
  fd = frida_syscall_4 (__NR_openat, AT_FDCWD, (size_t) maps_path, O_RDONLY, 0);
  if (fd < 0)
  {
    rustfrida_set_error (module, libc, "open /proc/self/maps failed");
    return false;
  }

  while ((n = frida_syscall_3 (__NR_read, fd, (size_t) buffer, sizeof (buffer))) > 0)
  {
    ssize_t i;

    frida_send_debug (diagfd, "resolver:maps-read", libc);
    for (i = 0; i != n; i++)
    {
      char ch = buffer[i];

      if (ch == '\n' || line_len == sizeof (line) - 1)
      {
        line[line_len] = '\0';
        rustfrida_maps_line_add_module (&module->resolver, line);
        line_len = 0;
      }
      else
      {
        line[line_len++] = ch;
      }
    }
  }

  if (line_len != 0)
  {
    line[line_len] = '\0';
    rustfrida_maps_line_add_module (&module->resolver, line);
  }

  frida_syscall_1 (__NR_close, fd);

  if (module->resolver.count == 0)
  {
    rustfrida_set_error (module, libc, "no export modules found");
    return false;
  }

  return true;
}

static int
rustfrida_dl_iterate_add_module (struct dl_phdr_info * info, size_t size, void * user_data)
{
  RustFridaDlIterateContext * ctx = user_data;
  ElfW(Addr) candidate_base;
  ElfW(Half) i;

  (void) size;

  if (info == NULL || info->dlpi_addr == 0 || info->dlpi_phdr == NULL || info->dlpi_phnum == 0)
    return 0;

  candidate_base = info->dlpi_addr;
  for (i = 0; i != info->dlpi_phnum; i++)
  {
    const ElfW(Phdr) * phdr = &info->dlpi_phdr[i];

    if (phdr->p_type == PT_LOAD && phdr->p_offset == 0)
    {
      candidate_base = info->dlpi_addr + phdr->p_vaddr;
      break;
    }
  }

  frida_send_debug (ctx->diagfd, "resolver:module", ctx->libc);
  if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
    frida_send_debug (ctx->diagfd, info->dlpi_name, ctx->libc);
  else
    frida_send_debug (ctx->diagfd, "resolver:module:<main>", ctx->libc);

  rustfrida_resolver_add_module (ctx->resolver, candidate_base);
  return 0;
}

static bool
rustfrida_resolver_lookup (const RustFridaSymbolResolver * resolver, const char * name, ElfW(Addr) * value)
{
  size_t module_index;

  for (module_index = 0; module_index != resolver->count; module_index++)
  {
    const RustFridaExportModule * module = &resolver->modules[module_index];
    size_t i;

    for (i = 0; i != module->nsyms; i++)
    {
      const ElfW(Sym) * sym = &module->symtab[i];
      unsigned char bind;
      unsigned char type;

      if (sym->st_name >= module->strsz || sym->st_shndx == SHN_UNDEF || sym->st_value == 0)
        continue;

      bind = ELF64_ST_BIND (sym->st_info);
      if (bind != STB_GLOBAL && bind != STB_WEAK)
        continue;

      type = ELF64_ST_TYPE (sym->st_info);
      if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE && type != STT_GNU_IFUNC)
        continue;

      if (frida_streq (module->strtab + sym->st_name, name))
      {
        ElfW(Addr) resolved = (sym->st_shndx == SHN_ABS) ? sym->st_value : module->base + sym->st_value;

        if (type == STT_GNU_IFUNC)
        {
          if (!rustfrida_address_is_executable (resolved))
            continue;
          resolved = ((ElfW(Addr) (*) (void)) resolved) ();
          if (resolved == 0 || !rustfrida_address_is_executable (resolved))
            continue;
        }
        *value = resolved;
        return true;
      }
    }
  }

  *value = 0;
  return false;
}

static void
rustfrida_set_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * message)
{
  if (libc->sprintf != NULL)
    libc->sprintf (module->error, "%s", message);
}

static void
rustfrida_set_symbol_error (RustFridaLinkedModule * module, const FridaLibcApi * libc, const char * prefix, const char * name)
{
  if (libc->sprintf != NULL)
  {
    libc->sprintf (module->error, "%s%s (modules=%zu nsyms=%zu,%zu,%zu)",
        prefix,
        name,
        module->resolver.count,
        module->resolver.count > 0 ? module->resolver.modules[0].nsyms : 0,
        module->resolver.count > 1 ? module->resolver.modules[1].nsyms : 0,
        module->resolver.count > 2 ? module->resolver.modules[2].nsyms : 0);
  }
}

static bool
rustfrida_parse_dynamic (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  ElfW(Rela) * rela = NULL;
  size_t relasz = 0;
  ElfW(Rela) * jmprel = NULL;
  size_t pltrelsz = 0;
  size_t max_reloc_sym = 0;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_SYMTAB:
        module->symtab = (const ElfW(Sym) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_STRTAB:
        module->strtab = (const char *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_STRSZ:
        module->strsz = dyn->d_un.d_val;
        break;
      case DT_GNU_HASH:
        module->gnu_hash = (const uint32_t *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELA:
        rela = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (module->symtab == NULL || module->strtab == NULL || module->strsz == 0)
    return false;

  module->nsyms = rustfrida_gnu_hash_nsyms (module->gnu_hash);

  if (rela != NULL)
  {
    size_t n = relasz / sizeof (ElfW(Rela));
    size_t i;
    for (i = 0; i != n; i++)
    {
      size_t sym = ELF64_R_SYM (rela[i].r_info);
      if (sym > max_reloc_sym)
        max_reloc_sym = sym;
    }
  }
  if (jmprel != NULL)
  {
    size_t n = pltrelsz / sizeof (ElfW(Rela));
    size_t i;
    for (i = 0; i != n; i++)
    {
      size_t sym = ELF64_R_SYM (jmprel[i].r_info);
      if (sym > max_reloc_sym)
        max_reloc_sym = sym;
    }
  }

  if (module->nsyms <= max_reloc_sym)
    module->nsyms = max_reloc_sym + 1;

  return module->nsyms != 0;
}

static bool
rustfrida_resolve_symbol (RustFridaLinkedModule * module, size_t sym_index, int diagfd, const FridaLibcApi * libc, ElfW(Addr) * value)
{
  const ElfW(Sym) * sym;
  const char * name;
  unsigned char bind;

  if (sym_index == 0)
  {
    *value = 0;
    return true;
  }

  if (sym_index >= module->nsyms)
  {
    rustfrida_set_error (module, libc, "symbol index out of range");
    return false;
  }

  sym = &module->symtab[sym_index];
  if (sym->st_shndx != SHN_UNDEF)
  {
    *value = (sym->st_shndx == SHN_ABS) ? sym->st_value : module->base + sym->st_value;
    return true;
  }

  if (sym->st_name >= module->strsz)
  {
    rustfrida_set_error (module, libc, "symbol name out of range");
    return false;
  }

  name = module->strtab + sym->st_name;
  bind = ELF64_ST_BIND (sym->st_info);
  frida_send_debug (diagfd, "link:resolve-symbol", libc);
  frida_send_debug (diagfd, name, libc);
  if (rustfrida_try_resolve_local_symbol (name, value))
  {
    frida_send_debug (diagfd, "link:resolve-local", libc);
    return true;
  }
  if (rustfrida_resolver_lookup (&module->resolver, name, value))
    return true;

  if (bind == STB_WEAK)
  {
    *value = 0;
    return true;
  }

  rustfrida_set_symbol_error (module, libc, "missing symbol: ", name);
  return false;
}

static bool
rustfrida_try_resolve_local_symbol (const char * name, ElfW(Addr) * value)
{
  if (frida_streq (name, "memcpy"))
    *value = (ElfW(Addr)) frida_memcpy;
  else if (frida_streq (name, "memmove"))
    *value = (ElfW(Addr)) frida_memmove;
  else if (frida_streq (name, "memset"))
    *value = (ElfW(Addr)) frida_memset;
  else if (frida_streq (name, "memcmp"))
    *value = (ElfW(Addr)) frida_memcmp;
  else if (frida_streq (name, "strlen"))
    *value = (ElfW(Addr)) frida_strlen;
  else if (frida_streq (name, "strcmp"))
    *value = (ElfW(Addr)) frida_strcmp;
  else if (frida_streq (name, "strncmp"))
    *value = (ElfW(Addr)) frida_strncmp;
  else if (frida_streq (name, "strchr"))
    *value = (ElfW(Addr)) frida_strchr;
  else if (frida_streq (name, "strrchr"))
    *value = (ElfW(Addr)) frida_strrchr;
  else if (frida_streq (name, "strstr"))
    *value = (ElfW(Addr)) frida_strstr;
  else if (frida_streq (name, "strcpy"))
    *value = (ElfW(Addr)) frida_strcpy;
  else if (frida_streq (name, "strncpy"))
    *value = (ElfW(Addr)) frida_strncpy;
  else if (frida_streq (name, "memchr"))
    *value = (ElfW(Addr)) frida_memchr;
  else if (frida_streq (name, "gettid"))
    *value = (ElfW(Addr)) frida_gettid;
  else if (frida_streq (name, "__clear_cache"))
    *value = (ElfW(Addr)) rustfrida_clear_cache;
  else if (rustfrida_try_resolve_aarch64_builtin (name, value))
    return true;
  else
    return false;

  return true;
}

#define RUSTFRIDA_AARCH64_MATCH_ORDER(name, stem) \
    (frida_streq ((name), "__aarch64_" stem "_acq_rel") || \
     frida_streq ((name), "__aarch64_" stem "_acq") || \
     frida_streq ((name), "__aarch64_" stem "_rel") || \
     frida_streq ((name), "__aarch64_" stem "_relax"))

static bool
rustfrida_try_resolve_aarch64_builtin (const char * name, ElfW(Addr) * value)
{
  if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldadd1"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldadd1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldadd2"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldadd2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldadd4"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldadd4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldadd8"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldadd8;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldclr1"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldclr1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldclr2"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldclr2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldclr4"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldclr4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldclr8"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldclr8;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldset1"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldset1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldset2"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldset2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldset4"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldset4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldset8"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldset8;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldeor1"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldeor1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldeor2"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldeor2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldeor4"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldeor4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "ldeor8"))
    *value = (ElfW(Addr)) rustfrida_atomic_ldeor8;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "swp1"))
    *value = (ElfW(Addr)) rustfrida_atomic_swp1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "swp2"))
    *value = (ElfW(Addr)) rustfrida_atomic_swp2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "swp4"))
    *value = (ElfW(Addr)) rustfrida_atomic_swp4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "swp8"))
    *value = (ElfW(Addr)) rustfrida_atomic_swp8;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "cas1"))
    *value = (ElfW(Addr)) rustfrida_atomic_cas1;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "cas2"))
    *value = (ElfW(Addr)) rustfrida_atomic_cas2;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "cas4"))
    *value = (ElfW(Addr)) rustfrida_atomic_cas4;
  else if (RUSTFRIDA_AARCH64_MATCH_ORDER (name, "cas8"))
    *value = (ElfW(Addr)) rustfrida_atomic_cas8;
  else if (frida_streq (name, "__emutls_get_address"))
    *value = (ElfW(Addr)) rustfrida_emutls_get_address;
  else
    return false;

  return true;
}

static void
rustfrida_clear_cache (char * begin, char * end)
{
#if defined (__aarch64__)
  uintptr_t start = (uintptr_t) begin;
  uintptr_t finish = (uintptr_t) end;
  uintptr_t ctr_el0;
  uintptr_t dcache_line_size;
  uintptr_t icache_line_size;
  uintptr_t cursor;

  if (finish <= start)
    return;

  __asm__ volatile ("mrs %0, ctr_el0" : "=r" (ctr_el0));
  dcache_line_size = (uintptr_t) 4 << ((ctr_el0 >> 16) & 0xf);
  icache_line_size = (uintptr_t) 4 << (ctr_el0 & 0xf);

  for (cursor = start & ~(dcache_line_size - 1); cursor < finish; cursor += dcache_line_size)
    __asm__ volatile ("dc cvau, %0" :: "r" (cursor) : "memory");
  __asm__ volatile ("dsb ish" ::: "memory");

  for (cursor = start & ~(icache_line_size - 1); cursor < finish; cursor += icache_line_size)
    __asm__ volatile ("ic ivau, %0" :: "r" (cursor) : "memory");
  __asm__ volatile ("dsb ish\n\tisb" ::: "memory");
#else
  (void) begin;
  (void) end;
#endif
}

/* LLVM's AArch64 outline atomic helpers are not exported by bionic on all devices. */
#define RUSTFRIDA_DEFINE_ATOMIC_OP_1(name, expr) \
static uint8_t \
name (uint8_t value, volatile uint8_t * address) \
{ \
  uint32_t old_value; \
  uint32_t new_value; \
  uint32_t status; \
  do \
  { \
    __asm__ volatile ( \
        "ldaxrb %w[old_value], [%[address]]\n\t" \
        expr "\n\t" \
        "stlxrb %w[status], %w[new_value], [%[address]]" \
        : [old_value] "=&r" (old_value), \
          [new_value] "=&r" (new_value), \
          [status] "=&r" (status) \
        : [address] "r" (address), \
          [value] "r" ((uint32_t) value) \
        : "memory", "cc"); \
  } \
  while (status != 0); \
  return (uint8_t) old_value; \
}

#define RUSTFRIDA_DEFINE_ATOMIC_OP_2(name, expr) \
static uint16_t \
name (uint16_t value, volatile uint16_t * address) \
{ \
  uint32_t old_value; \
  uint32_t new_value; \
  uint32_t status; \
  do \
  { \
    __asm__ volatile ( \
        "ldaxrh %w[old_value], [%[address]]\n\t" \
        expr "\n\t" \
        "stlxrh %w[status], %w[new_value], [%[address]]" \
        : [old_value] "=&r" (old_value), \
          [new_value] "=&r" (new_value), \
          [status] "=&r" (status) \
        : [address] "r" (address), \
          [value] "r" ((uint32_t) value) \
        : "memory", "cc"); \
  } \
  while (status != 0); \
  return (uint16_t) old_value; \
}

#define RUSTFRIDA_DEFINE_ATOMIC_OP_4(name, expr) \
static uint32_t \
name (uint32_t value, volatile uint32_t * address) \
{ \
  uint32_t old_value; \
  uint32_t new_value; \
  uint32_t status; \
  do \
  { \
    __asm__ volatile ( \
        "ldaxr %w[old_value], [%[address]]\n\t" \
        expr "\n\t" \
        "stlxr %w[status], %w[new_value], [%[address]]" \
        : [old_value] "=&r" (old_value), \
          [new_value] "=&r" (new_value), \
          [status] "=&r" (status) \
        : [address] "r" (address), \
          [value] "r" (value) \
        : "memory", "cc"); \
  } \
  while (status != 0); \
  return old_value; \
}

#define RUSTFRIDA_DEFINE_ATOMIC_OP_8(name, expr) \
static uint64_t \
name (uint64_t value, volatile uint64_t * address) \
{ \
  uint64_t old_value; \
  uint64_t new_value; \
  uint32_t status; \
  do \
  { \
    __asm__ volatile ( \
        "ldaxr %[old_value], [%[address]]\n\t" \
        expr "\n\t" \
        "stlxr %w[status], %[new_value], [%[address]]" \
        : [old_value] "=&r" (old_value), \
          [new_value] "=&r" (new_value), \
          [status] "=&r" (status) \
        : [address] "r" (address), \
          [value] "r" (value) \
        : "memory", "cc"); \
  } \
  while (status != 0); \
  return old_value; \
}

RUSTFRIDA_DEFINE_ATOMIC_OP_1 (rustfrida_atomic_ldadd1, "add %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_2 (rustfrida_atomic_ldadd2, "add %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_4 (rustfrida_atomic_ldadd4, "add %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_8 (rustfrida_atomic_ldadd8, "add %[new_value], %[old_value], %[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_1 (rustfrida_atomic_ldclr1, "bic %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_2 (rustfrida_atomic_ldclr2, "bic %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_4 (rustfrida_atomic_ldclr4, "bic %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_8 (rustfrida_atomic_ldclr8, "bic %[new_value], %[old_value], %[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_1 (rustfrida_atomic_ldset1, "orr %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_2 (rustfrida_atomic_ldset2, "orr %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_4 (rustfrida_atomic_ldset4, "orr %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_8 (rustfrida_atomic_ldset8, "orr %[new_value], %[old_value], %[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_1 (rustfrida_atomic_ldeor1, "eor %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_2 (rustfrida_atomic_ldeor2, "eor %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_4 (rustfrida_atomic_ldeor4, "eor %w[new_value], %w[old_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_8 (rustfrida_atomic_ldeor8, "eor %[new_value], %[old_value], %[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_1 (rustfrida_atomic_swp1, "mov %w[new_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_2 (rustfrida_atomic_swp2, "mov %w[new_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_4 (rustfrida_atomic_swp4, "mov %w[new_value], %w[value]")
RUSTFRIDA_DEFINE_ATOMIC_OP_8 (rustfrida_atomic_swp8, "mov %[new_value], %[value]")

static uint8_t
rustfrida_atomic_cas1 (uint8_t expected, uint8_t desired, volatile uint8_t * address)
{
  uint32_t old_value;
  uint32_t status;

  do
  {
    __asm__ volatile (
        "ldaxrb %w[old_value], [%[address]]\n\t"
        "cmp %w[old_value], %w[expected]\n\t"
        "b.ne 1f\n\t"
        "stlxrb %w[status], %w[desired], [%[address]]\n\t"
        "1:"
        : [old_value] "=&r" (old_value),
          [status] "=&r" (status)
        : [address] "r" (address),
          [expected] "r" ((uint32_t) expected),
          [desired] "r" ((uint32_t) desired)
        : "memory", "cc");
    if ((uint8_t) old_value != expected)
      return (uint8_t) old_value;
  }
  while (status != 0);

  return expected;
}

static uint16_t
rustfrida_atomic_cas2 (uint16_t expected, uint16_t desired, volatile uint16_t * address)
{
  uint32_t old_value;
  uint32_t status;

  do
  {
    __asm__ volatile (
        "ldaxrh %w[old_value], [%[address]]\n\t"
        "cmp %w[old_value], %w[expected]\n\t"
        "b.ne 1f\n\t"
        "stlxrh %w[status], %w[desired], [%[address]]\n\t"
        "1:"
        : [old_value] "=&r" (old_value),
          [status] "=&r" (status)
        : [address] "r" (address),
          [expected] "r" ((uint32_t) expected),
          [desired] "r" ((uint32_t) desired)
        : "memory", "cc");
    if ((uint16_t) old_value != expected)
      return (uint16_t) old_value;
  }
  while (status != 0);

  return expected;
}

static uint32_t
rustfrida_atomic_cas4 (uint32_t expected, uint32_t desired, volatile uint32_t * address)
{
  uint32_t old_value;
  uint32_t status;

  do
  {
    __asm__ volatile (
        "ldaxr %w[old_value], [%[address]]\n\t"
        "cmp %w[old_value], %w[expected]\n\t"
        "b.ne 1f\n\t"
        "stlxr %w[status], %w[desired], [%[address]]\n\t"
        "1:"
        : [old_value] "=&r" (old_value),
          [status] "=&r" (status)
        : [address] "r" (address),
          [expected] "r" (expected),
          [desired] "r" (desired)
        : "memory", "cc");
    if (old_value != expected)
      return old_value;
  }
  while (status != 0);

  return expected;
}

static uint64_t
rustfrida_atomic_cas8 (uint64_t expected, uint64_t desired, volatile uint64_t * address)
{
  uint64_t old_value;
  uint32_t status;

  do
  {
    __asm__ volatile (
        "ldaxr %[old_value], [%[address]]\n\t"
        "cmp %[old_value], %[expected]\n\t"
        "b.ne 1f\n\t"
        "stlxr %w[status], %[desired], [%[address]]\n\t"
        "1:"
        : [old_value] "=&r" (old_value),
          [status] "=&r" (status)
        : [address] "r" (address),
          [expected] "r" (expected),
          [desired] "r" (desired)
        : "memory", "cc");
    if (old_value != expected)
      return old_value;
  }
  while (status != 0);

  return expected;
}

#define RUSTFRIDA_EMUTLS_MAX_OBJECTS 64

typedef struct {
  size_t size;
  size_t align;
  union {
    uintptr_t offset;
    void * ptr;
  } loc;
  void * templ;
} RustFridaEmutlsObject;

typedef struct {
  RustFridaEmutlsObject * object;
  void * address;
} RustFridaEmutlsSlot;

static RustFridaEmutlsSlot rustfrida_emutls_slots[RUSTFRIDA_EMUTLS_MAX_OBJECTS];

static void *
rustfrida_emutls_get_address (void * object)
{
  RustFridaEmutlsObject * emutls_object = object;
  size_t i;
  size_t align;
  size_t size;
  size_t mapping_size;
  void * mapping;
  void * address;

  if (emutls_object == NULL || emutls_object->size == 0)
    return NULL;

  for (i = 0; i != RUSTFRIDA_EMUTLS_MAX_OBJECTS; i++)
  {
    RustFridaEmutlsSlot * slot = &rustfrida_emutls_slots[i];

    if (slot->object == emutls_object)
      return slot->address;
  }

  align = emutls_object->align;
  if (align < sizeof (void *))
    align = sizeof (void *);
  size = emutls_object->size;
  mapping_size = rustfrida_align_size_up (size + align, 4096);
  mapping = (void *) frida_syscall_6 (__NR_mmap, 0, mapping_size, PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS, (size_t) -1, 0);
  if ((intptr_t) mapping < 0)
    return NULL;

  address = (void *) rustfrida_align_up ((ElfW(Addr)) mapping, align);
  if (emutls_object->templ != NULL)
    frida_memcpy (address, emutls_object->templ, size);

  for (i = 0; i != RUSTFRIDA_EMUTLS_MAX_OBJECTS; i++)
  {
    RustFridaEmutlsSlot * slot = &rustfrida_emutls_slots[i];

    if (slot->object == NULL)
    {
      slot->object = emutls_object;
      slot->address = address;
      return address;
    }
  }

  frida_syscall_2 (__NR_munmap, (size_t) mapping, mapping_size);
  return NULL;
}

static bool
rustfrida_apply_relocations (RustFridaLinkedModule * module, ElfW(Rela) * rela, size_t relasz, int diagfd,
    const FridaLibcApi * libc, bool use_call_veneers)
{
  size_t count = relasz / sizeof (ElfW(Rela));
  size_t i;

  for (i = 0; i != count; i++)
  {
    ElfW(Rela) * r = &rela[i];
    ElfW(Addr) * target = (ElfW(Addr) *) (module->base + r->r_offset);
    size_t type = ELF64_R_TYPE (r->r_info);
    size_t sym_index = ELF64_R_SYM (r->r_info);
    ElfW(Addr) symbol_value;

    switch (type)
    {
      case R_AARCH64_RELATIVE:
        *target = module->base + r->r_addend;
        break;
      case R_AARCH64_ABS64:
      case R_AARCH64_GLOB_DAT:
      case R_AARCH64_JUMP_SLOT:
        if (!rustfrida_resolve_symbol (module, sym_index, diagfd, libc, &symbol_value))
          return false;
        symbol_value += r->r_addend;
        if (use_call_veneers && type == R_AARCH64_JUMP_SLOT && symbol_value != 0)
        {
          ElfW(Addr) veneer = rustfrida_emit_call_veneer (module, symbol_value, libc);
          if (veneer == 0)
            return false;
          *target = veneer;
        }
        else
        {
          *target = symbol_value;
        }
        break;
      default:
        if (libc->sprintf != NULL)
          libc->sprintf (module->error, "unsupported relocation type: %zu", type);
        return false;
    }
  }

  return true;
}

static bool
rustfrida_alloc_call_veneers (RustFridaLinkedModule * module, size_t capacity, const FridaLibcApi * libc)
{
  size_t page_size = 4096;
  size_t size;
  void * mapping;

  if (capacity == 0)
    return true;

  size = rustfrida_align_up (capacity * 32, page_size);
  mapping = frida_raw_mmap (NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED)
  {
    rustfrida_set_error (module, libc, "allocate call veneers failed");
    return false;
  }

  module->veneer_start = (ElfW(Addr)) mapping;
  module->veneer_end = module->veneer_start + size;
  module->veneer_count = 0;
  module->veneer_capacity = capacity;
  return true;
}

static ElfW(Addr)
rustfrida_emit_call_veneer (RustFridaLinkedModule * module, ElfW(Addr) target, const FridaLibcApi * libc)
{
  uint8_t * code;
  const uint32_t instructions[] = {
    0xd50324df, /* bti jc */
    0xa9bf7be9, /* stp x9, x30, [sp, #-16]! */
    0x58000089, /* ldr x9, #0x10 */
    0xd63f0120, /* blr x9 */
    0xa8c17be9, /* ldp x9, x30, [sp], #16 */
    0xd65f03c0, /* ret */
  };

  if (module->veneer_count >= module->veneer_capacity || module->veneer_start == 0)
  {
    rustfrida_set_error (module, libc, "call veneer table exhausted");
    return 0;
  }

  code = (uint8_t *) (module->veneer_start + (module->veneer_count * 32));
  module->veneer_count++;

  frida_memcpy (code, instructions, sizeof (instructions));
  frida_memcpy (code + 24, &target, sizeof (target));

  return (ElfW(Addr)) code;
}

static bool
rustfrida_protect_call_veneers (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  if (module->veneer_start == 0)
    return true;

  if (frida_syscall_3 (__NR_mprotect, module->veneer_start, module->veneer_end - module->veneer_start,
      PROT_READ | PROT_EXEC | PROT_BTI) != 0)
  {
    rustfrida_set_error (module, libc, "protect call veneers failed");
    return false;
  }

  return true;
}

static bool
rustfrida_protect_relro (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  ElfW(Half) i;

  for (i = 0; i != module->phdr_count; i++)
  {
    const ElfW(Phdr) * phdr = &module->phdrs[i];
    ElfW(Addr) start, end;

    if (phdr->p_type != PT_GNU_RELRO || phdr->p_memsz == 0)
      continue;

    start = rustfrida_align_down (module->base + phdr->p_vaddr, 4096);
    end = rustfrida_align_up (module->base + phdr->p_vaddr + phdr->p_memsz, 4096);
    if (frida_syscall_3 (__NR_mprotect, start, end - start, PROT_READ) != 0)
    {
      rustfrida_set_error (module, libc, "mprotect RELRO failed");
      return false;
    }
  }

  return true;
}

static bool
rustfrida_protect_load_segments (RustFridaLinkedModule * module, const FridaLibcApi * libc, bool enable_bti)
{
  ElfW(Half) i;

  for (i = 0; i != module->phdr_count; i++)
  {
    const ElfW(Phdr) * phdr = &module->phdrs[i];
    ElfW(Addr) start;
    ElfW(Addr) end;
    int prot;

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    start = rustfrida_align_down (module->base + phdr->p_vaddr, 4096);
    end = rustfrida_align_up (module->base + phdr->p_vaddr + phdr->p_memsz, 4096);
    prot = rustfrida_phdr_prot (phdr);
    if (enable_bti && module->uses_bti && (prot & PROT_EXEC) != 0)
      prot |= PROT_BTI;

    if (frida_syscall_3 (__NR_mprotect, start, end - start, prot) != 0)
    {
      rustfrida_set_error (module, libc, "mprotect LOAD segment failed");
      return false;
    }
  }

  return true;
}

static void
rustfrida_call_init_functions (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  void (* init_func) (void) = NULL;
  void (** init_array) (void) = NULL;
  size_t init_array_size = 0;
  size_t i;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_INIT:
        init_func = (void (*) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_INIT_ARRAY:
        init_array = (void (**) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_INIT_ARRAYSZ:
        init_array_size = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (init_func != NULL)
    init_func ();

  if (init_array != NULL && init_array_size != 0)
  {
    for (i = 0; i != init_array_size / sizeof (init_array[0]); i++)
    {
      if (init_array[i] != NULL)
        init_array[i] ();
    }
  }

  module->initialized = true;
}

static void
rustfrida_call_fini_functions (RustFridaLinkedModule * module)
{
  ElfW(Dyn) * dyn;
  void (* fini_func) (void) = NULL;
  void (** fini_array) (void) = NULL;
  size_t fini_array_size = 0;
  size_t count;

  if (!module->initialized || module->finalized)
    return;
  module->finalized = true;

  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_FINI:
        fini_func = (void (*) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_FINI_ARRAY:
        fini_array = (void (**) (void)) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_FINI_ARRAYSZ:
        fini_array_size = dyn->d_un.d_val;
        break;
      default:
        break;
    }
  }

  if (fini_array != NULL && fini_array_size != 0)
  {
    count = fini_array_size / sizeof (fini_array[0]);
    while (count != 0)
    {
      void (* fini) (void) = fini_array[--count];
      if (fini != NULL)
        fini ();
    }
  }

  if (fini_func != NULL)
    fini_func ();
}

static bool
rustfrida_link_agent (int fd, int diagfd, const FridaLibcApi * libc, RustFridaLinkedModule * module,
    const ElfW(Addr) * resolver_module_bases, size_t resolver_module_count,
    ElfW(Addr) libc_base, ElfW(Addr) linker_base, const char * agent_vma_name, bool catch_link_signals, bool stream_agent)
{
  size_t page_size = 4096;
  ssize_t file_size;
  void * file_map = MAP_FAILED;
  void * reservation = MAP_FAILED;
  const ElfW(Ehdr) * file_ehdr;
  const ElfW(Phdr) * file_phdrs;
  ElfW(Addr) min_vaddr = (ElfW(Addr)) -1;
  ElfW(Addr) max_vaddr = 0;
  ElfW(Addr) load_start;
  ElfW(Addr) load_end;
  ElfW(Addr) load_size;
  ElfW(Addr) load_bias;
  ElfW(Half) i;
  ElfW(Rela) * rela = NULL;
  size_t relasz = 0;
  ElfW(Rela) * jmprel = NULL;
  size_t pltrelsz = 0;
  ElfW(Dyn) * dyn;
  bool fd_open = fd != -1;

  frida_send_debug (diagfd, "link:begin", libc);
  frida_memset (module, 0, sizeof (*module));
  frida_send_log (diagfd, "link: start", libc);

  if (stream_agent)
  {
    uint64_t stream_size = 0;

    frida_send_debug (diagfd, "link:recv-stream-size", libc);
    if (!frida_receive_chunk (diagfd, &stream_size, sizeof (stream_size), libc) ||
        stream_size == 0 || stream_size > (uint64_t) (512 * 1024 * 1024))
    {
      rustfrida_set_error (module, libc, "invalid streamed agent size");
      goto fail;
    }
    file_size = (ssize_t) stream_size;

    frida_send_debug (diagfd, "link:mmap-buffer", libc);
    file_map = frida_raw_mmap (NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (file_map == MAP_FAILED)
    {
      rustfrida_set_error (module, libc, "mmap agent buffer failed");
      goto fail;
    }

    frida_send_debug (diagfd, "link:recv-stream", libc);
    if (!frida_receive_chunk (diagfd, file_map, (size_t) file_size, libc))
    {
      rustfrida_set_error (module, libc, "read streamed agent failed");
      goto fail;
    }
    frida_send_debug (diagfd, "link:recv-stream-ok", libc);
  }
  else
  {
    frida_send_debug (diagfd, "link:lseek", libc);
    file_size = frida_syscall_3 (__NR_lseek, fd, 0, SEEK_END);
    if (file_size <= 0)
    {
      rustfrida_set_error (module, libc, "lseek agent fd failed");
      goto fail;
    }
    if (frida_syscall_3 (__NR_lseek, fd, 0, SEEK_SET) != 0)
    {
      rustfrida_set_error (module, libc, "rewind agent fd failed");
      goto fail;
    }

    frida_send_debug (diagfd, "link:mmap-buffer", libc);
    file_map = frida_raw_mmap (NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (file_map == MAP_FAILED)
    {
      rustfrida_set_error (module, libc, "mmap agent buffer failed");
      goto fail;
    }

    frida_send_debug (diagfd, "link:read-file", libc);
    {
      size_t offset = 0;

      while (offset < (size_t) file_size)
      {
        ssize_t n = frida_syscall_3 (__NR_read, fd, (size_t) ((uint8_t *) file_map + offset),
            (size_t) file_size - offset);
        if (n <= 0)
        {
          rustfrida_set_error (module, libc, "read agent fd failed");
          goto fail;
        }
        offset += n;
      }
    }
    frida_raw_close (fd);
    fd_open = false;
  }

  frida_send_debug (diagfd, "link:validate-elf", libc);
  file_ehdr = (const ElfW(Ehdr) *) file_map;
  if (!rustfrida_is_valid_elf (file_ehdr))
  {
    rustfrida_set_error (module, libc, "invalid agent ELF");
    goto fail;
  }
  frida_send_log (diagfd, "link: elf mapped", libc);

  if (file_ehdr->e_phoff + (file_ehdr->e_phnum * sizeof (ElfW(Phdr))) > (size_t) file_size)
  {
    rustfrida_set_error (module, libc, "agent phdr out of range");
    goto fail;
  }

  file_phdrs = (const ElfW(Phdr) *) ((const uint8_t *) file_map + file_ehdr->e_phoff);
  frida_send_debug (diagfd, "link:scan-phdrs", libc);
  for (i = 0; i != file_ehdr->e_phnum; i++)
  {
    const ElfW(Phdr) * phdr = &file_phdrs[i];

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    if (phdr->p_vaddr < min_vaddr)
      min_vaddr = phdr->p_vaddr;
    if (phdr->p_vaddr + phdr->p_memsz > max_vaddr)
      max_vaddr = phdr->p_vaddr + phdr->p_memsz;
  }

  if (min_vaddr == (ElfW(Addr)) -1 || max_vaddr <= min_vaddr)
  {
    rustfrida_set_error (module, libc, "agent has no loadable segments");
    goto fail;
  }

  load_start = rustfrida_align_down (min_vaddr, page_size);
  load_end = rustfrida_align_up (max_vaddr, page_size);
  load_size = load_end - load_start;

  frida_send_debug (diagfd, "link:reserve", libc);
  reservation = frida_raw_mmap (NULL, load_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED)
  {
    rustfrida_set_error (module, libc, "reserve agent address space failed");
    goto fail;
  }

  load_bias = (ElfW(Addr)) reservation - load_start;

  frida_send_debug (diagfd, "link:map-segments", libc);
  for (i = 0; i != file_ehdr->e_phnum; i++)
  {
    const ElfW(Phdr) * phdr = &file_phdrs[i];
    ElfW(Addr) seg_start;
    ElfW(Addr) seg_end;
    ElfW(Addr) map_size;
    ElfW(Addr) target;

    if (phdr->p_type == PT_DYNAMIC)
      module->dynamic = (ElfW(Dyn) *) (load_bias + phdr->p_vaddr);

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    if (phdr->p_offset + phdr->p_filesz > (ElfW(Off)) file_size)
    {
      rustfrida_set_error (module, libc, "agent segment out of range");
      goto fail;
    }

    seg_start = rustfrida_align_down (phdr->p_vaddr, page_size);
    seg_end = rustfrida_align_up (phdr->p_vaddr + phdr->p_memsz, page_size);
    map_size = seg_end - seg_start;
    target = load_bias + seg_start;

    frida_send_debug (diagfd, "link:prepare-segment", libc);
    if (frida_syscall_3 (__NR_mprotect, target, map_size, PROT_READ | PROT_WRITE) != 0)
    {
      rustfrida_set_error (module, libc, "prepare agent segment failed");
      goto fail;
    }

    if (phdr->p_filesz != 0)
      frida_memcpy ((void *) (load_bias + phdr->p_vaddr), (const uint8_t *) file_map + phdr->p_offset, phdr->p_filesz);

    if (phdr->p_memsz > phdr->p_filesz)
    {
      ElfW(Addr) bss_start = load_bias + phdr->p_vaddr + phdr->p_filesz;
      ElfW(Addr) bss_end = load_bias + phdr->p_vaddr + phdr->p_memsz;
      ElfW(Addr) limit = load_bias + seg_end;

      if (bss_end > limit)
        bss_end = limit;
      if (bss_end > bss_start)
        frida_memset ((void *) bss_start, 0, bss_end - bss_start);
    }
  }
  frida_send_debug (diagfd, "link:segments-ok", libc);

  frida_send_log (diagfd, "link: load segments mapped", libc);

  module->base = load_bias;
  module->load_start = (ElfW(Addr)) reservation;
  module->load_end = (ElfW(Addr)) reservation + load_size;
  module->phdrs = (const ElfW(Phdr) *) (load_bias + file_ehdr->e_phoff);
  module->phdr_count = file_ehdr->e_phnum;
  module->uses_bti = rustfrida_elf_has_bti_property (file_map, (size_t) file_size, file_phdrs, file_ehdr->e_phnum);
  frida_send_debug (diagfd, module->uses_bti ? "link:bti-enabled" : "link:bti-disabled", libc);

  frida_send_debug (diagfd, "link:unmap-buffer", libc);
  frida_raw_munmap (file_map, file_size);
  file_map = MAP_FAILED;

  frida_send_debug (diagfd, "link:parse-dynamic", libc);
  if (module->dynamic == NULL)
  {
    rustfrida_set_error (module, libc, "agent has no dynamic section");
    goto fail;
  }

  if (!rustfrida_parse_dynamic (module))
  {
    rustfrida_set_error (module, libc, "agent dynamic section incomplete");
    goto fail;
  }
  frida_send_log (diagfd, "link: dynamic parsed", libc);

  frida_send_debug (diagfd, "link:build-resolver", libc);
  if (!rustfrida_build_symbol_resolver (module, diagfd, libc, resolver_module_bases, resolver_module_count,
        libc_base, linker_base))
    goto fail;
  frida_send_log (diagfd, "link: resolver built", libc);

  frida_send_debug (diagfd, "link:collect-relocations", libc);
  for (dyn = module->dynamic; dyn != NULL && dyn->d_tag != DT_NULL; dyn++)
  {
    switch (dyn->d_tag)
    {
      case DT_RELA:
        rela = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_RELASZ:
        relasz = dyn->d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = (ElfW(Rela) *) (module->base + dyn->d_un.d_ptr);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn->d_un.d_val;
        break;
      case DT_PLTREL:
        if (dyn->d_un.d_val != DT_RELA)
        {
          rustfrida_set_error (module, libc, "unsupported PLT relocation format");
          goto fail;
        }
        break;
      default:
        break;
    }
  }

  frida_send_debug (diagfd, "link:apply-rela", libc);
  if (rela != NULL && !rustfrida_apply_relocations (module, rela, relasz, diagfd, libc, false))
    goto fail;
  frida_send_log (diagfd, "link: rela applied", libc);
  if (pltrelsz != 0)
  {
    frida_send_debug (diagfd, "link:alloc-veneers", libc);
    if (!rustfrida_alloc_call_veneers (module, pltrelsz / sizeof (ElfW(Rela)), libc))
      goto fail;
  }
  frida_send_debug (diagfd, "link:apply-jmprel", libc);
  if (jmprel != NULL && !rustfrida_apply_relocations (module, jmprel, pltrelsz, diagfd, libc, true))
    goto fail;
  frida_send_log (diagfd, "link: plt rela applied", libc);
  if (module->veneer_start != 0)
  {
    frida_send_debug (diagfd, "link:protect-veneers", libc);
    if (!rustfrida_protect_call_veneers (module, libc))
      goto fail;
  }

  frida_send_debug (diagfd, "link:protect-load-init", libc);
  if (!rustfrida_protect_load_segments (module, libc, false))
    goto fail;
  frida_send_log (diagfd, "link: load segments protected for init", libc);
  if (catch_link_signals)
  {
    frida_send_debug (diagfd, "link:init-catch-install", libc);
    if (!rustfrida_install_entry_signal_handlers (module, diagfd, -1, libc))
      goto fail;
    frida_send_debug (diagfd, "link:init-catch-installed", libc);
  }
  frida_send_debug (diagfd, "link:call-init", libc);
  rustfrida_call_init_functions (module);
  frida_send_debug (diagfd, "link:call-init-ok", libc);
  frida_send_log (diagfd, "link: init done", libc);

  frida_send_debug (diagfd, "link:protect-load", libc);
  if (!rustfrida_protect_load_segments (module, libc, true))
    goto fail;
  frida_send_log (diagfd, "link: load segments protected", libc);

  frida_send_debug (diagfd, "link:protect-relro", libc);
  if (!rustfrida_protect_relro (module, libc))
    goto fail;
  frida_send_log (diagfd, "link: relro protected", libc);

  if (agent_vma_name != NULL)
  {
    frida_send_debug (diagfd, "link:name-vma", libc);
    rustfrida_name_load_segments (module, agent_vma_name);
  }

  return true;

fail:
  if (fd_open)
    frida_raw_close (fd);
  if (file_map != MAP_FAILED)
    frida_raw_munmap (file_map, file_size);
  if (reservation != MAP_FAILED)
  {
    module->load_start = (ElfW(Addr)) reservation;
    module->load_end = (ElfW(Addr)) reservation + load_size;
  }
  rustfrida_unmap_module (module, libc);
  return false;
}

static void *
rustfrida_find_export (RustFridaLinkedModule * module, const char * symbol)
{
  size_t i;

  if (module->symtab == NULL || module->strtab == NULL)
    return NULL;

  for (i = 0; i != module->nsyms; i++)
  {
    const ElfW(Sym) * sym = &module->symtab[i];
    unsigned char bind;

    if (sym->st_name >= module->strsz || sym->st_shndx == SHN_UNDEF)
      continue;

    bind = ELF64_ST_BIND (sym->st_info);
    if (bind != STB_GLOBAL && bind != STB_WEAK)
      continue;

    if (frida_streq (module->strtab + sym->st_name, symbol))
      return (void *) (module->base + sym->st_value);
  }

  return NULL;
}

static void
rustfrida_close_module (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  rustfrida_call_fini_functions (module);
  rustfrida_unmap_module (module, libc);
}

static void
rustfrida_name_load_segments (RustFridaLinkedModule * module, const char * name)
{
  const size_t page_size = 4096;
  ElfW(Half) i;

  if (module == NULL || name == NULL || *name == '\0' || module->phdrs == NULL)
    return;

  for (i = 0; i != module->phdr_count; i++)
  {
    const ElfW(Phdr) * phdr = &module->phdrs[i];
    ElfW(Addr) seg_start;
    ElfW(Addr) seg_end;

    if (phdr->p_type != PT_LOAD || phdr->p_memsz == 0)
      continue;

    seg_start = rustfrida_align_down (module->base + phdr->p_vaddr, page_size);
    seg_end = rustfrida_align_up (module->base + phdr->p_vaddr + phdr->p_memsz, page_size);
    if (seg_end > seg_start)
    {
      frida_syscall_5 (__NR_prctl, PR_SET_VMA, PR_SET_VMA_ANON_NAME,
          seg_start, seg_end - seg_start, (size_t) name);
    }
  }
}

static char *
rustfrida_append_literal (char * cursor, const char * end, const char * text)
{
  while (cursor < end && *text != '\0')
    *cursor++ = *text++;
  return cursor;
}

static char *
rustfrida_append_hex_value (char * cursor, const char * end, ElfW(Addr) value)
{
  static const char digits[] = "0123456789abcdef";
  int shift;

  cursor = rustfrida_append_literal (cursor, end, "0x");
  for (shift = (int) (sizeof (ElfW(Addr)) * 8) - 4; shift >= 0 && cursor < end; shift -= 4)
    *cursor++ = digits[(value >> shift) & 0xf];

  return cursor;
}

static char *
rustfrida_append_dec_value (char * cursor, const char * end, unsigned int value)
{
  char tmp[10];
  size_t len = 0;

  do
  {
    tmp[len++] = (char) ('0' + (value % 10));
    value /= 10;
  }
  while (value != 0 && len != sizeof (tmp));

  while (len != 0 && cursor < end)
    *cursor++ = tmp[--len];

  return cursor;
}

static char *
rustfrida_append_signed_dec_value (char * cursor, const char * end, int value)
{
  if (value < 0)
  {
    cursor = rustfrida_append_literal (cursor, end, "-");
    value = -value;
  }

  return rustfrida_append_dec_value (cursor, end, (unsigned int) value);
}

static void
rustfrida_send_entry_signal_log (int sockfd, int sig, int code, const void * fault_address,
    ElfW(Addr) pc, ElfW(Addr) sp, ElfW(Addr) lr)
{
  uint8_t type = 0x81;
  uint32_t length;
  char payload[320];
  char * cursor = payload;
  const char * end = payload + sizeof (payload);

  if (sockfd == -1)
    return;

  cursor = rustfrida_append_literal (cursor, end, "[loader] entry signal sig=");
  cursor = rustfrida_append_dec_value (cursor, end, (unsigned int) sig);
  cursor = rustfrida_append_literal (cursor, end, " code=");
  cursor = rustfrida_append_signed_dec_value (cursor, end, code);
  cursor = rustfrida_append_literal (cursor, end, " pc=");
  cursor = rustfrida_append_hex_value (cursor, end, pc);
  cursor = rustfrida_append_literal (cursor, end, " sp=");
  cursor = rustfrida_append_hex_value (cursor, end, sp);
  cursor = rustfrida_append_literal (cursor, end, " lr=");
  cursor = rustfrida_append_hex_value (cursor, end, lr);
  cursor = rustfrida_append_literal (cursor, end, " base=");
  cursor = rustfrida_append_hex_value (cursor, end, rustfrida_entry_agent_base);
  cursor = rustfrida_append_literal (cursor, end, " load=");
  cursor = rustfrida_append_hex_value (cursor, end, rustfrida_entry_agent_load_start);
  cursor = rustfrida_append_literal (cursor, end, "..");
  cursor = rustfrida_append_hex_value (cursor, end, rustfrida_entry_agent_load_end);
  if (rustfrida_entry_agent_base != 0 &&
      lr >= rustfrida_entry_agent_load_start &&
      lr < rustfrida_entry_agent_load_end)
  {
    cursor = rustfrida_append_literal (cursor, end, " lr_off=");
    cursor = rustfrida_append_hex_value (cursor, end, lr - rustfrida_entry_agent_base);
  }
  cursor = rustfrida_append_literal (cursor, end, " fault=");
  cursor = rustfrida_append_hex_value (cursor, end, (ElfW(Addr)) fault_address);
  cursor = rustfrida_append_literal (cursor, end, "\n");

  length = (uint32_t) (cursor - payload);
  frida_raw_send (sockfd, &type, sizeof (type), 0);
  frida_raw_send (sockfd, &length, sizeof (length), 0);
  frida_raw_send (sockfd, payload, length, 0);
}

static void
rustfrida_entry_signal_handler (int sig, siginfo_t * info, void * ucontext)
{
  ElfW(Addr) pc = 0;
  ElfW(Addr) sp = 0;
  ElfW(Addr) lr = 0;

#if defined (__aarch64__)
  if (ucontext != NULL)
  {
    ucontext_t * uc = (ucontext_t *) ucontext;
    pc = (ElfW(Addr)) uc->uc_mcontext.pc;
    sp = (ElfW(Addr)) uc->uc_mcontext.sp;
    lr = (ElfW(Addr)) uc->uc_mcontext.regs[30];
  }
#endif

  rustfrida_send_entry_signal_log (rustfrida_entry_signal_fd, sig,
      info != NULL ? info->si_code : 0, info != NULL ? info->si_addr : NULL, pc, sp, lr);

  if (rustfrida_entry_signal_fd != -1)
  {
    frida_raw_close (rustfrida_entry_signal_fd);
    rustfrida_entry_signal_fd = -1;
  }
  frida_syscall_1 (__NR_exit, (size_t) (128 + sig));
}

static bool
rustfrida_raw_install_entry_signal_handler (int sig)
{
  RustFridaKernelSigaction action;
  ssize_t result;

  frida_memset (&action, 0, sizeof (action));
  action.handler = (void (*) (int)) rustfrida_entry_signal_handler;
  action.flags = SA_SIGINFO | SA_ONSTACK;
  action.restorer = NULL;
  action.mask = 0;

  result = frida_syscall_4 (__NR_rt_sigaction, sig, (size_t) &action, 0, 8);
  return result == 0;
}

static bool
rustfrida_install_entry_signal_handlers (RustFridaLinkedModule * module, int loader_ctrlfd, int agent_ctrlfd,
    const FridaLibcApi * libc)
{
  frida_send_debug (loader_ctrlfd, "entry-catch:begin", libc);
  (void) module;

  rustfrida_entry_signal_fd = agent_ctrlfd;
  rustfrida_entry_agent_base = module->base;
  rustfrida_entry_agent_load_start = module->load_start;
  rustfrida_entry_agent_load_end = module->load_end;
  frida_send_debug (loader_ctrlfd, "entry-catch:install-segv", libc);
  if (!rustfrida_raw_install_entry_signal_handler (SIGSEGV))
    goto syscall_failed;
  frida_send_debug (loader_ctrlfd, "entry-catch:install-ill", libc);
  if (!rustfrida_raw_install_entry_signal_handler (SIGILL))
    goto syscall_failed;
  frida_send_debug (loader_ctrlfd, "entry-catch:install-bus", libc);
  if (!rustfrida_raw_install_entry_signal_handler (SIGBUS))
    goto syscall_failed;
  frida_send_debug (loader_ctrlfd, "entry-catch:install-abrt", libc);
  if (!rustfrida_raw_install_entry_signal_handler (SIGABRT))
    goto syscall_failed;
  frida_send_debug (loader_ctrlfd, "entry-catch:installed", libc);
  return true;

syscall_failed:
  frida_send_debug (loader_ctrlfd, "entry-catch:rt-sigaction-failed", libc);
  rustfrida_send_agent_log (agent_ctrlfd, "[loader] entry signal catch unavailable: rt_sigaction failed\n", libc);
  return false;
}

static void
rustfrida_unmap_module (RustFridaLinkedModule * module, const FridaLibcApi * libc)
{
  if (module->veneer_start != 0 && module->veneer_end > module->veneer_start)
  {
    frida_raw_munmap ((void *) module->veneer_start, module->veneer_end - module->veneer_start);
    module->veneer_start = 0;
    module->veneer_end = 0;
    module->veneer_count = 0;
    module->veneer_capacity = 0;
  }

  if (module->load_start != 0 && module->load_end > module->load_start)
  {
    frida_raw_munmap ((void *) module->load_start, module->load_end - module->load_start);
    module->load_start = 0;
    module->load_end = 0;
    module->base = 0;
    module->dynamic = NULL;
    module->phdrs = NULL;
    module->phdr_count = 0;
  }
}

/* ========== Worker thread ========== */

static void *
frida_main (void * user_data)
{
  RustFridaLoaderContext * ctx = user_data;
  const FridaLibcApi * libc = ctx->libc;
  RustFridaLinkedModule agent_module;
  pid_t thread_id;
  FridaUnloadPolicy unload_policy;
  int ctrlfd_for_peer, ctrlfd, agent_codefd, agent_ctrlfd;
  bool close_loader_ctrl;
  bool hold_before_entry;
  bool catch_entry_signals;
  bool stream_agent;
  bool agent_ctrl_is_loader;
  const char * agent_vma_name;

  frida_memset (&agent_module, 0, sizeof (agent_module));
  thread_id = frida_gettid ();
  unload_policy = FRIDA_UNLOAD_POLICY_IMMEDIATE;
  ctrlfd = -1;
  agent_codefd = -1;
  agent_ctrlfd = -1;
  close_loader_ctrl = frida_agent_data_has_token (ctx->agent_data, "close-ctrl");
  hold_before_entry = frida_agent_data_has_token (ctx->agent_data, "hold-entry");
  catch_entry_signals = frida_agent_data_has_token (ctx->agent_data, "catch-signals");
  stream_agent = frida_agent_data_has_token (ctx->agent_data, "stream-agent");
  agent_ctrl_is_loader = frida_agent_data_has_token (ctx->agent_data, "agent-ctrl=loader");
  rustfrida_loader_debug_enabled = frida_agent_data_has_token (ctx->agent_data, "loader-debug");
  agent_vma_name = frida_agent_data_get_last_value (ctx->agent_data, "vma");

  /* Close the peer end of the control socketpair */
  ctrlfd_for_peer = ctx->ctrlfds[0];
  if (ctrlfd_for_peer != -1)
    frida_raw_close (ctrlfd_for_peer);

  /* Try the pre-created socketpair fd first */
  ctrlfd = ctx->ctrlfds[1];
  if (ctrlfd != -1)
  {
    if (!frida_send_hello (ctrlfd, thread_id, libc))
    {
      frida_raw_close (ctrlfd);
      ctrlfd = -1;
    }
  }
  /* Fall back to abstract Unix socket */
  if (ctrlfd == -1)
  {
    ctrlfd = frida_connect (ctx->fallback_address, libc);
    if (ctrlfd == -1)
      goto beach;

    if (!frida_send_hello (ctrlfd, thread_id, libc))
      goto beach;
  }

  /* Link the agent SO from the selected host transfer path. */
  if (ctx->agent_handle == NULL)
  {
    char recv_diag[32];

    frida_send_debug (ctrlfd, "loader:connected", libc);
    if (stream_agent)
    {
      frida_send_debug (ctrlfd, "loader:waiting-agent-stream", libc);
      frida_send_debug (ctrlfd, "loader:link-agent-begin", libc);
      if (!rustfrida_link_agent (-1, ctrlfd, libc, &agent_module,
        ctx->resolver_module_bases, ctx->resolver_module_count,
        (ElfW(Addr)) ctx->libc_base, (ElfW(Addr)) ctx->linker_base,
        agent_vma_name, catch_entry_signals, true))
        goto dlopen_failed;
    }
    else
    {
      frida_send_debug (ctrlfd, "loader:waiting-agent-fd", libc);
      agent_codefd = frida_receive_fd_diag (ctrlfd, libc, recv_diag);
      if (agent_codefd == -1)
      {
        frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
            recv_diag /* contains diag msg */, libc);
        goto beach;
      }
      frida_send_debug (ctrlfd, "loader:got-agent-fd", libc);

      frida_send_debug (ctrlfd, "loader:link-agent-begin", libc);
      {
        int owned_agent_fd = agent_codefd;
        agent_codefd = -1;
        if (!rustfrida_link_agent (owned_agent_fd, ctrlfd, libc, &agent_module,
          ctx->resolver_module_bases, ctx->resolver_module_count,
          (ElfW(Addr)) ctx->libc_base, (ElfW(Addr)) ctx->linker_base,
          agent_vma_name, catch_entry_signals, false))
          goto dlopen_failed;
      }
    }
    frida_send_debug (ctrlfd, "loader:link-agent-ok", libc);
    frida_send_log (ctrlfd, "worker: agent linked", libc);

    frida_send_debug (ctrlfd, "loader:find-entry", libc);
    ctx->agent_entrypoint_impl = rustfrida_find_export (&agent_module, ctx->agent_entrypoint);
    if (ctx->agent_entrypoint_impl == NULL)
      goto dlsym_failed;
    ctx->agent_current_thread_eval_impl = rustfrida_find_export (&agent_module, ctx->agent_current_thread_eval);
    frida_send_debug (ctrlfd, "loader:find-entry-ok", libc);
    frida_send_log (ctrlfd, "worker: exports resolved", libc);

    ctx->agent_handle = (void *) agent_module.base;
  }

  /* Receive the REPL socketpair fd for the agent, or reuse the loader control
   * socket in pure spawn where no fd passing or remote fd extraction is used. */
  if (agent_ctrl_is_loader)
  {
    frida_send_debug (ctrlfd, "loader:reuse-ctrl-for-agent", libc);
    agent_ctrlfd = ctrlfd;
  }
  else
  {
  frida_send_debug (ctrlfd, "loader:waiting-repl-fd", libc);
  {
    char recv_diag[32];

    agent_ctrlfd = frida_receive_fd_diag (ctrlfd, libc, recv_diag);
    if (agent_ctrlfd == -1)
    {
      frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN, recv_diag, libc);
      goto beach;
    }
  }
  frida_send_debug (ctrlfd, "loader:got-repl-fd", libc);
  frida_send_log (ctrlfd, "worker: repl fd received", libc);
  if (agent_ctrlfd != -1)
    frida_enable_close_on_exec (agent_ctrlfd, libc);
  }

  /* Signal READY and wait for ACK before entering agent */
  frida_send_debug (ctrlfd, "loader:send-ready", libc);
  if (!frida_send_ready (ctrlfd, libc))
  {
    frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
        "frida_send_ready failed", libc);
    goto beach;
  }
  if (!frida_receive_ack (ctrlfd, libc))
  {
    frida_send_error (ctrlfd, FRIDA_MESSAGE_ERROR_DLOPEN,
        "frida_receive_ack failed", libc);
    goto beach;
  }
  if (agent_ctrl_is_loader)
  {
    ctrlfd = -1;
  }
  if (close_loader_ctrl && ctrlfd != -1)
  {
    frida_send_debug (ctrlfd, "loader:close-ctrl", libc);
    frida_raw_close (ctrlfd);
    ctrlfd = -1;
  }
  if (hold_before_entry)
  {
    rustfrida_send_agent_log (agent_ctrlfd, "[loader] hold before agent entry\n", libc);
    frida_sleep_ms (3000);
    rustfrida_send_agent_log (agent_ctrlfd, "[loader] hold done\n", libc);
  }

  rustfrida_start_spawn_cleanup (ctx);

  /* Construct AgentArgs on stack and call hello_entry */
  {
    AgentArgs args;
    hello_entry_fn entry = (hello_entry_fn) ctx->agent_entrypoint_impl;

    args.table      = ctx->string_table_addr;
    args.ctrl_fd    = agent_ctrlfd;
    args.agent_memfd = -1;
    args.resume_flag = ctx->spawn_resume_flag;

    if (catch_entry_signals)
    {
      rustfrida_install_entry_signal_handlers (&agent_module, ctrlfd, agent_ctrlfd, libc);
      frida_send_debug (ctrlfd, "entry-catch:call-entry", libc);
      entry (&args);
    }
    else
    {
      /* hello_entry blocks in the agent command loop */
      rustfrida_send_agent_log (agent_ctrlfd, "[loader] entering agent\n", libc);
      entry (&args);
    }

    rustfrida_send_agent_log (agent_ctrlfd, "[loader] agent returned before command loop\n", libc);

    /* Agent returned — close the REPL fd so the host observes EOF before dlclose. */
    if (agent_ctrlfd != -1)
      frida_raw_close (agent_ctrlfd);
    agent_ctrlfd = -1;
  }

  goto beach;

dlopen_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLOPEN,
        agent_module.error[0] != '\0' ? agent_module.error : "Unable to link library",
        libc);
    goto beach;
  }
dlsym_failed:
  {
    frida_send_error (ctrlfd,
        FRIDA_MESSAGE_ERROR_DLSYM,
        "Unable to find entrypoint",
        libc);
    goto beach;
  }
beach:
  {
    if (agent_module.load_start != 0)
    {
      void * module_handle = (void *) agent_module.base;
      rustfrida_close_module (&agent_module, libc);
      if (ctx->agent_handle == module_handle)
      {
        ctx->agent_handle = NULL;
        ctx->agent_entrypoint_impl = NULL;
        ctx->agent_current_thread_eval_impl = NULL;
      }
    }

    if (agent_ctrlfd != -1)
      frida_raw_close (agent_ctrlfd);

    if (agent_codefd != -1)
      frida_raw_close (agent_codefd);

    if (ctrlfd != -1)
    {
      frida_send_bye (ctrlfd, unload_policy, libc);
      frida_raw_close (ctrlfd);
    }

    return NULL;
  }
}

/* ========== Socket helpers (from Frida's loader.c, verbatim) ========== */

/* TODO: Handle EINTR. */

static int
frida_connect (const char * address, const FridaLibcApi * libc)
{
  bool success = false;
  int sockfd;
  struct sockaddr_un addr;
  size_t len;
  const char * c;
  char ch;

  sockfd = frida_raw_socket (AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd == -1)
    goto beach;

  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  for (c = address, len = 0; (ch = *c) != '\0'; c++, len++)
    addr.sun_path[1 + len] = ch;

  if (frida_raw_connect (sockfd, (struct sockaddr *) &addr, offsetof (struct sockaddr_un, sun_path) + 1 + len) == -1)
    goto beach;

  success = true;

beach:
  if (!success && sockfd != -1)
  {
    frida_raw_close (sockfd);
    sockfd = -1;
  }

  return sockfd;
}

static bool
frida_send_hello (int sockfd, pid_t thread_id, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_HELLO;
  FridaHelloMessage hello = {
    .thread_id = thread_id,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &hello, sizeof (hello), libc);
}

static bool
frida_send_ready (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_READY;

  return frida_send_chunk (sockfd, &type, sizeof (type), libc);
}

static bool
frida_receive_ack (int sockfd, const FridaLibcApi * libc)
{
  FridaMessageType type;

  if (!frida_receive_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return type == FRIDA_MESSAGE_ACK;
}

static bool
frida_send_bye (int sockfd, FridaUnloadPolicy unload_policy, const FridaLibcApi * libc)
{
  FridaMessageType type = FRIDA_MESSAGE_BYE;
  FridaByeMessage bye = {
    .unload_policy = unload_policy,
  };

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;

  return frida_send_chunk (sockfd, &bye, sizeof (bye), libc);
}

static bool
frida_send_debug (int sockfd, const char * message, const FridaLibcApi * libc)
{
  uint16_t length;
  FridaMessageType type = FRIDA_MESSAGE_DEBUG;

  if (!rustfrida_loader_debug_enabled)
    return true;

  if (sockfd == -1 || message == NULL)
    return false;

  length = frida_strlen (message);

  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;
  if (!frida_send_chunk (sockfd, &length, sizeof (length), libc))
    return false;
  return frida_send_chunk (sockfd, message, length, libc);
}

static bool
frida_send_error (int sockfd, FridaMessageType type, const char * message, const FridaLibcApi * libc)
{
  uint16_t length;

  length = frida_strlen (message);

  #define FRIDA_SEND_VALUE(v) \
      if (!frida_send_chunk (sockfd, &(v), sizeof (v), libc)) \
        return false
  #define FRIDA_SEND_BYTES(data, size) \
      if (!frida_send_chunk (sockfd, data, size, libc)) \
        return false

  FRIDA_SEND_VALUE (type);
  FRIDA_SEND_VALUE (length);
  FRIDA_SEND_BYTES (message, length);

  return true;
}

static bool
frida_send_log (int sockfd, const char * message, const FridaLibcApi * libc)
{
  return frida_send_error (sockfd, FRIDA_MESSAGE_LOG, message, libc);
}

static bool
rustfrida_send_agent_log (int sockfd, const char * message, const FridaLibcApi * libc)
{
  uint8_t type = 0x81;
  uint32_t length;

  if (sockfd == -1 || message == NULL)
    return false;

  length = frida_strlen (message);
  if (!frida_send_chunk (sockfd, &type, sizeof (type), libc))
    return false;
  if (!frida_send_chunk (sockfd, &length, sizeof (length), libc))
    return false;
  return frida_send_chunk (sockfd, message, length, libc);
}

static bool
frida_receive_chunk (int sockfd, void * buffer, size_t length, const FridaLibcApi * libc)
{
  void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    struct iovec io = {
      .iov_base = cursor,
      .iov_len = remaining
    };
    struct msghdr msg;
    ssize_t n;

    /*
     * Avoid inline initialization to prevent the compiler attempting to insert
     * a call to memset.
     */
    msg.msg_name = NULL,
    msg.msg_namelen = 0,
    msg.msg_iov = &io,
    msg.msg_iovlen = 1,
    msg.msg_control = NULL,
    msg.msg_controllen = 0,

    n = frida_raw_recvmsg (sockfd, &msg, 0);
    if (n <= 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static int
frida_receive_fd_diag (int sockfd, const FridaLibcApi * libc, char * diag_buf)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg;

  msg.msg_name = NULL,
  msg.msg_namelen = 0,
  msg.msg_iov = &io,
  msg.msg_iovlen = 1,
  msg.msg_control = &control,
  msg.msg_controllen = sizeof (control),

  res = frida_raw_recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
  {
    libc->sprintf (diag_buf, "recvfd:res=%d,ctl=%d,fd=%d",
        res, (int) msg.msg_controllen, sockfd);
    return -1;
  }

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static int
frida_receive_fd (int sockfd, const FridaLibcApi * libc)
{
  int res;
  uint8_t dummy;
  struct iovec io = {
    .iov_base = &dummy,
    .iov_len = sizeof (dummy)
  };
  FridaControlMessage control;
  struct msghdr msg;

  /*
   * Avoid inline initialization to prevent the compiler attempting to insert
   * a call to memset.
   */
  msg.msg_name = NULL,
  msg.msg_namelen = 0,
  msg.msg_iov = &io,
  msg.msg_iovlen = 1,
  msg.msg_control = &control,
  msg.msg_controllen = sizeof (control),

  res = frida_raw_recvmsg (sockfd, &msg, 0);
  if (res == -1 || res == 0 || msg.msg_controllen == 0)
    return -1;

  return *((int *) CMSG_DATA (CMSG_FIRSTHDR (&msg)));
}

static bool
frida_send_chunk (int sockfd, const void * buffer, size_t length, const FridaLibcApi * libc)
{
  const void * cursor = buffer;
  size_t remaining = length;

  while (remaining != 0)
  {
    ssize_t n;

    n = frida_raw_send (sockfd, cursor, remaining, MSG_NOSIGNAL);
    if (n == -1)
      return false;
    if (n == 0)
      return false;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static void
frida_enable_close_on_exec (int fd, const FridaLibcApi * libc)
{
  frida_raw_fcntl (fd, F_SETFD, frida_raw_fcntl (fd, F_GETFD, 0) | FD_CLOEXEC);
}

static size_t
frida_strlen (const char * str)
{
  size_t n = 0;
  const char * cursor;

  for (cursor = str; *cursor != '\0'; cursor++)
  {
    asm ("");
    n++;
  }

  return n;
}

static int
frida_strcmp (const char * a, const char * b)
{
  while (*a != '\0' && *a == *b)
  {
    a++;
    b++;
  }

  return ((unsigned char) *a) - ((unsigned char) *b);
}

static bool
frida_streq (const char * a, const char * b)
{
  while (*a != '\0' && *a == *b)
  {
    a++;
    b++;
  }

  return *a == *b;
}

static bool
frida_str_has_suffix (const char * str, const char * suffix)
{
  size_t str_len = 0;
  size_t suffix_len = frida_strlen (suffix);
  size_t i;

  while (str[str_len] != '\0' && str[str_len] != '\n')
    str_len++;

  if (str_len < suffix_len)
    return false;

  for (i = 0; i != suffix_len; i++)
  {
    if (str[str_len - suffix_len + i] != suffix[i])
      return false;
  }

  return true;
}

static int
frida_strncmp (const char * a, const char * b, size_t n)
{
  while (n != 0 && *a != '\0' && *a == *b)
  {
    a++;
    b++;
    n--;
  }

  if (n == 0)
    return 0;

  return ((unsigned char) *a) - ((unsigned char) *b);
}

static char *
frida_strchr (const char * str, int c)
{
  char needle = (char) c;

  while (*str != '\0')
  {
    if (*str == needle)
      return (char *) str;
    str++;
  }

  return needle == '\0' ? (char *) str : NULL;
}

static char *
frida_strrchr (const char * str, int c)
{
  char needle = (char) c;
  const char * result = NULL;

  do
  {
    if (*str == needle)
      result = str;
  } while (*str++ != '\0');

  return (char *) result;
}

static char *
frida_strstr (const char * haystack, const char * needle)
{
  size_t needle_len = frida_strlen (needle);

  if (needle_len == 0)
    return (char *) haystack;

  for (; *haystack != '\0'; haystack++)
  {
    size_t i;

    for (i = 0; i != needle_len; i++)
    {
      if (haystack[i] == '\0' || haystack[i] != needle[i])
        break;
    }
    if (i == needle_len)
      return (char *) haystack;
  }

  return NULL;
}

static char *
frida_strcpy (char * dst, const char * src)
{
  char * result = dst;

  while ((*dst++ = *src++) != '\0')
  {
  }

  return result;
}

static char *
frida_strncpy (char * dst, const char * src, size_t n)
{
  char * result = dst;

  while (n != 0 && *src != '\0')
  {
    *dst++ = *src++;
    n--;
  }

  while (n != 0)
  {
    *dst++ = '\0';
    n--;
  }

  return result;
}

static void *
frida_memchr (const void * ptr, int c, size_t n)
{
  const uint8_t * cursor = ptr;
  uint8_t needle = (uint8_t) c;

  while (n != 0)
  {
    if (*cursor == needle)
      return (void *) cursor;
    cursor++;
    n--;
  }

  return NULL;
}

static void *
frida_memcpy (void * dst, const void * src, size_t n)
{
  uint8_t * d = dst;
  const uint8_t * s = src;

  while (n != 0)
  {
    *d++ = *s++;
    n--;
  }

  return dst;
}

static void *
frida_memmove (void * dst, const void * src, size_t n)
{
  uint8_t * d = dst;
  const uint8_t * s = src;

  if (d == s || n == 0)
    return dst;

  if (d < s)
  {
    while (n != 0)
    {
      *d++ = *s++;
      n--;
    }
  }
  else
  {
    d += n;
    s += n;
    while (n != 0)
    {
      *--d = *--s;
      n--;
    }
  }

  return dst;
}

static void *
frida_memset (void * dst, int c, size_t n)
{
  uint8_t * d = dst;

  while (n != 0)
  {
    *d++ = (uint8_t) c;
    n--;
  }

  return dst;
}

static int
frida_memcmp (const void * a, const void * b, size_t n)
{
  const uint8_t * pa = a;
  const uint8_t * pb = b;

  while (n != 0)
  {
    if (*pa != *pb)
      return ((int) *pa) - ((int) *pb);
    pa++;
    pb++;
    n--;
  }

  return 0;
}

static pid_t
frida_gettid (void)
{
  return frida_syscall_0 (SYS_gettid);
}
