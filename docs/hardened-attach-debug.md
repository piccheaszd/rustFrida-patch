# Hardened Attach Debug Notes

Date: 2026-05-25

## Scope

This note records the attach-stability fixes for a hardened arm64 Android app
tested on a rooted device. The notes are intentionally generic: package names,
vendor names, app-specific paths, and test-only binary names are omitted.

The current working baseline is early spawn with probe-based thread selection.
It reaches the agent before the app-specific startup path runs, then loads the
script while the child is still paused:

```sh
RF_REMOTE_CALL_TIMEOUT_MS=7000 \
RF_INJECT_THREAD=probe \
RF_THREAD_PROBE_LIMIT=16 \
RF_THREAD_PROBE_TIMEOUT_MS=150 \
/data/local/tmp/rf_test --spawn <package> --spawn-early \
  --verbose --connect-timeout 25 \
  --quickjs-profile full -l /data/local/tmp/test.js
```

## Findings

The upstream merge was not the root cause. A known-good control app continued
to attach and evaluate a simple script, while the hardened target exposed
timing-sensitive failures around thread selection, ptrace stop state, and early
runtime initialization.

Default thread selection was unsafe in the target process. Worker threads often
stopped in futex or runtime paths where code-swap execution did not reliably
resume into user mode. The most reliable manual baseline was main-thread
injection during an app-driven UI or input-event window.

Immediate full QuickJS initialization touched surfaces that were too broad for
this target at startup. The minimal profile keeps the small evaluation surface
needed for diagnostics and skips optional bootstrap modules until each module
can be re-enabled and tested independently.

Late attach and `--spawn-late` are still unstable on the hardened target. The
observed failures happen before user JavaScript can run: main-thread injection
can hit an EOF while restoring the code-swap area, and probe-selected injection
can reset during the loader fd handoff. No new crash report was produced in
these failing runs, which points to target-side restart/self-protection rather
than a normal native crash.

Early spawn is the usable path. `--spawn-early` with `RF_INJECT_THREAD=probe`
loaded the agent, initialized QuickJS, ran the probe script, resumed the child,
and cleaned up without a new crash report. The same path also supports the full
QuickJS profile for targeted API tests.

`Hook.WXSHADOW` works for individual startup hooks, but it has two operational
limits:

- Multiple `WXSHADOW` hooks on the same 4 KB page are unsupported. The engine
  now rejects this case immediately instead of hanging the target.
- During early startup, combining a `WXSHADOW` `android_dlopen_ext` hook and a
  `WXSHADOW` `RegisterNatives` hook in the same run can stop progress inside the
  first app-owned loader library: dlopen enter is logged, but no matching leave
  is observed. Running either hook alone is stable. Use separate runs for loader
  tracing and JNI-registration tracing, or switch one side to a non-WXSHADOW
  backend after validating it on the target.

## Fixes Recorded

- `RF_INJECT_THREAD=probe|auto` now samples candidate threads with
  `PTRACE_SEIZE + PTRACE_INTERRUPT`, captures PC/LR/SP, syscall, `wchan`, and
  mapping context, then scores candidates instead of relying only on thread
  names.
- Remote-call cleanup now restores original general-purpose and floating-point
  registers on timeout, `PTRACE_CONT` failure, wait failure, abnormal stop, and
  retry exhaustion.
- The agent sends an early HELLO before reading injected configuration or
  processing command-line state, making early agent-entry failures visible to
  the host.
- Agent entry now writes the initial HELLO and stage logs directly to the raw
  control fd before constructing the Rust `UnixStream`, so clone/global-stream
  setup failures are distinguishable from agent load failures.
- Host connection waiting now treats HELLO-before-EOF as a concrete failure
  instead of waiting for the full connection timeout.
- `RF_LOAD_DELAY_MS` delays automatic script execution after agent connection,
  giving hardened startup paths time to settle before running user JavaScript.
- `rust_frida/build.rs` now fails if the embedded `libagent.so` is older than
  `agent` or `quickjs-hook` inputs, preventing stale embedded-agent tests.
- `rust_frida/build.rs` also fails if the embedded loader blobs are older than
  `loader/helpers` or `loader/build_helpers.py`, preventing stale loader
  protocol tests.
- `--quickjs-profile minimal` now exposes only the small diagnostic surface.
  The generic alias `--quickjs-profile hardened` maps to the same profile.
- QuickJS exposes the Frida-compatible `NativePointer` global alias in addition
  to `ptr()`.
- `WXSHADOW` same-page multi-hook attempts now return an explicit hook error:
  use `Hook.RECOMP`, `Hook.NORMAL`, or only one `WXSHADOW` hook per page.

## Validated Result

The early-spawn minimal-profile path reached the agent, initialized QuickJS,
loaded the probe script, returned `=> 2`, resumed the child, and shut down
through the managed cleanup path without producing a new crash report.

The early-spawn full-profile path loaded a `Hook.WXSHADOW` `RegisterNatives`
script and captured the system connectivity JNI registration table without a new
crash report.

A loader-only `android_dlopen_ext` `WXSHADOW` trace completed 41 enter/leave
pairs in the startup window after the same-page guard rejected the second
same-page dlopen hook with a clear JavaScript error.

An early proc-surface trace harness was added for low-noise startup tracing:

```sh
RF_REMOTE_CALL_TIMEOUT_MS=30000 \
RF_INJECT_THREAD=probe \
RF_THREAD_PROBE_LIMIT=16 \
RF_THREAD_PROBE_TIMEOUT_MS=150 \
/data/local/tmp/rf_test --spawn <package> --spawn-early \
  --verbose --connect-timeout 25 \
  --quickjs-profile full -l /data/local/tmp/early_trace_proc.js
```

The minimal proc trace successfully installed `WXSHADOW` hooks for `prctl`,
`readlink`, `openat`, `fopen`, `ptrace`, `abort`, and `exit`, then resumed the
child and shut down cleanly with no new crash report. It confirmed the startup
probe sequence previously inferred from static analysis:

- repeated `/proc/self/cmdline` reads during very early runtime setup;
- repeated `/proc/self/fd/<n>` `readlink` probes;
- repeated `/proc/self/maps` reads;
- `PR_GET_DUMPABLE` followed by `PR_SET_DUMPABLE(1)`, then another
  `/proc/self/fd/<n>` `readlink`;
- `/proc/<pid>/cmdline`, `/proc/<pid>/status`, and
  `/proc/self/task/<tid>/status` scans across process threads.

The proc trace also confirmed a harness limitation: JS-level global `syscall`
hooks are too broad for this target during startup. A broad `syscall` hook
triggered on runtime worker threads and produced a trace-harness crash before
the target-specific startup checks could be observed. The reusable full harness
therefore keeps syscall tracing disabled by default; use exported libc calls or
a native/CModule filter for syscall-level tracing.

The captured LR values line up with the static loader-library call sites. In
the validated run, the loader library was mapped at a page-aligned base and the
observed return addresses mapped back to these offsets:

- `PR_SET_DUMPABLE(1)`: return offset `+0x8c984`, call site `+0x8c980`;
- `readlink("/proc/self/fd/<n>")`: return offset `+0x8c99c`, call site
  `+0x8c998`;
- `PR_GET_DUMPABLE`: return offset `+0x8ca0c`, call site `+0x8ca08`;
- `openat("/proc/self/task/<tid>/status")`: return offset `+0x67d84`, call
  site `+0x67d80`.

Expected success markers:

- `Loader: agent 加载成功`
- `Agent 已连接`
- `[agent] agent-entry: raw hello sent ...`
- `[agent] agent-entry: stream ready ...`
- `[quickjs] profile=minimal`
- `eval ok source=rf_probe.js out_len=1`
- result `=> 2`

## 2026-05-25 Loader/Attach Fixes

The loader-side fd/VMA exposure found by the proc trace has been reduced:

- removed the bootstrapper `PR_SET_VMA_ANON_NAME` label for the temporary loader
  allocation;
- removed the loader worker `PR_SET_NAME` label so `/proc/self/task/*/status`
  does not expose a framework-specific thread name;
- removed the loader's `/proc/self/fd/<agent-fd>` `readlink` step and the
  derived VMA naming path;
- changed agent ELF loading from file-backed memfd `PT_LOAD` mappings to an
  anonymous staging buffer plus anonymous LOAD pages, then restored final segment
  protections after relocation;
- kept RELRO protection after final LOAD protection to preserve read-only
  relocation behavior.

The policy patcher now also supports `$self` as a source type and grants the
current injector domain process-signal permissions toward app domains. This is
needed for late/PID attach because `PTRACE_ATTACH` depends on a stop signal being
deliverable to the selected thread.

Validation after the change:

- `--spawn-early` with `/data/local/tmp/test.js` and `Hook.WXSHADOW` still reaches
  `Agent 已连接`, evaluates the script, applies the WXSHADOW patch, resumes the
  child, and shuts down without a new tombstone.
- PID attach can now pass the former stop-wait failure on a fresh process and
  complete bootstrapper phase 1/2.
- `--spawn-late` can now pass attach, bootstrapper phase 1/2, and loader write.
  The remaining observed failure is target process exit during or immediately
  after loader execution, without a new tombstone. This points to late/PID
  anti-debug handling rather than the prior fd/VMA linker crash.

## 2026-05-25 Agent Entry Fixes

The late path was further narrowed from loader/linker failure to post-HELLO
target exit:

- agent entry now avoids libc `fcntl()` for `UnixStream::try_clone()` and
  duplicates the control fd with a raw `fcntl` syscall;
- agent Rust allocations now use a raw anonymous `mmap` allocator, avoiding the
  injected-process libc allocator during early entry;
- agent frame writes and command-loop reads use raw `write`/`read` syscalls for
  the control socket;
- the raw command-loop reader now retries `EINTR` and waits/retries on
  `EAGAIN`, matching blocking socket semantics;
- host HELLO handling now registers the command sender and marks the session
  connected synchronously before spawning the tx thread, removing the previous
  "HELLO logged but wait timed out" race;
- host diagnostics now distinguish true connection timeout from "connected then
  immediately disconnected".

Validation after these fixes:

- `--spawn-late` reaches the agent command loop. The last agent marker is
  `31 command-loop-read`; the agent does not emit the normal command-loop EOF
  or exit markers. The host then receives socket EOF and the target process
  exits without a fresh tombstone, consistent with post-resume target-side
  termination/self-protection rather than an agent-managed shutdown path.
- `--spawn-early` with the existing `RegisterNatives` `Hook.WXSHADOW` test
  script still reaches `Agent 已连接`, initializes QuickJS, applies the
  `WXSHADOW` patch, captures JNI registration output, resumes the child, and
  shuts down through the managed cleanup path.

## 2026-05-25 Early Trace for Late Detection Points

Added `tools/late_detection_trace.js` as a reusable `--spawn-early` trace
harness for late/PID attach failure analysis. It installs `WXSHADOW` hooks for
`readlink`, `readlinkat`, `openat`, `fopen`, `ptrace`, `kill`, `shutdown`,
`abort`, `exit`, and loader calls, while using a normal hook for `prctl` to
avoid same-page conflicts. It also records `readlink` targets and resolves LR
values to module-relative offsets.

Generic validation command:

```sh
RF_REMOTE_CALL_TIMEOUT_MS=7000 \
RF_INJECT_THREAD=probe \
RF_THREAD_PROBE_LIMIT=16 \
RF_THREAD_PROBE_TIMEOUT_MS=150 \
RF_AGENT_VMA_NAME=agent \
/data/local/tmp/rf_test --spawn <package> --spawn-early --verbose \
  --connect-timeout 25 --quickjs-profile full \
  -l /data/local/tmp/late_detection_trace.js
```

Second validation run:

- `--spawn-early` loaded the trace harness, resumed the child, then shut down
  cleanly through managed cleanup.
- Captured event volume: `readlink` 116 enters, `readlinkat` 115 enters,
  `openat` 30 enters, `fopen` 27 enters, and `prctl` 39 enters.
- No target-side `kill`, `tgkill`, `abort`, `exit`, or `_exit` call was observed
  in the trace window.
- The loader-library base for that run was `0x77c2e20000`; the absolute base is
  ASLR-dependent, so use the offsets below for correlation.

Stable loader-library probe offsets from the trace:

- `+0x48e6c`: `fopen("/proc/<pid>/cmdline")`
- `+0x53cd0`: `fopen()` on runtime ELF paths such as ART/libc
- `+0x55e98`: `fopen("/proc/self/maps")`
- `+0x646a4`: `fopen("/proc/<pid>/status")`
- `+0x67c6c`: close after thread-status scan
- `+0x67d84`: `openat("/proc/self/task/<tid>/status")`
- `+0x682e4`: full `/proc/self/fd/<n>` `readlink` sweep
- `+0x6a0f4`: later `fopen("/proc/self/maps")`
- `+0x767c8`: early repeated `fopen("/proc/self/maps")`
- `+0x8c984`: `PR_SET_DUMPABLE(1)`
- `+0x8c99c`: targeted `/proc/self/fd/<n>` `readlink`
- `+0x8ca0c`: `PR_GET_DUMPABLE`
- `+0x8f308`: later `fopen("/proc/<pid>/cmdline")`

Important late/PID attach relevance:

- The `+0x682e4` fd sweep reached the injected control socket descriptors; in
  this run the loader had reported control fds `[74, 75]`, and the trace later
  showed `/proc/self/fd/74` and `/proc/self/fd/75` resolving to socket inodes.
- The same sweep also saw other high fds, including an app fd directory and an
  ashmem mapping. This confirms that fd/VMA hiding must cover high-numbered
  descriptors, not only the memfd used for agent delivery.
- The trace does not prove the final termination branch yet. It proves the
  observable inputs that can distinguish early from late/PID attach: procfs fd
  enumeration, thread-status enumeration, maps reads, and dumpable toggling.
  Next fixes should either hide these artifacts or move late attach so these
  checks do not observe framework-owned fds/threads.

## 2026-05-25 Control FD and Stream Transfer Fixes

The previous fd/VMA fixes removed file-backed LOAD mappings and visible VMA
names, but late attach still exposed one short-lived agent memfd fd during the
loader transfer window. The loader then copied from that fd into an anonymous
buffer, so the mapping was clean but `/proc/self/fd` could still see the
transfer fd before it was closed.

Additional hardening:

- agent communication now uses one target-side control fd instead of duplicating
  it for reader/writer split;
- the loader control fd is closed by default before entering agent code
  (`RF_KEEP_LOADER_CTRL=1` keeps the old behavior, `RF_CLOSE_LOADER_CTRL`
  overrides explicitly);
- the agent ELF is now sent over the loader control socket by default instead
  of passing an agent memfd with `SCM_RIGHTS`;
- the old memfd transfer path is retained only for diagnostics and compatibility
  via `RF_STREAM_AGENT=0`, `RF_AGENT_MEMFD=1`, or
  `RF_AGENT_TRANSFER=memfd`;
- the streamed agent path still reads into an anonymous buffer, maps anonymous
  LOAD pages, restores final segment protections, and keeps RELRO protection.

Validation:

- default stream-agent `--spawn-early --quickjs-profile minimal` completed
  `link:recv-stream-size`, `link:recv-stream`, ELF validation, anonymous segment
  mapping, relocation, entry, and agent command-loop startup.
- default stream-agent `--spawn-late --quickjs-profile minimal` reached
  `Loader: agent 加载成功`, `Agent 已连接`, and agent command-loop startup, then
  shut down normally from host-side input EOF.
- The old memfd path was observed to still fail in hardened late attach at the
  loader `link:read-file` window, so stream-agent is the default transfer mode.

Remaining PID-attach-specific observations:

- Attaching to a fully running process can still fail before loader execution if
  all sampled threads are in `get_signal` and the selected thread never reaches
  the expected SIGSTOP wait state.
- After bringing the process foreground, PID attach can pass thread probing and
  bootstrapper phase 1/2, but one run saw the target restart during the host
  resolver-table write before loader execution. This is separate from the agent
  transfer fd issue proven by the successful `--spawn-late` stream run.

## Remaining Work

1. Improve automatic thread probing so it can find a usable user-mode transition
   without manual input-event timing.
2. Convert the fixed load delay into a readiness probe if unattended startup
   attach needs to be deterministic.
3. Re-enable skipped QuickJS modules one at a time and keep the minimal profile
   as the fallback baseline.
4. Evaluate a remote trampoline strategy that starts from a thread already
   returning from native code instead of arbitrary signal-path stops.
5. Add a safe startup tracing recipe that avoids combining loader and
   JNI-registration `WXSHADOW` hooks in the same early-start run.
6. Keep the explicit memfd fallback for regression tests, but do not use it for
   hardened late/spawn-late profiles unless debugging loader transfer behavior.
7. Continue PID attach hardening around stop-state selection and target restarts
   during host-side memory writes.
