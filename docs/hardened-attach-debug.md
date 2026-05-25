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

Expected success markers:

- `Loader: agent 加载成功`
- `Agent 已连接`
- `[agent] agent-entry: raw hello sent ...`
- `[agent] agent-entry: stream ready ...`
- `[quickjs] profile=minimal`
- `eval ok source=rf_probe.js out_len=1`
- result `=> 2`

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
