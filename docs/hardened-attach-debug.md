# Hardened Attach Debug Notes

Date: 2026-05-25

## Scope

This note records the attach-stability fixes for a hardened arm64 Android app
tested on a rooted device. The notes are intentionally generic: package names,
vendor names, app-specific paths, and test-only binary names are omitted.

The working baseline is late PID attach with a minimal QuickJS surface and a
delayed script load after agent connection:

```sh
RF_REMOTE_CALL_TIMEOUT_MS=7000 \
RF_INJECT_THREAD=main \
RF_LOAD_DELAY_MS=8000 \
/data/local/tmp/rf_test --pid <pid> \
  --verbose --quickjs-profile minimal -l /data/local/tmp/rf_probe.js
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

Automatic script loading immediately after agent connection could overlap with
the app's own security/runtime initialization. Delaying `-l/--load-script`
execution avoided that startup race in the validated run.

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
- Host connection waiting now treats HELLO-before-EOF as a concrete failure
  instead of waiting for the full connection timeout.
- `RF_LOAD_DELAY_MS` delays automatic script execution after agent connection,
  giving hardened startup paths time to settle before running user JavaScript.
- `rust_frida/build.rs` now fails if the embedded `libagent.so` is older than
  `agent` or `quickjs-hook` inputs, preventing stale embedded-agent tests.
- `--quickjs-profile minimal` now exposes only the small diagnostic surface.
  The generic alias `--quickjs-profile hardened` maps to the same profile.

## Validated Result

The delayed minimal-profile path reached the agent, initialized QuickJS, loaded
the probe script, returned `=> 2`, and shut down through the managed cleanup
path without producing a new crash report in the successful run.

Expected success markers:

- `Loader: agent 加载成功`
- `Agent 已连接`
- `[agent] agent-entry: hello sent ...`
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
