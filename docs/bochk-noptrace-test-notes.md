# BOCHK noptrace pure spawn test notes

This note tracks the current `com.bochk.app.aos` analysis state on the
`noptrace` pure-spawn branch. It is meant as a runbook for the next test round,
not as a general user guide.

## Scope

- Device used so far: Android 14 arm64, ColorOS/OnePlus branch.
- Target package: `com.bochk.app.aos`.
- Binary under test: `rustfrida` built with `--no-default-features --features noptrace`.
- Entry path: `--spawn com.bochk.app.aos --spawn-pure`.
- The host pure-spawn path must not call `inject_via_bootstrapper()`, must not
  rewrite target registers, and must not use ptrace for loader startup.

## Build

```bash
./zymbiote/build.sh
cargo build -p agent --release --no-default-features --features quickjs,noptrace
cargo build -p rust_frida --release --no-default-features --features noptrace
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rf-noptrace
adb shell su -c 'chmod 755 /data/local/tmp/rf-noptrace'
```

`agent` and `rust_frida` features must match. `rust_frida/build.rs` checks the
embedded agent feature stamp and fails the build if the `noptrace` bit is stale.

## Cleanup Before Each Probe

```bash
adb shell su -c 'am force-stop com.bochk.app.aos'
adb shell su -c 'am force-stop org.mozilla.firefox'
adb shell su -c 'am force-stop com.oplus.securitypermission'
adb shell su -c 'logcat -c'
```

After a failed or detected run, also remove old probe logs:

```bash
adb shell su -c 'rm -f /data/local/tmp/bochk_probe_*.log /data/local/tmp/rf-noptrace-bochk'
```

## Probe Command Pattern

Use a short identity-watch window so PID/package mismatches caused by BOCHK
renaming or secondary-process behavior are reported automatically:

```bash
(sleep 10; printf 'exit\n') | adb shell su -c 'RF_BOCHK_AUDIT=bytes-cold2-wx-maponly RF_IDENTITY_WATCH_SECS=4 /data/local/tmp/rf-noptrace --spawn com.bochk.app.aos --spawn-pure --verbose -o /data/local/tmp/bochk_probe.log'
```

Then collect the relevant device-side signal:

```bash
adb logcat -d -t 8000 | rg -i 'bochk|AppStartConfirm|checkAllowStartActivity|firefox|securitypermission|SIGABRT|ANR|ptrace|native-audit'
adb shell su -c 'tail -n 200 /data/local/tmp/bochk_probe.log'
```

Do not use `strace` to prove no ptrace. `strace` itself uses ptrace. For ptrace
proof, use eBPF tracepoints/kprobes or writable tracefs syscall events when the
device SELinux policy allows it.

## `RF_BOCHK_AUDIT` Profiles

These values are mapped in `rust_frida/src/main.rs` and installed pre-resume
through the agent socket:

| Value | Meaning | Current use |
| --- | --- | --- |
| `0`, `false` | No native audit hook | Pure-spawn baseline |
| `runtime` | Initialize native audit runtime only | Checks agent/audit setup without resolving libc |
| `resolve` | Resolve libc symbols | Separates dlsym/dlopen effects from hook effects |
| `read-maps`, `maps-dump` | Read or dump `/proc/self/maps` | Checks whether passive map reads trigger detection |
| `bytes-getpid` | Compare libc `getpid` memory bytes with file bytes, no hook | Code-integrity baseline |
| `bytes-cold2` | Normal inline hook on libc `ether_ntoa_r`, then byte compare | Reproduces normal-hook detection |
| `bytes-cold2-wx-maponly` | WXSHADOW hook on libc `ether_ntoa_r`, then dump libc maps | Checks VMA visibility after WXSHADOW |
| `bytes-cold2-wx-patchonly` | WXSHADOW hook only, no after-read probe | Checks whether the hook itself is enough to trigger |
| `bytes-cold2-wx-fast` | WXSHADOW hook plus async byte read | Avoid for now; this probe caused native crash during testing |
| `prctl`, `open`, `noop`, `cold`, `cold2` variants | Focused hook probes | Use only after the above ladder identifies a clean boundary |

## Findings So Far

- Pure spawn baseline on BOCHK is clean enough to start and connect.
- Passive profiles (`runtime`, `resolve`, `read-maps`, `maps-dump`,
  `bytes-getpid`) did not reproduce the browser/security warning in the last
  round.
- Normal inline hook on libc `ether_ntoa_r` changed in-memory bytes and was
  detected.
- `Hook.WXSHADOW` kept libc VMA layout stable in the observed map dump. libc did
  not split into a suspicious one-page executable mapping after the hook.
- WXSHADOW still triggered BOCHK's detection chain in the last run. The warning
  path involved `com.oplus.securitypermission:ui` and
  `AppStartConfirmDialogActivity`; later BOCHK aborted.
- Tombstone/logcat showed BOCHK executing code in `libbochk_aos.so` while reading
  `/proc/self/maps` with `fgets`. This proves maps scanning exists, but the clean
  passive map profiles mean maps reading alone is probably not the full trigger.
- Logcat `{ ptrace } denied` lines seen during crash collection are likely
  `crash_dump` attempting tombstone collection, not necessarily rustfrida or
  BOCHK watchdog ptrace.

Current working hypothesis: BOCHK is not only checking for a raw ptrace event.
The detection likely combines one or more of these signals:

- inline hook code-integrity mismatch;
- anonymous executable or RWX hook/runtime pools in maps;
- WXSHADOW/kernel page metadata or execution-view mismatch;
- app-local native detector in `libbochk_aos.so` around its early maps/integrity
  checks.

## Suggested Test Order Tonight

Run one profile at a time, cleaning logs and force-stopping the related packages
between runs:

1. `RF_BOCHK_AUDIT=0`
2. `RF_BOCHK_AUDIT=runtime`
3. `RF_BOCHK_AUDIT=resolve`
4. `RF_BOCHK_AUDIT=read-maps`
5. `RF_BOCHK_AUDIT=maps-dump`
6. `RF_BOCHK_AUDIT=bytes-getpid`
7. `RF_BOCHK_AUDIT=bytes-cold2`
8. `RF_BOCHK_AUDIT=bytes-cold2-wx-maponly`
9. `RF_BOCHK_AUDIT=bytes-cold2-wx-patchonly`

Record for each run:

- whether BOCHK reaches its normal UI;
- whether Firefox/browser warning appears;
- whether `com.oplus.securitypermission:ui` starts;
- whether BOCHK aborts or produces a tombstone;
- the first `bochk-native-audit` line before detection;
- any process identity mismatch reported by `RF_IDENTITY_WATCH_SECS`.

## Next Engineering Targets

- Add a passive BOCHK maps-diff probe that records maps before and after hook
  runtime initialization without installing an inline hook.
- Add a non-inline app-local probe path, for example a GOT/PLT or loader-event
  probe, so analysis is not forced through libc inline patching.
- Reduce or hide anonymous executable/RWX hook-runtime artifacts before BOCHK's
  early maps scan.
- Keep `bytes-cold2-wx-fast` disabled until the async read crash is understood.
