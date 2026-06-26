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

## Current Status (2026-06-26)

Confirmed fixed or reduced:

- Pure spawn works on BOCHK without host ptrace attach, target register rewrite,
  or target-side remote call. The minimal QuickJS path reached `jsinit =>
  initialized` and `jseval 1+1 => 2`.
- Zygote patch restoration completes on exit. Unmatched children use the
  restore-only stage-1 path instead of hook-slot-only fallback.
- Stage-1 temporary strings and pointer tables are scrubbed after the agent
  reads them. The main BOCHK process releases the stage-1 RW tail after resume
  cleanup.
- BOCHK self-trace or spoof children are reported by the identity watcher. If a
  small inherited anonymous RW tail still contains stage-1 signatures, the host
  scrubs it through `/proc/<pid>/mem`.
- Direct memory scans over the stage-1 RX, stage-1 tail, and linker veneer did
  not find the previously visible `frida`, `quickjs`, `rustfrida-loader`,
  `stage1`, or related loader strings.
- No `rwxp` VMA was observed in the latest pure-spawn + minimal QuickJS
  baseline run.
- The stage-1 loader now registers the stage-1 RX and linker veneer exact ranges
  with `kpm-hide-maps` 1.1.2 through `PR_HIDEMAPS_REGISTER` before entering the
  agent. The KPM filters matching `/proc/<pid>/maps` lines for the current `mm`,
  dynamically calibrates `vm_area_struct.vm_mm` on first range hit, and
  propagates those ranges across `dup_mmap` forks.
- BOCHK device retest confirmed the range path: both loader registrations
  returned OK, and an external `/proc/<pid>/maps` read of the main process showed
  only `[vdso]` in the anonymous executable list. The previous stage-1 RX and
  linker veneer anonymous `r-xp` entries were filtered.

Still open:

- The underlying anonymous executable mappings still exist in memory. Attempts
  to fully `munmap`, `mprotect`, or zero the RX mapping caused BOCHK to exit or
  crash, so the current stable path keeps them mapped and hides procfs output
  instead.
- The range filter is device-verified through procfs, but BOCHK's full internal
  decision path still needs per-profile validation, especially when native hooks
  are enabled.
- The BOCHK main process can still show `TracerPid` pointing at BOCHK's own
  self-trace child. RF is no longer the tracer, but app-local detection can still
  treat "being traced" as a signal.
- A self-trace child can retain the anonymous RW VMA shape after host-side
  scrubbing. The signatures are gone, but the map shape itself is not removed.
- KPM hide-maps / recompile / wxshadow coverage is device and kernel specific.
  Target process visibility must be measured through the exact BOCHK read path.
- WXSHADOW hook profiles are not clean on BOCHK yet. `bytes-cold2-wx-maponly`
  and `bytes-cold2-wx-patchonly` both triggered the same
  `AppStartConfirmDialogActivity` path, so this is not just an after-hook maps
  probe artifact.
- RECOMP hook profiles still need per-hook validation. A clean pure-spawn REPL
  does not prove that BOCHK accepts every native hook backend.

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

- Pure spawn baseline on BOCHK is clean enough to start and connect, initialize
  QuickJS, and run a trivial eval.
- The latest pure-spawn baseline run did not expose `rwxp` memory and did not
  retain the old stage-1 string signatures in the scanned stage-1
  RX/tail/veneer ranges.
- The main process releases the stage-1 RW tail. BOCHK self-trace children can
  inherit a tail-shaped anonymous RW VMA, but identity-watch scrubbing removes
  the recognizable signatures.
- Anonymous `r-xp` stage-1 RX and linker veneer mappings remain in memory by
  design for now. Removing or blanking the RX mapping was unstable on BOCHK.
- `kpm-hide-maps` 1.1.2 hides those two mappings from procfs maps output after
  RF registers the exact ranges. This was verified on the BOCHK device: the main
  process anonymous executable maps list no longer exposed stage-1 RX or veneer.
- Passive profiles (`runtime`, `resolve`, `read-maps`, `maps-dump`,
  `bytes-getpid`) did not reproduce the browser/security warning in the last
  round, but they did introduce one anonymous `rwxp` VMA because native audit
  initialized the hook runtime before doing passive work. Current source now
  defers hook-runtime initialization for these profiles. The 2026-06-26 safe
  retest confirmed external maps signal counts of zero for `rwxp`, RF tokens,
  and anonymous executable mappings across `0`, `runtime`, `resolve`,
  `read-maps`, `maps-dump`, and `bytes-getpid`; the `runtime` log reported
  `hook-runtime=deferred`.
- The 2026-06-26 safe retest was run after a phone reboot with KPM modules not
  loaded. Loader logs showed `anti-detect:register-profile-failed` and
  `hide-maps:register-stage1-failed`, so that run verifies the native audit
  fix only. It does not replace a KPM-enabled full stealth pass.
- Normal inline hook on libc `ether_ntoa_r` changed in-memory bytes and was
  detected.
- `Hook.WXSHADOW` kept libc bytes stable in the observed probe, but still
  triggered BOCHK's detection chain. Both `bytes-cold2-wx-maponly` and
  `bytes-cold2-wx-patchonly` launched `com.oplus.securitypermission:ui` /
  `AppStartConfirmDialogActivity`; the `maponly` run later produced a BOCHK ANR.
- Tombstone/logcat showed BOCHK executing code in `libbochk_aos.so` while reading
  `/proc/self/maps` with `fgets`. This proves maps scanning exists, but the clean
  passive map profiles mean maps reading alone is probably not the full trigger.
- Logcat `{ ptrace } denied` lines seen during crash collection are likely
  `crash_dump` attempting tombstone collection, not necessarily rustfrida or
  BOCHK watchdog ptrace.

Current working hypothesis: BOCHK is not only checking for a raw ptrace event.
The detection likely combines one or more of these signals:

- inline hook code-integrity mismatch;
- anonymous executable hook/runtime pools in maps;
- WXSHADOW/kernel page metadata or execution-view mismatch;
- app-local native detector in `libbochk_aos.so` around its early maps/integrity
  checks.

## Executed Matrix (2026-06-26)

Each profile was run with `RF_ANTIDETECT=1`, `RF_LOADER_DEBUG=1`,
`RF_IDENTITY_WATCH_SECS=4`, `--spawn com.bochk.app.aos --spawn-pure`, and
`--quickjs-profile minimal`. Each run force-stopped BOCHK, Firefox, and
`com.oplus.securitypermission` before launch.

| Profile | Hook / action | Result |
| --- | --- | --- |
| `0` | pure-spawn baseline | Clean: no `rwxp`, no RF map tokens, no security dialog. |
| `runtime` | passive audit probe only | Previous run: no dialog, but one anonymous `rwxp` VMA appeared. Source now defers hook runtime; safe retest was clean. |
| `resolve` | resolve libc symbols | Previous run: no dialog; same anonymous `rwxp`. Source now defers hook runtime; safe retest was clean. |
| `read-maps` | read `/proc/self/maps` | Previous run: no dialog; same anonymous `rwxp`. Source now defers hook runtime; safe retest was clean. |
| `maps-dump` | dump suspicious map lines | Previous run: no dialog; dump showed ART JIT memfds and native audit `rwxp`. Source now defers hook runtime; safe retest no longer exposed native-audit `rwxp`. |
| `bytes-getpid` | compare `libc!getpid` bytes, no hook | No dialog; memory bytes unchanged. |
| `bytes-cold2` | normal inline hook on `libc!ether_ntoa_r` | Detected: entry bytes changed, `AppStartConfirmDialogActivity` launched, BOCHK ANR. |
| `bytes-cold2-wx-maponly` | WXSHADOW hook + maps observation | Detected: `AppStartConfirmDialogActivity` launched, BOCHK ANR. |
| `bytes-cold2-wx-patchonly` | WXSHADOW hook only | Detected: `checkAllowStartActivity` and `AppStartConfirmDialogActivity` launched. |

## Safe Retest After Native-Audit Deferral (2026-06-26)

This retest used direct WSL `adb` through mirrored networking and
`/data/local/tmp/rf-noptrace` rebuilt from the current tree. To avoid the
previous phone hang, it did not pull full `/proc/<pid>/maps`; each run used
device-side timeout-bounded greps for `rwxp`, RF tokens, and anonymous
executable mappings.

| Profile | External maps signal | UI/security signal | Agent signal |
| --- | --- | --- | --- |
| `0` | `rwxp=0`, RF token=0, anonymous executable=0 | none | connected |
| `runtime` | `rwxp=0`, RF token=0, anonymous executable=0 | none | `hook-runtime=deferred` |
| `resolve` | `rwxp=0`, RF token=0, anonymous executable=0 | none | libc symbols resolved |
| `read-maps` | `rwxp=0`, RF token=0, anonymous executable=0 | none | read first `/proc/self/maps` line |
| `maps-dump` | `rwxp=0`, RF token=0, anonymous executable=0 | none | target self-dump showed ART JIT memfds, two anonymous `r-xp` lines, and one system `/system/lib64/libstagefright.so` `rwxp`; no native-audit anonymous `rwxp` |
| `bytes-getpid` | `rwxp=0`, RF token=0, anonymous executable=0 | none | libc `getpid` memory bytes matched disk before/after |

Limitations: KPM modules were not loaded after the phone reboot. Loader logs
showed `anti-detect:register-profile-failed` and
`hide-maps:register-stage1-failed`, so this confirms the passive native-audit
`rwxp` fix but not the full KPM-hidden BOCHK profile.

## KPM-Enabled Retest Freeze (2026-06-26)

After reloading `anti-detect` 1.2.23 and `kpm-hide-maps` 1.1.2 at runtime,
BOCHK baseline reached agent connection and registered both KPM surfaces:
`anti-detect:register-profile-ok`,
`hide-maps:register-stage1-ok`, and `hide-maps:register-veneer-ok`.

The next `runtime` passive profile confirmed
`hook-runtime=deferred`, then stopped after:

```text
[stage1] released RW tail: base=...; RX remains mapped
```

The host never reached the usual post-resume messages (`spawn 已恢复`,
unmatched-child restore logs, or identity watcher startup), and subsequent
host-side `adb shell pidof` also hung until the phone was rebooted. This points
at a kernel/procfs interaction during early process resume rather than the
passive native-audit runtime itself.

Important caveat: the external maps probe used in that aborted run had a shell
quoting bug around `grep -E 'a|b|c'` through `su -c`; the reported baseline
token and anonymous executable counts from that run are invalid.

Mitigation in current source: `anti-detect` 1.2.24 no longer expands
`AD_F_AUDIT_ONLY` into all feature bits. `RF_ANTIDETECT=1` now registers only a
lightweight per-mm profile; full audit requires explicit
`RF_ANTIDETECT=audit-full` or `RF_ANTIDETECT_FLAGS=0x1ff`.

The host also supports `RF_SKIP_REPL_READY=1` for KPM regression runs. This
skips the post-resume `/proc/<pid>/task/<pid>/status` and `wchan` polling that
normally waits for the Android main thread to become idle. Use it for BOCHK
KPM retests until the procfs interaction is isolated.

## KPM-Enabled Retest After Mitigation (2026-06-26)

Retest configuration:

```text
anti-detect=1.2.24
kpm-hide-maps=1.1.2
RF_ANTIDETECT=1
RF_SKIP_REPL_READY=1
RF_IDENTITY_WATCH_SECS=0
RF_LOADER_DEBUG=1
--spawn com.bochk.app.aos --spawn-pure --quickjs-profile minimal
```

Result:

| Profile | Result |
| --- | --- |
| `0` with only `anti-detect` 1.2.24 and boot `kpm-hide-maps` 1.0.1 | Clean baseline; `anti-detect:register-profile-ok`; profile flags stayed `0x1`; `hide-maps` range registration failed as expected because 1.0.1 has no range ABI. |
| `0` with `anti-detect` 1.2.24 and `kpm-hide-maps` 1.1.2 | Clean baseline; `hide-maps:register-stage1-ok`; `hide-maps:register-veneer-ok`; `RF_SKIP_REPL_READY=1`; reached `spawn 已恢复`; device stayed responsive. |
| `runtime` | Clean; `hook-runtime=deferred`; reached `spawn 已恢复`; device stayed responsive. |
| `resolve` | Clean; resolved libc `prctl` / `open` / `openat` / `getpid` / `memmem` / `ether_ntoa_r`; device stayed responsive. |
| `read-maps` | Clean; target read `/proc/self/maps` first line; device stayed responsive. |
| `maps-dump` | Clean; self maps dump showed ART JIT memfds and system `/system/lib64/libstagefright.so` `rwxp`; no RF/stage1/veneer lines were emitted. |
| `bytes-getpid` | Clean; `libc!getpid` bytes before/after matched; no hook installed. |

Kernel log evidence:

- `anti-detect` registered only `flags=0x1`; `exit_mmap` counters remained
  zero for path/link/dir/tracerpid/ptrace/dumpable/exit/kill.
- `kpm-hide-maps` registered two exact ranges per run, covering stage-1 RX and
  linker veneer, then removed both ranges on `exit_mmap`.
- The first range match calibrated `vm_area_struct.vm_mm` offset from `0x40`
  to `0x10` on this boot.

The previous KPM-enabled freeze is not reproduced under this mitigated profile.
Do not treat this as proof that full audit (`RF_ANTIDETECT=audit-full` or
`flags=0x1ff`) is safe for BOCHK.

## Focused 0x181 Retest And Fix (2026-06-26)

Additional KPM-enabled checks used `anti-detect` 1.2.24,
`kpm-hide-maps` 1.1.2, `RF_ANTIDETECT=1`, `RF_SKIP_REPL_READY=1`, and
`--spawn com.bochk.app.aos --spawn-pure --quickjs-profile minimal`.

Observed:

- External host-side full read of `/proc/<pid>/maps` succeeded with 299205
  bytes. The only executable oddities were system
  `/system/lib64/libstagefright.so` `rwxp` and `[vdso]`; no RF, stage-1, veneer,
  `rustfrida`, `wxshadow`, or `recompile` token was present.
- Baseline without `RF_SKIP_REPL_READY` passed.
- `runtime` without `RF_SKIP_REPL_READY` passed.
- Baseline with `RF_IDENTITY_WATCH_SECS=3` passed and scrubbed one inherited
  stage-1 tail region in the BOCHK self-trace child.
- Split feature audit passed for `RF_ANTIDETECT_FLAGS=0x11`
  (`AD_F_AUDIT_ONLY | AD_F_FILTER_STATUS`) and `0x61`
  (`AD_F_AUDIT_ONLY | AD_F_GUARD_PTRACE | AD_F_GUARD_DUMPABLE`).
- `RF_ANTIDETECT_FLAGS=0x181`
  (`AD_F_AUDIT_ONLY | AD_F_BLOCK_SELF_EXIT | AD_F_BLOCK_SELF_KILL`) reached
  `spawn 已恢复`, then the host command timed out and adb later reported the
  device as offline. The following `0x0f` path/link/dir run did not execute and
  is not valid evidence.

The 0x181-specific code path was exit/kill syscall auditing. In 1.2.24,
audit-only still called the active self-protect classifiers before returning.
Those classifiers resolved the caller module by walking `current->mm` VMAs and
calling `d_path()` from the exit/kill syscall hook path. That is the only new
heavy kernel path introduced by 0x181 after the successful 0x11 and 0x61 runs.

`anti-detect` 1.2.25 fixes this directly:

- exit audit-only counts only simple exit status classes;
- kill audit-only counts only simple fatal signal classes;
- caller VMA/path classification is reserved for active blocking mode;
- BOCHK UID checks are ordered before caller path lookup in active mode, so even
  non-audit BOCHK-specific self-protect checks avoid unnecessary `find_vma()` /
  `d_path()` work.

Retest after reloading `anti-detect` 1.2.25:

- With the boot `kpm-hide-maps` still lacking the range ABI, `0x181` completed
  with RF `rc=0`; adb returned `alive-after-181`; `anti-detect` logged
  `flags=0x181` and later released the profile with `exit=60 kill=1`.
- After reloading current `kpm-hide-maps` 1.1.2, the same `0x181` run completed
  with RF `rc=0`; adb returned `alive-after-181-fullkpm`; `hide-maps` registered
  both stage-1 and veneer ranges and removed both on `exit_mmap`;
  `anti-detect` released `flags=0x181` with `exit=3 kill=1`.
- No `com.oplus.securitypermission:ui` or Firefox warning process remained
  after the full-KPM run. The RF socket did see `EOF after HELLO`, so BOCHK's
  target process lifecycle still needs separate identity/liveness investigation,
  but the previous adb-offline kernel hang was not reproduced.

Active blocking mode caveat: active exit/kill handling still uses caller
VMA/path resolution for generic loader-token based decisions. BOCHK-specific
checks now avoid that path when the BOCHK UID/name is recognized, but generic
active blocking remains higher risk than audit-only and should be tested
separately from 0x181 audit.

Active `0x180` retest:

- `RF_ANTIDETECT_FLAGS=0x180`
  (`AD_F_BLOCK_SELF_EXIT | AD_F_BLOCK_SELF_KILL`, no audit bit) completed with
  RF `rc=0`; adb returned `alive-after-active180`; no BOCHK, BOCHK helper,
  `com.oplus.securitypermission:ui`, or Firefox process remained after the run.
- Loader logs showed `anti-detect:register-profile-ok`,
  `hide-maps:register-stage1-ok`, and `hide-maps:register-veneer-ok`.
- KPM logs proved the active branch executed:
  `bypass self-protect exit nr=93 status=0 comm=e.process.gapps ... reason=4`.
- The same run still ended in `exit_mmap` with profile counters
  `flags=0x180 ... exit=1 kill=0`, and `kpm-hide-maps` removed both registered
  ranges. RF saw `socket EOF after HELLO` / `Broken pipe`, so active exit
  blocking did not preserve BOCHK process liveness in this scenario.
- No adb-offline or kernel hang occurred. This validates the 1.2.25 BOCHK
  active fast path for this run, but generic active caller-path classification
  should still be tested separately before enabling it broadly.

Minimal real inline hook retest:

- `RF_BOCHK_AUDIT=bytes-noop` installed a normal inline hook on `libc!getpid`
  with a silent callback. This is the smallest existing real native hook
  profile and does not target BOCHK business code.
- The hook did install: `libc!getpid` memory changed from
  `5f2403d548d03bd5...` to `c5b4f41748d03bd5...`, and the agent logged
  `bytes hooked libc!getpid ... mode=normal`.
- The process reached `spawn 已恢复` and released the stage-1 RW tail, then the
  RF host never processed the scheduled `exit` input. The host-side timeout
  fired with `rc=124`; the follow-up adb probe returned `error: closed`.
- This reproduces the device-freeze class with a trivial real inline hook.
  Normal inline hook is therefore not a stable BOCHK debugging mode, independent
  of which libc symbol is selected.

Invalid RECOMP attempt after reboot:

- A first attempt to run `RF_BOCHK_AUDIT=bytes-noop-recomp` was invalid. The
  agent log showed `RF_BOCHK_AUDIT ... (nativeaudit bochk)` and
  `hook runtime initialized profile=all`, then installed normal inline hooks on
  `libc!prctl`, `libc!open`, and `libc!openat`.
- Root cause: host-side `RF_BOCHK_AUDIT` mapping did not include
  `bytes-noop-recomp`; unknown values fell back to `nativeaudit bochk`, the
  broad normal-inline profile. This re-entered the already unsafe hook class and
  does not prove anything about RECOMP.
- Fix: map `bytes-noop-recomp` to `nativeaudit bochk-bytes-noop-recomp` and make
  unknown `RF_BOCHK_AUDIT` values skip native audit instead of defaulting to
  `bochk/all`.

Validated minimal RECOMP attempt:

- Run: `/tmp/rf_boc_verify_bytes_noop_recomp_20260626_174013`.
- Profile mapped correctly to `nativeaudit bochk-bytes-noop-recomp`.
- Agent log:
  - `hook runtime initialized profile=bytes-noop-recomp`
  - `bytes symbol=libc!getpid ... mode=recomp`
  - `recompiler ... prctl 注册成功`
  - `bytes recomp slot orig=... slot=...`
  - original `libc!getpid` bytes were unchanged before/after install.
- RF exited cleanly with `rc=0`; adb stayed responsive after 20 seconds.
- This run exposed a separate detection surface: the hook engine initial exec
  pool appeared in target maps as anonymous `rwxp`
  `7a0dd20000-7a0dd30000`. This was not the RECOMP code/trampoline page.

Validated hook-exec hide-maps registration:

- Change: `quickjs_loader::init_hook_runtime()` now registers the hook engine
  initial exec pool with `PR_HIDEMAPS_REGISTER` as an exact per-mm range.
- Run: `/tmp/rf_boc_verify_bytes_noop_recomp_hmapexec_20260626_174356`.
- Agent log confirmed:
  `hide-maps registered hook-exec: 0x7a0dd20000-0x7a0dd30000`.
- Kernel log confirmed the matching `kpm-hide-maps: registered range`.
- After 20 seconds:
  - RF `rc=0`
  - adb returned `alive-after-20s`
  - BOCHK stayed in `com.bochk.main.MainActivity`
  - no `com.oplus.securitypermission` or Firefox process remained
  - `/proc/<pid>/maps` had no `rwxp` matches
  - executable anonymous `00:00 inode=0` mappings only showed `[vdso]`
- This proves the minimal RECOMP noop profile is substantially safer than
  normal inline/WXSHADOW on this device, but it does not yet prove arbitrary
  target-function hooks, JS callbacks, `onLeave`, JNI hooks, or ART hooks are
  safe.

Validated full-api RegisterNatives RECOMP observer:

- Run: `/tmp/rf_boc_regnatives_recomp_20260626_175131`.
- Build: full-api noptrace host `/data/local/tmp/rf-noptrace-full`; the host was
  built with `RF_AGENT_API=full` so it embedded `libagent.noptrace-full.so`.
- Script: `tools/bochk_register_natives_recomp.js`, using
  `Interceptor.attach(Jni.addr("RegisterNatives"), ..., Hook.RECOMP)`.
- Agent log confirmed:
  - `hide-maps registered hook-exec: 0x7985a70000-0x7985a80000`;
  - `RegisterNatives=0x7985e7f250`;
  - `recompiler ... prctl 注册成功`;
  - `hook installed mode=RECOMP maxMethods=80`.
- The hook captured BOCHK registrations such as:
  - `fiqlohqeo.ap` -> `libbochk_aos.so+0x238550` and `+0x238ec0`;
  - `fiqlohqeo.C` -> `libbochk_aos.so+0x3137a4`;
  - `fiqlohqeo.ac` lifecycle callbacks -> `libbochk_aos.so+0x5af00c`,
    `+0x5af128`, `+0x5af210`, `+0x5af488`, `+0x5af580`, and related offsets;
  - additional `fiqlohqeo.aO`, `Z`, `H`, `V`, `aY`, `F`, `aL`, and `o`
    registrations.
- RF exited with `rc=0`; adb stayed responsive; BOCHK was still focused on
  `MainActivity` before cleanup.
- The 20-second maps probe showed no `rwxp`, no RF token lines, and anonymous
  executable mappings only showed `[vdso]`.

Validated full-api RECOMP out-parameter modification:

- First attempt: `/tmp/rf_boc_recomp_timeval_modify_20260626_175731`.
- That run installed a RECOMP mapping for `libc!gettimeofday`, but the host used
  the old non-Java pre-resume stop-worker timeout of 2 seconds. The script
  timed out before JS logs were flushed, the target soon hit `exit_mmap`, and no
  modification evidence was produced.
- Fix: pre-resume scripts containing `Hook.RECOMP` or `Java.RECOMP` now use a
  longer load timeout instead of the 2-second stop-worker timeout. The first
  out-param proof used 8 seconds; later full-api business-method tests pushed
  this timeout to 15 seconds because the `RegisterNatives` + target hook chain
  can cross the 8-second boundary before the agent reports eval completion.
- Successful run: `/tmp/rf_boc_recomp_timeval_modify_wait8_20260626_175957`.
- Script: `tools/bochk_recomp_timeval_modify.js`, using
  `Interceptor.attach(libc!gettimeofday, ..., Hook.RECOMP)`.
- Agent log confirmed:
  - `gettimeofday=0x7a1df18670`;
  - `hide-maps registered hook-exec: 0x7985a70000-0x7985a80000`;
  - `recompiler ... prctl 注册成功`;
  - `hook installed mode=RECOMP target=gettimeofday`;
  - `eval ok source=bochk_recomp_timeval_modify.js`;
  - `leave call=1 ret=0 tv=...`;
  - `patched timeval.tv_usec 433613 -> 433614`.
- RF exited with `rc=0`; adb stayed responsive; BOCHK reached
  `com.bochk.main.MainActivity`.
- External maps before cleanup had no RF token lines, no `rwxp`, and anonymous
  executable mappings only showed `[vdso]`.
- This proves JS `onLeave` can modify data returned to BOCHK through an output
  argument while using `Hook.RECOMP`. It does not yet prove that changing a
  BOCHK business native method return value with `retval.replace()` is stable.

Validated full-api RECOMP business boolean return modification, unstable:

- Candidate came from the RegisterNatives observer:
  `fiqlohqeo.ap.d()Z -> libbochk_aos.so+0x238ec0`.
- Script: `tools/bochk_business_bool_recomp_modify.js`.
- First attempt: `/tmp/rf_boc_business_bool_recomp_20260626_181753`.
  This variant installed the target hook from `RegisterNatives.onLeave`. It
  timed out during pre-resume eval, produced no `[biz-bool]` target logs, and
  BOCHK reached `AppStartConfirmDialogActivity`. Treat this run as invalid for
  return-modification proof.
- Successful modification run:
  `/tmp/rf_boc_business_bool_recomp_onenter_20260626_181954`.
  The script installed the business hook from `RegisterNatives.onEnter`, before
  returning to BOCHK's native registration path.
- Agent log confirmed:
  - `RegisterNatives=0x7985e7f250`;
  - `RegisterNatives hook installed mode=RECOMP target=fiqlohqeo.ap.d()Z`;
  - `method d ()Z -> libbochk_aos.so+0x238ec0`;
  - `install target fiqlohqeo.ap.d()Z at libbochk_aos.so+0x238ec0`;
  - `target hook installed mode=RECOMP`;
  - `enter target hit=1`;
  - `flipped return 0 -> 1 hit=1`;
  - a later hit still returned `0` after the one-shot flip.
- Kernel log confirmed RECOMP mappings for both the `RegisterNatives` page and
  the BOCHK business page, then released both on `exit_mmap`.
- Negative result: this is not a stable BOCHK debugging profile. The process
  exited after the flip; RF reported `socket EOF after HELLO` / `Broken pipe`,
  BOCHK was no longer the focused app, and `com.oplus.securitypermission:ui`
  appeared before cleanup.
- Conclusion: `Hook.RECOMP` can modify a BOCHK business native scalar return
  with `retval.replace()`, but this specific method/value flip triggers the
  target's protection or business-failure path. Future business tests should
  start with observe-only hooks, then same-value replacement, then low-impact
  return changes before altering security-sensitive booleans.

Record for future runs:

- whether BOCHK reaches its normal UI;
- whether Firefox/browser warning appears;
- whether `com.oplus.securitypermission:ui` starts;
- whether BOCHK aborts or produces a tombstone;
- the first `bochk-native-audit` line before detection;
- any process identity mismatch reported by `RF_IDENTITY_WATCH_SECS`.

## Next Engineering Targets

- Keep measuring BOCHK's actual detector path with `kpm-hide-maps` loaded,
  especially self-trace child reads of parent maps and hook-enabled profiles.
- Split hook validation by backend: no hook, runtime only, resolver only,
  passive maps read, normal inline hook, WXSHADOW, and RECOMP. Normal inline is
  now known unsafe for BOCHK even on `libc!getpid`; do not re-run it as a
  stability candidate.
- Add a non-inline app-local probe path, for example a GOT/PLT or loader-event
  probe, so analysis is not forced through libc inline patching.
- Investigate a stable way to remove or relocate the remaining executable
  stage-1/veneer mappings only if BOCHK proves it can see and reject them.
- Keep `bytes-cold2-wx-fast` disabled until the async read crash is understood.
