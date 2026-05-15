# WXSHADOW Hook Notes

## 2026-05-15 Fix

`Hook.WXSHADOW` installs an inline jump through the wxshadow KPM instead of
directly modifying the target code mapping. On the PJX110 Android 14 test
device, default hooks worked but wxshadow hooks could hang during spawn before
the app attached.

The user-space cause was install order:

1. `patch_target()` wrote the target instruction with `wxshadow_patch()`.
2. It then scanned the now-protected code page for same-page ARM64
   `LDR literal` instructions.
3. Reading a wxshadow-protected executable page can trigger repeated
   read/execute permission switching on this kernel, so the installer could
   livelock and the app was later killed by the ActivityManager start timeout.

The fix is to collect same-page `LDR literal` records from the original page
before any wxshadow patch is applied, then patch the collected instruction
sites afterward. Cross-page hook installation follows the same rule: relocate
both pages first, then write the second segment and finally the first segment.

## Kernel Side Requirement

This user-space fix assumes the wxshadow KPM can successfully patch normal
user executable PTE mappings. The matching KPM fix for this device:

- walks user `mm->pgd` using `TCR_EL1.T0*` page-table parameters;
- stores and reuses each shadow page's owner `mm`;
- retries VMA offset scanning from the first wxshadow `prctl` caller context;
- routes KPM info logs through a compile-time `WXSHADOW_VERBOSE` switch.

## Verification

The regression test uses `com.coloros.note`:

```bash
adb push test.js /data/local/tmp/test.js
adb shell "su -c 'am force-stop com.coloros.note; sleep 1; (sleep 10; printf \"exit\\n\") | /data/local/tmp/rf --spawn com.coloros.note -l /data/local/tmp/test.js --timeout 60 --verbose'"
```

Expected result:

- `wxshadow stealth patch OK` for `libart.so` `RegisterNatives`;
- the script prints registered native methods after the child is resumed;
- shutdown cleanup releases wxshadow patches without process death.

PID-mode QuickJS dispatch should also return synchronously:

```bash
adb shell "su -c 'printf \"jsinit\\njseval 1+1\\nexit\\n\" | /data/local/tmp/rf --pid <pid> --timeout 60 --verbose'"
```

Expected result: `=> initialized` then `=> 2`.
