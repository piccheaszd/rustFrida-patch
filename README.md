# rustFrida

ARM64 Android 动态插桩框架。

## 环境要求

- Android NDK r25+；仓库自带的 `.cargo/config.toml` 当前指向 `/home/p1cc/Android/Sdk/ndk/android-ndk-r25c`，新环境需要按本机 NDK 路径调整
- Rust toolchain + `aarch64-linux-android` target
- Python 3（构建 loader shellcode）
- `.cargo/config.toml` 已配置交叉编译（仓库自带）

首次 clone 后先拉取子仓库：

```bash
git submodule update --init --recursive
```

`quickjs-hook/third_party/tinycc` 是 RF 的 CModule 编译器子仓库，默认跟随 `https://github.com/kkkbbb/tinycc.git` 的 `rf/cmodule-runtime` 分支。

## 构建

当前有两种主程序构建，二者都会输出名为 `rustfrida` 的 Android arm64 二进制：

- 默认构建：带 ptrace backend，支持 PID/name attach、`--watch-so`、server、trace、普通 spawn 和 pure spawn。
- `noptrace` 构建：编译期移除 ptrace 注入/远程调用/trace 后端，只保留属性命令和 `--spawn --spawn-pure` 自加载路径；pure spawn 使用单独的精简 zymbiote stage-0。

最终产物 `rustfrida` 通过 `include_bytes!` 内嵌 loader blob 和 agent SO。`rust_frida/build.rs` 会在 Android arm64 构建时自动重建缺失或过期的 loader blob；agent 与 host 的 feature 必须匹配，build script 会检查 `libagent.features` 以及按构建类型保存的 `libagent.ptrace.features` / `libagent.noptrace.features`，发现 stale 或 `noptrace` 不一致时直接报错并给出需要重跑的 `cargo build -p agent ...` 命令。

```
loader shellcode  ──┐
                    ├──→  rustfrida (主程序)
agent (libagent.so) ┘
```

### 1. 构建/更新 loader blob（bootstrapper + rustfrida-loader）

```bash
python3 loader/build_helpers.py
# 输出:
#   loader/build/bootstrapper.bin
#   loader/build/rustfrida-loader.bin
```

loader 是 ARM64 shellcode，被 `rustfrida` 通过 `include_bytes!` 嵌入。修改 `loader/` 下 C 代码后需要重新生成；通常不需要手动执行上面的命令，`rust_frida/build.rs` 会在 `aarch64-linux-android` 构建中发现 blob 缺失或过期时自动运行 `python3 loader/build_helpers.py`。手动命令仍可用于单独验证 loader helper 构建是否正常。

### 2. 默认 ptrace 构建

```bash
cargo build -p agent --release
cargo build -p rust_frida --release
```

输出：

```text
target/aarch64-linux-android/release/libagent.so
target/aarch64-linux-android/release/rustfrida
```

### 3. noptrace pure spawn 构建

```bash
cargo build -p agent --release --no-default-features --features quickjs,noptrace
cargo build -p rust_frida --release --no-default-features --features noptrace
```

`noptrace` 版仍然内嵌同一个 loader blob，但 host 不会在目标 App 子进程中调用 `inject_via_bootstrapper()`，也不会读写子进程寄存器。host 只通过 zymbiote socket 传输 stage-1 loader、agent SO 和 pre-resume 脚本。

修改 `zymbiote/` 后需要重新生成 zymbiote ELF；默认构建嵌入 `zymbiote.elf`，`noptrace` 构建嵌入 `zymbiote-pure.elf` 和用于未匹配 child 清理的 `zymbiote-restore.elf`：

```bash
./zymbiote/build.sh
```

两套构建会覆盖同一路径。需要同时保留时，在第二套构建后手动改名：

```bash
cp target/aarch64-linux-android/release/rustfrida target/aarch64-linux-android/release/rustfrida-noptrace
```

### 4. 一键验证构建矩阵

本仓库提供本地验证脚本，固定执行 ptrace/noptrace 两套 agent + host 检查，并在结束前恢复默认 ptrace agent 变体，避免后续默认构建误用 `noptrace` marker：

```bash
tools/verify-build-matrix.sh
PROFILE=release tools/verify-build-matrix.sh
```

脚本会执行 `cargo fmt --all --check`、`./zymbiote/build.sh`、默认 agent build + `rust_frida` check、`noptrace` agent build + `rust_frida` check，最后再跑一轮默认 agent build + `rust_frida` check。

### 当前实现状态

本分支已合入 upstream `v0.0.5` 更新，并保留本地 `--spawn-pure` / `noptrace` pure spawn 路径。相关点需要一起理解：

- PID 注入会优先选择更适合远程调用的工作线程，并在 bootstrap/loader 执行期间短暂停止同进程其他线程，降低主线程或信号线程干扰。
- host 侧通过 `/proc/<pid>/mem` 批量读写上下文，减少 ptrace word-write 的不稳定窗口。
- agent memfd 会按 ELF LOAD 段的 `p_memsz` 进行 padding，loader 将完整段映射为文件支撑 VMA，避免单独匿名 BSS 尾段。
- 自解析 linker 只索引必要平台模块，并继续使用本分支传入的 resolver host module bases，避免在加固 app 中扫描所有 app `.so`。
- 当前 loader 同时兼容 `DEBUG`/`LOG` 诊断消息；协议值保持一致，避免破坏旧 host/loader 握手。
- 上游 Java worker / callback executor 已合入，Java/Managed DSL 的 pre-resume 脚本会优先走 raw-clone Java worker，恢复后按需启动 post-resume worker，减少主线程 remote eval 依赖。
- 上游 ART dex resolver、managed install 和 Java array/exception 处理更新已合入，用于增强新版 ART 上的 managed hook 稳定性。
- 上游 loader resolver seeding、libc/linker base 传递、maps fallback 和远端 loader mapping cleanup 已合入；远端 loader stack/mapping 残留清理默认跳过，避免在已恢复运行的目标线程里额外 remote-call `munmap`。确实需要清理时显式设置 `RF_CLEANUP_REMOTE_LOADER=1`。
- 上游 passive `setArgV0` 与 spawn-only 诊断路径已合入，便于区分 zygote patch、child resume、agent 注入三类问题。
- `--spawn-pure` 是 no-ptrace 子进程路径：`noptrace` 构建嵌入独立的 pure-only zymbiote stage-0，只负责阻塞子进程、接收 stage-1 loader 并跳转；loader 在 App 子进程内自链接 agent。
- pure-only zymbiote stage-0 不内置 ELF linker、QuickJS、hook engine、属性 remap 或 capset mount hook；当前 executable payload 约 2.3KB，小于一页但仍会覆盖真实 `libstagefright.so` 尾页代码。
- `noptrace` 构建只扫描和 patch `zygote64`，不再处理 32-bit zygote / usap；因此只支持 arm64 目标 App。
- pure spawn 的 pre-resume 脚本统一通过 agent socket 发送；Java 主线程 eval 的 remote-agent 分支在 `noptrace` 下不可用。
- `hello_entry()` 入口最前面安装 native early hook；不等待 JS、Java 初始化或 log writer。
- target pure child 会把 zygote payload 备份和 hook 槽原值随 stage-1 一起下发；loader 在 agent entry 前启动 raw clone 清理线程，等 stage-0 退出 resume 等待后优先恢复 payload 页，再恢复 `setArgV0`/`setcontext` 槽。未匹配 child 不再只走 hook slot 自恢复：host 会下发 restore-only stage-1，由 child 侧恢复 payload 页和 hook 槽；找不到父 zygote patch 时会尝试从 child maps/backing file 重建 cleanup，失败则拒绝 hook-only fallback 并显式报警。
- `noptrace` stage-1 会在 agent 读取完启动参数后清理临时字符串/指针表；子进程恢复后异步释放 stage-1 RW tail。host identity watcher 也会在 BOCHK self-trace / 伪装 child 中扫描并清零继承的 stage-1 tail 签名。
- 当前不会强制 `munmap` stage-1 RX 或 linker veneer。BOCHK 实测中对 RX 段做完整 `munmap` / `mprotect` / 清零会导致目标退出或崩溃，因此先保留匿名 `r-xp` 以换稳定性和可调试性。
- 如果加载了 `kpm-hide-maps` 1.1.1 或更新版本，stage-1 loader 会在进入 agent 前通过 `PR_HIDEMAPS_REGISTER` 注册 stage-1 RX 和 linker veneer 的精确范围；KPM 只过滤同一 `mm` 中精确匹配的 `/proc/<pid>/maps` 行，并在首次命中时动态校准当前内核的 `vm_area_struct.vm_mm` 偏移，避免不同 Android 6.1 结构布局导致注册成功但过滤失败。
- 普通 `--spawn package` 默认走 late spawn：先恢复子进程，等待主线程回到 Looper idle 后再按 PID attach。这个模式不保证早期 hook，但更适合交互式 REPL。
- `--spawn -l script.js` 默认走 early spawn：在 zygote/setcontext 阻塞窗口里注入并加载脚本，脚本完成后再恢复子进程，用于抢 `Application.onCreate` / `RegisterNatives` 等早期逻辑。
- `--spawn-early` 可强制无脚本时也走 early spawn；这是诊断/特殊场景用法，稳定性弱于 late。
- `--spawn-late` 可强制带 `-l` 时也走 late spawn，脚本会在冷启动后加载，适合优先保证 REPL/脚本运行稳定的场景。
- `Memory.write*` / `writeBytes` 现在要求写入范围完整落在可写 VMA 中，跨页或只读页会返回 JS 错误，避免直接 SIGSEGV 打断 agent 连接。
- `Hook.RECOMP` 已覆盖 `hook()` / `Interceptor.replace()` / `Interceptor.attach()` 路径；`attach` 的 `onLeave` 会保留 `d0/d1`，避免 double/float 返回值被 leave 回调破坏。
- `Hook.RECOMP` 的 JS 回调会避开同线程 QuickJS 重入：脚本自身通过 `NativeFunction` 调用已 attach 的目标函数时，回调会被跳过以避免死锁；目标 App 线程后续命中同一函数仍会进入 `onEnter` / `onLeave`。

合并后验证过的 smoke：

```bash
python3 loader/build_helpers.py
cargo build -p agent --release
cargo build -p rust_frida --release
printf 'jsinit\njseval 1+1\nexit\n' | adb shell su -c '/data/local/tmp/rf --spawn com.coloros.note --verbose'
printf 'jseval 1+1\nexit\n' | adb shell su -c '/data/local/tmp/rf --spawn com.coloros.note -l /data/local/tmp/rf_smoke.js'
printf 'jseval 1+1\nexit\n' | adb shell su -c '/data/local/tmp/rf --spawn com.coloros.note -l /data/local/tmp/rf_smoke.js --spawn-late'
```

预期结果是 agent 连接成功，`jsinit` 返回 `=> initialized`，`jseval 1+1` 返回 `=> 2`，退出时 zygote patch 和 QuickJS cleanup 正常完成。

### Hook.RECOMP / recompile.kpm

`Hook.RECOMP` 依赖内核侧 `recompile.kpm`。在 KPatch-Next 环境下，推荐把验证过的 KPM 放到持久目录：

```bash
adb push recompile.kpm /data/local/tmp/recompile.kpm
adb shell su -c 'cp -a /data/adb/kp-next/kpm/recompile.kpm /data/adb/kp-next/kpm/recompile.kpm.bak 2>/dev/null || true'
adb shell su -c 'cp -f /data/local/tmp/recompile.kpm /data/adb/kp-next/kpm/recompile.kpm && chmod 600 /data/adb/kp-next/kpm/recompile.kpm'
adb shell su -c '/data/adb/modules/KPatch-Next/bin/kpatch kpm unload recompile; /data/adb/modules/KPatch-Next/bin/kpatch kpm load /data/adb/kp-next/kpm/recompile.kpm'
```

加载成功后，`dmesg | grep -i recompile` 应该看到：

```text
recompile: export hooks setup_sigframe=...
recompile: module loaded
```

如果出现 `setup_sigframe and do_signal both not found, signal PC export unprotected`，说明当前内核没有被 KPM 识别到可用的 signal PC export hook；这类内核上需要使用适配后的 `recompile.kpm`，不能只依赖原始 release 版本。

在 Android 14 / 6.1 内核上还要注意 instruction abort 路径：仅把 `setup_sigframe` 适配到 `setup_rt_frame` 只能修复 signal PC export；如果执行被 hook 函数时卡在原始代码页，KPM 还需要覆盖实际的 instruction abort 入口（该设备上验证为 `do_mem_abort`）。验证成功时，dmesg 会出现成对的映射记录：

```text
recompile: registered mapping: <orig> -> <recomp>
recompile: released mapping: <orig>
```

最小 RECOMP smoke 脚本：

```js
console.log("[recomp-smoke-libm] start");

var atan2Ptr = Module.findExportByName("libm.so", "atan2");
console.log("[recomp-smoke-libm] atan2=" + atan2Ptr);

var hits = 0;
Interceptor.attach(atan2Ptr, {
  onEnter: function () {
    hits++;
    if (hits <= 3) {
      console.log("[recomp-smoke-libm] enter atan2 hit=" + hits + " pc=" + this.pc);
    }
  },
  onLeave: function (retval) {
    if (hits <= 3) {
      console.log("[recomp-smoke-libm] leave atan2 ret=" + retval);
    }
  }
}, Hook.RECOMP);

var atan2 = new NativeFunction(atan2Ptr, "double", ["double", "double"]);
for (var i = 0; i < 3; i++) {
  console.log("[recomp-smoke-libm] call atan2 -> " + atan2(1.0 + i, 2.0));
}

console.log("[recomp-smoke-libm] done hits=" + hits);
```

已在 Android 14 arm64 设备上用 `com.paic.mo.client` 的 spawn early 路径验证：

```bash
adb shell su -c 'RF_STOP_WORLD=1 RF_REMOTE_CALL_TIMEOUT_MS=7000 /data/local/tmp/rf --spawn com.paic.mo.client --spawn-early --verbose --connect-timeout 25 --quickjs-profile full -l /data/local/tmp/recomp_smoke_libm.js'
```

预期成功标记：

```text
Loader: agent 加载成功
Agent 已连接
[recompiler] prctl 注册成功
[recomp-smoke-libm] call atan2 -> 0.4636476090008061
[recomp-smoke-libm] call atan2 -> 0.7853981633974483
[recomp-smoke-libm] call atan2 -> 0.982793723247329
```

`noptrace` pure spawn smoke：

```bash
./zymbiote/build.sh
cargo build -p agent --release --no-default-features --features quickjs,noptrace
cargo build -p rust_frida --release --no-default-features --features noptrace
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rf-noptrace
adb shell su -c 'chmod 755 /data/local/tmp/rf-noptrace'
printf 'jseval 1+1\nexit\n' | adb shell su -c '/data/local/tmp/rf-noptrace --spawn com.coloros.note --spawn-pure -l /data/local/tmp/rf_smoke.js --verbose'
```

已在 Android 14 arm64 设备上验证 `com.coloros.note` 和 `com.bochk.app.aos` 的 pure spawn。

BOCHK 当前实测结论（2026-06-26）：

- 已解决：`noptrace --spawn-pure` 不再对目标子进程执行 ptrace attach、寄存器改写或远程调用；BOCHK 可完成 agent 连接，`jsinit` 返回 `=> initialized`，`jseval 1+1` 返回 `=> 2`。
- 已解决：zygote patch 在退出时恢复；未匹配 child 通过 restore-only stage-1 恢复；BOCHK self-trace child 会被 identity watcher 识别。
- 已解决：stage-1 临时字符串、指针表和 main process RW tail 已清理；self-trace child 中继承的 stage-1 tail 签名会被 host 侧清零。针对 stage-1 RX、tail、veneer 的直接内存扫描未再命中 `frida`、`quickjs`、`rustfrida-loader`、`stage1` 等字符串。
- 已解决：当前 BOCHK pure-spawn + minimal QuickJS 路径未观察到 `rwxp` VMA。
- 已解决：`kpm-hide-maps` 1.1.1 已在 BOCHK 设备侧复测，stage-1 RX 和 linker veneer 注册返回 OK；外部读取主进程 `/proc/<pid>/maps` 时匿名 `r-xp` 列表只剩 `[vdso]`，不再暴露这两个 RF range。这是 procfs 输出过滤，不是实际 `munmap`。
- 剩余：BOCHK 的 self-trace child 仍会让主进程 `TracerPid` 指向 App 自己的 watchdog child；RF 不再 ptrace 目标，但 App 原生自检仍可能把“被 trace 状态”作为业务信号。
- 剩余：`Hook.WXSHADOW` / `Hook.RECOMP` 在 BOCHK 上还需要逐个 hook profile 验证；不要把 pure spawn + REPL 通过等同于所有 native hook 都安全。

BOCHK 的 `noptrace` / WXSHADOW 分阶段探测记录和复测顺序见
[`docs/bochk-noptrace-test-notes.md`](docs/bochk-noptrace-test-notes.md)。

### noptrace 测试矩阵

| 类别 | 当前状态 | 验证目标 |
| --- | --- | --- |
| 普通 arm64 App | 已在 ColorOS / Android 14 上用 `com.coloros.note` pure spawn 通过 | agent 连接、pre-resume 脚本执行、退出恢复 zygote patch |
| 多进程 App | 部分覆盖；仍需专门枚举 secondary process | 未匹配 child 通过 restore-only stage-1 恢复 payload 页和 hook 槽，不留下 `libstagefright.so` 尾页覆盖 |
| 含 `:remote` / `:push` 的 App | 待专测 | 只消费目标进程 hello，非目标进程恢复后继续运行 |
| 有 self-ptrace watchdog 的 App | 已用 `com.bochk.app.aos` 覆盖 RF 不 ptrace 目标、BOCHK 自己拉起 self-trace child 的路径 | `TracerPid` 不指向 RF；identity watcher 能识别 self-trace / 伪装 child 并清理继承的 stage-1 tail 签名 |
| 早期 `JNI_OnLoad` 检测 App | 已用 `com.bochk.app.aos` 验证 pure spawn、minimal QuickJS REPL 和 `RegisterNatives` pre-resume smoke；BOCHK 后续 native hook 检测链路仍在拆分 | native early hook 在 JS/Java/log writer 前安装；stage-1 临时字符串不留在 RW tail |
| 大量 SO 加载 App | `com.bochk.app.aos` 部分覆盖；pure spawn 连接稳定，普通 libc inline hook 会触发检测，WXSHADOW/RECOMP 仍需逐 profile 验证 | loader/agent 自链接稳定，脚本能在大量 dlopen 场景下保持连接；hook 后 maps/code-integrity 信号可分离 |
| WebView-heavy App | 待专测 | WebView 初始化和多进程 sandbox 不触发未恢复 payload 页执行 |
| 厂商 ROM | ColorOS / Android 14 已测；MIUI / OneUI / HarmonyOS Android 分支（NEXT 前）待测 | zygote64 布局、`libstagefright.so` host 页选择、SELinux/tracefs 验证能力 |
| no-ptrace 证明 | tracefs raw syscall 在当前 ColorOS 设备上受 SELinux 限制，无法写入 `sys_enter_ptrace` filter | 用 eBPF tracepoint/kprobe 或可写 tracefs 验证 `sys_enter_ptrace(id==117)` 无 rustfrida/App 命中 |

### 可选组件与辅助二进制

这些 crate 不在 workspace `default-members` 里，按需构建：

**QBDI Trace 支持：** 需要先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi  # agent 启用 qbdi feature
cargo build -p rust_frida --release --features qbdi  # rustfrida 嵌入 qbdi-helper SO
```

**eBPF SO 加载监控（`--watch-so`）：** ldmonitor 是 rustfrida 的编译依赖，默认构建 `rust_frida` 时已包含，`--watch-so` 无需额外步骤。如需独立使用 ldmonitor 命令行工具：

```bash
cargo build -p ldmonitor --release    # → ldmonitor 独立二进制
```

### TinyCC 子仓库维护

RF 的 CModule 功能依赖 `quickjs-hook/third_party/tinycc`。该目录是 git submodule，RF 定制修改维护在 `rf/cmodule-runtime` 分支：

```bash
git -C quickjs-hook/third_party/tinycc remote -v
# origin   https://github.com/kkkbbb/tinycc.git
# upstream https://github.com/frida/tinycc.git

git -C quickjs-hook/third_party/tinycc status --short --branch
```

同步上游时，在子仓库 rebase 后更新父仓库的 gitlink：

```bash
git -C quickjs-hook/third_party/tinycc fetch upstream
git -C quickjs-hook/third_party/tinycc rebase upstream/main
git -C quickjs-hook/third_party/tinycc push origin rf/cmodule-runtime

git add quickjs-hook/third_party/tinycc
git commit -m "Update tinycc submodule"
```

如果修改了 TinyCC 本身，先在子仓库提交并 push，再回到父仓库提交 submodule 指针。

## 部署 & 运行

下面的 `./rf` / `./rf-noptrace` 示例默认在 `adb shell su` 后的 `/data/local/tmp` 目录执行。

默认 ptrace 版：

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rf
adb shell su -c 'chmod 755 /data/local/tmp/rf'

# PID 注入
./rf --pid <pid>
./rf --pid <pid> -l script.js
./rf --name com.example.app -l script.js

# Spawn 模式（启动时注入）
./rf --spawn com.example.app
./rf --spawn com.example.app -l script.js
./rf --spawn com.example.app --spawn-early
./rf --spawn com.example.app -l script.js --spawn-late
./rf --spawn com.example.app --spawn-pure -l early.js

# 等待 SO 加载后注入（eBPF）
./rf --watch-so libnative.so

# 详细日志
./rf --pid <pid> --verbose

# 同步输出日志到文件（终端仍正常输出，文件为纯文本）
./rf --pid <pid> -l script.js -o /data/local/tmp/rustfrida.log

# QuickJS 精简 profile：跳过 Module / Java 等可选启动路径，适合先绕开加固 App 初始化期崩溃
./rf --pid <pid> --quickjs-profile minimal

# 属性 profile：默认 ptrace 版可在 spawn/server 生命周期内应用
./rf --dump-props default
./rf --set-prop default ro.debuggable=0
./rf --del-prop default ro.secure
./rf --repack-props default
./rf --spawn com.example.app --profile default
```

`noptrace` 版：

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/rf-noptrace
adb shell su -c 'chmod 755 /data/local/tmp/rf-noptrace'

# 只支持 arm64 pure spawn；必须带 --spawn-pure
./rf-noptrace --spawn com.example.app --spawn-pure
./rf-noptrace --spawn com.example.app --spawn-pure -l /data/local/tmp/early.js

# 属性快照/伪装命令仍可独立使用
./rf-noptrace --dump-props default
./rf-noptrace --set-prop default ro.debuggable=0
./rf-noptrace --del-prop default ro.secure
./rf-noptrace --repack-props default
```

`noptrace` 构建不包含 `--pid`、`--name`、`--watch-so`、`--server`、`--profile`、trace 命令和 process remote-call 后端。当前 pure-only stage-0 不包含属性 profile 注入 hook；`--dump-props` / `--set-prop` / `--del-prop` / `--repack-props` 只能编辑 profile，不能自动应用到 pure spawn。需要自动应用 profile 时使用默认 ptrace 版。

### Spawn / Zymbiote 诊断开关

这些开关用于拆分 zygote patch、生进程恢复和 agent 注入问题。诊断命令仍会修改 zygote 进程，设备侧执行前确认处于授权测试环境。

```bash
# 只 patch zygote、启动目标并恢复 child，不注入 agent；用于确认 zymbiote 拦截和 child resume 是否正常
RF_DIAG_SPAWN_ONLY=1 RF_DIAG_HOLD_SECS=20 ./rf --spawn com.example.app

# 只走 passive setArgV0 launch 路径，不安装 setcontext 拦截；用于定位 setcontext hook 是否引入不稳定
RF_DIAG_ZYM_PASSIVE_SETARGV0=1 RF_DIAG_HOLD_SECS=20 ./rf --spawn com.example.app

# 普通 spawn/pure spawn 中禁用 setcontext patch，只保留 setArgV0 侧路径
RF_DIAG_ZYM_NO_SETCONTEXT=1 ./rf --spawn com.example.app -l early.js

# 普通 spawn/pure spawn 中禁用 setArgV0 patch，只保留 setcontext 侧路径
RF_DIAG_ZYM_NO_SETARGV0=1 ./rf --spawn com.example.app -l early.js
```

`RF_DIAG_ZYM_NO_SETCONTEXT` 和 `RF_DIAG_ZYM_NO_SETARGV0` 不能同时启用；`RF_DIAG_ZYM_PASSIVE_SETARGV0` 与 `RF_DIAG_ZYM_NO_SETARGV0` 也互斥。`RF_DIAG_HOLD_SECS` 只影响 spawn-only/passive 诊断命令保持目标进程存活检查的时间，默认 20 秒。

### no-ptrace 验证

验证 pure spawn 是否触发 `ptrace`，不要用 `strace`，因为 `strace` 本身就是 ptrace。优先用 eBPF tracepoint/kprobe；设备没有 bpftrace 时可直接用 tracefs raw syscall 事件观察 arm64 `__NR_ptrace == 117`：

```bash
adb shell su -c '
TRACE=/sys/kernel/tracing
I=$TRACE/instances/rustfrida-ptrace
mkdir -p $I
echo 0 > $I/tracing_on
echo > $I/trace
echo "id == 117" > $I/events/raw_syscalls/sys_enter/filter
echo 1 > $I/events/raw_syscalls/sys_enter/enable
echo 1 > $I/tracing_on
/data/local/tmp/rf-noptrace --spawn com.example.app --spawn-pure -l /data/local/tmp/early.js >/data/local/tmp/rf-run.log 2>&1
echo 0 > $I/tracing_on
cat $I/trace
'
```

空 trace 或没有目标 `rustfrida`/App 相关记录，才算 no-ptrace 路径通过。只看日志里“没有 ptrace”不够。

### REPL 命令

```
jsinit              # 初始化 JS 引擎
jseval <expr>       # 求值表达式
loadjs <script>     # 执行脚本
jsrepl              # 交互式 REPL（Tab 补全）
exit                # 退出
```

---

## 快速上手

最常见的工作流是：写一个 `script.js`，用 `-l` 加载到目标进程，然后通过日志、RPC 或文件把结果带出来。默认 ptrace 版覆盖 attach 和 spawn；`noptrace` 版只走 `--spawn --spawn-pure`。

```bash
# 已运行的进程
./rf --pid <pid> -l script.js

# 从启动阶段注入，适合抓 Application / ClassLoader 初始化
./rf --spawn com.example.app -l script.js

# no-ptrace pure spawn，从 zygote64 子进程内自加载 agent
./rf-noptrace --spawn com.example.app --spawn-pure -l script.js

# 先进入交互，再手动 loadjs / jseval（默认 ptrace 版）
./rf --pid <pid>
```

最小脚本：

```js
console.log("agent loaded");

Java.ready(function() {
    console.log("Java is ready");
});
```

### 能力地图

| 你想做什么 | 优先使用 | 典型入口 |
| --- | --- | --- |
| Hook Java 方法、改参数/返回值 | `Java.use()` | `Class.method.impl = function (...) { ... }` |
| 高频 Java 方法 Hook | Managed DSL 动态编译器 | `method.dslImpl = script` |
| Hook native 函数并继续跑原函数 | `Interceptor.attach` | `onEnter(args)` / `onLeave(retval)` |
| 完全替换 native 函数 | `hook()` 或 `Interceptor.replace()` | `return value` / 条件性 `this.$orig()` |
| 高频 native Hook | `CModule` + `attachNative` / `hookNative` | `void cb(HookContext *ctx, void *data)` |
| 查找 so、符号、导入导出 | `Module` | `findExportByName()` / `enumerateSymbols()` |
| 读写目标进程内存 | `Memory` / `ptr()` | `p.readU32()` / `p.writeBytes()` |
| 监控 JNI 注册 | `Jni` + native hook | `Jni.addr("RegisterNatives")` |
| 远程触发脚本能力 | HTTP RPC | `rpc.exports = { ... }` |
| 采集指令 trace 用于回放分析 | `qbdi` | `registerTraceCallbacks()` |

`noptrace` 构建中的脚本 API 仍来自同一个 agent，但 host 侧去掉了 ptrace attach、process remote-call、trace 命令和相关帮助文案；脚本要在恢复前执行时，统一通过 agent socket 发送。

`--quickjs-profile minimal` 会在 agent 侧启用精简 API profile：保留 `console`、`File`、`ptr`、native hook、`Jni`、`Memory`、`rpc` 等核心能力，跳过 `Module` 和 lazy `Java` API 的启动注册，减少初始化阶段读取 maps 或解析 ART 状态的检测面。默认值是 `full`。

### 常见场景

#### Hook Java 方法

适合看业务参数、绕过判断、替换返回值。Spawn 模式下务必放在 `Java.ready()` 里。

```js
Java.ready(function() {
    var Login = Java.use("com.example.LoginManager");

    Login.checkPassword.impl = function(user, pass) {
        console.log("checkPassword", user, pass);
        return true;              // 直接改返回值，不调原方法
    };
});
```

需要保留原逻辑时调用 `$orig()`：

```js
Java.ready(function() {
    var Log = Java.use("android.util.Log");

    Log.i.overload("java.lang.String", "java.lang.String").impl = function(tag, msg) {
        console.log("[Log.i]", tag, msg);
        return this.$orig(tag, msg);
    };
});
```

#### Hook Native 函数并修改参数

只改参数然后继续执行原函数，优先用 `Interceptor.attach({ onEnter })`。

```js
var open = Module.findExportByName("libc.so", "open");

Interceptor.attach(open, {
    onEnter(args) {
        var path = args[0].readCString();
        console.log("open", path);

        if (path.indexOf("/proc/self/maps") >= 0) {
            args[0] = Memory.allocUtf8String("/data/local/tmp/fake_maps");
        }
    }
});
```

#### Hook Native 函数并修改返回值

需要返回值时加 `onLeave`。

```js
var getuid = Module.findExportByName("libc.so", "getuid");

Interceptor.attach(getuid, {
    onLeave(retval) {
        console.log("getuid =>", retval.toUInt32());
        retval.replace(0);
    }
});
```

#### 条件性调用原 native 函数

如果你需要“有时调原函数、有时直接返回”，用 `hook()` 更直接。

```js
var getpid = Module.findExportByName("libc.so", "getpid");

hook(getpid, function() {
    if (Date.now() & 1) {
        return this.$orig();    // 调原函数，参数默认来自当前寄存器
    }
    return 12345;               // 跳过原函数
});
```

#### 监控 RegisterNatives

适合定位 Java native 方法和 so 内真实函数地址。

```js
Interceptor.attach(Jni.addr("RegisterNatives"), {
    onEnter(args) {
        var cls = Jni.env.getClassName(args[1]);
        var methods = Jni.structs.JNINativeMethod.readArray(args[2], Number(args[3]));

        console.log("RegisterNatives:", cls);
        methods.forEach(function(m) {
            var mod = Module.findByAddress(m.fnPtr);
            var where = mod ? mod.name + "+" + m.fnPtr.sub(mod.base) : m.fnPtr.toString();
            console.log("  " + m.name + " " + m.sig + " -> " + where);
        });
    }
});
```

#### 远程调用脚本能力

当你希望工具常驻，然后由 host 脚本、UI 或自动化流程触发功能时，用 `rpc.exports`。

```js
rpc.exports = {
    ping: function() { return "pong"; },
    app: function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        return String(app.getPackageName());
    }
};
```

启动时加 `--rpc-port`，host 侧通过 `curl` 调用：

```bash
adb forward tcp:9191 tcp:9191
./rf --pid <pid> -l script.js --rpc-port 9191
curl -X POST http://127.0.0.1:9191/rpc/0/ping
```

### 选择建议

- 普通 Java 逻辑先用 `Java.use().impl`，稳定后再考虑 DSL。
- 高频 Java Hook 用 DSL 动态编译器，避免每次命中都进 JS runtime。
- Native 只改参数并继续执行，用 `Interceptor.attach({ onEnter })`。
- Native 需要决定是否调用原函数，用 `hook()` / `Interceptor.replace()`。
- 高频 Native 热路径用 `CModule` 写 C callback，再用 `attachNative` / `hookNative` 安装。
- 不知道用哪个 stealth 模式时先用默认模式；遇到检测或只读代码页问题再切 `Hook.WXSHADOW` / `Hook.RECOMP`。

---

## HTTP RPC 远程调用

脚本里用 Frida 风格的 `rpc.exports` 注册方法，host 端通过 HTTP POST 调用，返回值会 `JSON.stringify` 后透传回来。适合把 agent 当成一个常驻服务用——UI、自动化脚本、测试框架都可以直接 `curl` 触发。

HTTP RPC 主要面向默认 ptrace 构建的 legacy/session 使用方式；`noptrace` 构建没有 server 和 process remote-call 后端。

### 启动

在 legacy 单会话或 `--server` 多会话模式下，加上 `--rpc-port` 即可启动 HTTP 服务器。参数可以是纯端口号（默认绑 `0.0.0.0`），也可以是完整地址：

```bash
# legacy 模式：attach + 加载脚本 + 开 RPC 端口
./rf --pid 1234 -l rpc_test.js --rpc-port 9191

# server 模式：多 session 共享同一个 RPC 端口，按 session id 路由
./rf --server --rpc-port 127.0.0.1:9191

# 本机访问通过 adb forward 最简单
adb forward tcp:9191 tcp:9191
```

### JS 侧注册

```js
// 整体替换
rpc.exports = {
    ping: function() { return "pong"; },
    add: function(a, b) { return a + b; },
    echo: function(obj) { return { received: obj, ts: Date.now() }; },

    // 读取当前 App 的 package name + label
    getAppName: function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var app = ActivityThread.currentApplication();
        var ctx = app.getApplicationContext();
        var pm = ctx.getPackageManager();
        return {
            packageName: String(ctx.getPackageName()),
            label: String(pm.getApplicationLabel(ctx.getApplicationInfo())),
        };
    }
};

// 或者单独追加
rpc.export('version', function() { return "1.0.0"; });
```

`rpc.exports` 就是个普通 JS 对象，**现场 lookup，不需要向 host 注册方法列表**——你可以任意时刻增删改，下一次 HTTP 请求立刻生效。

### HTTP 路由

| 方法 | 路径 | Body | 说明 |
| --- | --- | --- | --- |
| `GET` | `/` / `/health` | — | 健康检查 |
| `GET` | `/sessions` | — | 列出所有 session（id/pid/label/status）|
| `POST` | `/rpc/<session>/<method>` | JSON 数组 | 调用 `rpc.exports[method].apply(null, args)`；空 body 等价 `[]` |

`<session>` 在 legacy 模式下固定为 `0`，在 `--server` 模式下对应 `list` 命令显示的 id。

### 调用示例

```bash
# 简单调用
curl -X POST http://127.0.0.1:9191/rpc/0/ping
# → {"ok":true,"result":"pong"}

# 位置参数（JSON 数组）
curl -X POST http://127.0.0.1:9191/rpc/0/add -d '[3,4]'
# → {"ok":true,"result":7}

# 对象参数
curl -X POST http://127.0.0.1:9191/rpc/0/echo -d '[{"foo":1,"bar":"hi"}]'
# → {"ok":true,"result":{"received":{"foo":1,"bar":"hi"},"ts":1775806588866}}

# Java 集成
curl -X POST http://127.0.0.1:9191/rpc/0/getAppName
# → {"ok":true,"result":{"packageName":"com.android.settings","label":"设置"}}

# 列出 session
curl http://127.0.0.1:9191/sessions
# → [{"id":0,"pid":1234,"label":"PID:1234","status":"connected"}]
```

成功响应统一是 `{"ok":true,"result":<value>}`；失败是 `{"ok":false,"error":"<msg>"}`，HTTP 状态码 400（参数错）/404（session/method 不存在）/503（session 未连接）/500（JS 异常或超时）。

### 行为约束

- **返回值必须 JSON-safe**：`JSON.stringify` 在 JS 侧执行，函数/循环引用/`undefined` 会被跳过。直接 `return` 一个 Java wrapper 只会得到指针字面量——请手动 `String(obj.method())` 或构造 plain object。
- **并发串行化**：同一 session 内 HTTP 请求排队执行；跨 session 完全并行。
- **超时 30 秒**：超时返回 `{"ok":false,"error":"rpc call timed out"}`。长耗时任务请改用轮询接口。
- **仅同步**：不支持 `async` / Promise——Promise 会被 `JSON.stringify` 成 `{}`。

---

## JS API 参考

### 全局对象一览

`console`, `ptr()`, `Memory`, `File`, `Module`, `Interceptor`, `CModule`, `hook()`, `hookNative()`, `attachNative()`, `unhook()`, `callNative()`, `qbdi`, `Java`, `Jni`

### 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建的指针对象 |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |

### 结构体 / 上下文对象

```ts
type ModuleInfo = {
  name: string; base: NativePointer; size: number; path: string
}

// Native / Java hook 回调都是 Frida 风格：arguments = 参数，this = 上下文载体

type NativeHookThis = {
  x0 ~ x30: bigint             // ARM64 通用寄存器（读/写）
  sp: bigint
  pc: bigint
  trampoline: bigint
  $orig(): bigint              // 调原函数；默认使用当前寄存器（入口原参数，或你已写入的 this.xN）
}

// native hook 写法：
// hook(addr, function(a, b, c) {     // arguments[0..7] = x0..x7（BigInt）
//   this.x0 = ptr("0x1234");          // 改寄存器
//   return this.$orig();              // replace hook 中显式调原函数
// });

type JavaInstanceThis = JavaObjectProxy & {
  // 继承 JavaObjectProxy: 字段 this.field.value / 方法 this.method(args) / this.$className / this.__jptr
  $orig(...args: any[]): any    // 调原方法，不传参用原始参数
}

type JavaStaticThis = {
  $orig(...args: any[]): any
  $className: string
  $static: true
}

// hook 写法：
// Cls.method.impl = function(a, b, c) {   // arguments = Java 参数（对象自动 Proxy）
//   this.$className           // 始终可读
//   this.field.value          // 实例方法: 直接读字段
//   return this.$orig(a, b, c) // 调原方法
// }

// Interceptor.attach 双阶段：args 是 NativePointer 代理（args[0] = x0），
// retval 支持 .replace() / .toInt32()；this 在 onEnter/onLeave 之间共享
type InterceptorArgs = {
  [i: number]: NativePointer    // args[0..30] ⇄ ctx.x0..x30（读/写）
}
type InterceptorRetval = NativePointer & {
  replace(v: AddressLike): void // 改返回值
  toInt32(): number
  toUInt32(): number
}
type InterceptorThis = {
  x0 ~ x30: bigint; sp: bigint; pc: bigint
  lr: bigint; returnAddress: bigint
  // + 用户自定义字段，onEnter/onLeave 跨阶段共享（Frida 兼容）
}
type InvocationListener = { detach(): boolean }

type JniEntry = { name: string; index: number; address: NativePointer }

type JNINativeMethodInfo = {
  address: NativePointer; namePtr: NativePointer; sigPtr: NativePointer
  fnPtr: NativePointer; name: string | null; sig: string | null
}
```

---

## Native Hook

Frida 风格：**`arguments`** = x0..x7（前 8 个整型参数，BigInt），**`this`** = register 上下文（含 x0-x30 / sp / pc / $orig）。

```js
// 固定继续执行原函数：用 attach，不要用 hook()+$orig() 透传
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter(args) {
        console.log("open:", args[0].readCString(), "flags=" + args[1]);
    }
});

// 修改返回值（直接 return 覆盖）
hook(Module.findExportByName("libc.so", "getpid"), function() {
    return 12345;              // 调用方拿到 12345
});

// 条件性调用原函数：用 hook()/replace；无参数 $orig() 会使用当前 this.xN
hook(target, function(a, b) {
    if (Number(a) === 0) {
        return -1;             // 跳过原函数
    }
    this.x0 = ptr("0x1234");   // 改第一个参数
    this.x1 = 100;             // 改第二个参数
    return this.$orig();       // 用当前寄存器调原函数
});

// 不 return 也行 — this.x0 赋值会同步回 C 层
hook(Module.findExportByName("libc.so", "getuid"), function() {
    this.$orig();
    this.x0 = 77777;          // 调用方拿到 77777
});

// 移除 hook
unhook(Module.findExportByName("libc.so", "open"));

// 直接调用 native 函数（最多 6 个参数，走 x0-x5）
var pid = callNative(Module.findExportByName("libc.so", "getpid"));
```

### NativeFunction（任意签名调用）

Frida 兼容 API，任意参数数量（寄存器用完自动栈溢出，上限 256 个栈参数）。

```js
var open = new NativeFunction(
    Module.findExportByName("libc.so", "open"),
    "int",                            // 返回类型
    ["pointer", "int"]                // 参数类型
);
var fd = open(Memory.allocUtf8String("/tmp/foo"), 0);

var atan2 = new NativeFunction(
    Module.findExportByName("libm.so", "atan2"),
    "double",
    ["double", "double"]
);
atan2(1.0, 2.0);
```

**支持的类型**：`void`, `bool`, `char`/`uchar`, `int8`/`uint8`, `short`/`ushort`, `int16`/`uint16`, `int`/`uint`, `int32`/`uint32`, `long`/`ulong` (64-bit), `int64`/`uint64`, `size_t`/`ssize_t`, `pointer`, `float`, `double`。

AAPCS64 调用约定：整数/指针先填 x0-x7，浮点先填 d0-d7（两队列独立），超出部分自动压栈。不支持 struct-by-value。


### CModule 和 native C callback

`CModule` 用内置 TinyCC 在目标进程里动态编译 C 代码，适合把高频 native hook 的热路径从 JS callback 下沉到 C callback。CModule 对象持有编译后的代码内存；只要 hook 还在使用其中的函数指针，就必须保留 JS 引用，避免 GC 释放代码。

```js
var cm = new CModule(`
    #include <rfhook.h>

    void on_getuid(HookContext *ctx, void *user_data) {
        uint64_t real = hook_invoke_trampoline(ctx, ctx->trampoline);
        ctx->x[0] = (real == 0 ? 0 : 20000);
    }
`);

globalThis.keep_getuid_cmodule = cm;        // hook 存活期间必须保留引用

var getuid = Module.findExportByName("libc.so", "getuid");
var trampoline = hookNative(getuid, cm.on_getuid);
```

`hookNative(target, callbackPtr, userData?, mode?)` 是 replace 语义：原函数不会自动执行。需要原函数时，在 C callback 里调用 `hook_invoke_trampoline(ctx, ctx->trampoline)`；不需要原函数时直接改 `ctx->x[0]`。

```js
var cm = new CModule(`
    #include <rfhook.h>

    struct Counter {
        uint64_t calls;
    };

    void on_enter(HookContext *ctx, void *user_data) {
        struct Counter *counter = (struct Counter *) user_data;
        counter->calls++;
        ctx->x[1] = 0;        // 改第二个参数
    }

    void on_leave(HookContext *ctx, void *user_data) {
        if ((int64_t) ctx->x[0] < 0) {
            ctx->x[0] = 0;    // onLeave 中 x0 是返回值
        }
    }
`);

globalThis.keep_open_cmodule = cm;

var state = Memory.alloc(8);
state.writeU64(0);

var open = Module.findExportByName("libc.so", "open");
attachNative(open, {
    onEnter: cm.on_enter,
    onLeave: cm.on_leave,
    data: state,
    mode: Hook.NORMAL
});
```

`attachNative(target, { onEnter?, onLeave?, data?, mode? })` 是 attach 语义：hook engine 会自动执行原函数。只提供 `onEnter` 时走 tail-jump 快路径，不保留 leave 状态；提供 `onLeave` 时才会在原函数返回后进入 leave callback。`onEnter` 和 `onLeave` 的 C 函数签名相同：

```c
void callback(HookContext *ctx, void *user_data);
```

两者区别只在时机和 `ctx` 内容：

| 阶段 | `ctx->x[0..]` 含义 | 原函数 |
| --- | --- | --- |
| `onEnter` | 入参寄存器，可改参数 | 返回后自动执行 |
| `onLeave` | `x0` 是返回值，可改返回值 | 已经执行完 |

如果安装了 `onLeave`，`onEnter` 可用 `ctx->intercept_leave = 0` 跳过本次 leave；没有安装 `onLeave` 时设置这个字段没有意义。

CModule 默认注入这些头：`stdint.h`, `stddef.h`, `stdbool.h`, `string.h`, `rfhook.h`。`rfhook.h` 暴露 `HookContext`、`RfHookCallback` 和 `hook_invoke_trampoline()`：

```c
typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv;
    void *trampoline;
    uint64_t d[8];
    uint64_t intercept_leave;
} HookContext;

typedef void (*RfHookCallback)(HookContext *ctx, void *user_data);
uint64_t hook_invoke_trampoline(HookContext *ctx, void *trampoline);
```

也可以把 JS 侧找到的 native symbol 传给 CModule：

```js
var cm = new CModule(`
    extern int puts(const char *);

    void say_hi(void) {
        puts("hello from CModule");
    }
`, {
    puts: Module.findExportByName("libc.so", "puts")
});

new NativeFunction(cm.say_hi, "void", [])();
```

调试符号：

```js
console.log(cm.base, cm.size);
console.log(cm.findSymbolByName("on_enter"));
cm.dropMetadata();     // 可选：释放 TinyCC 元数据；函数代码仍保留到 CModule 被 GC
```

### Interceptor（Frida 兼容双阶段）

Frida 原生语法。`hook()` 是 replace 单阶段，通过 `this.$orig()` 手动调用原函数；`Interceptor.attach` 自动执行原函数并提供 `onEnter` / `onLeave` 双阶段拦截，`this` 在两阶段之间共享。

```js
// 双阶段 attach: onEnter 前置 + 自动调原函数 + onLeave 后置
var listener = Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter(args) {
        // args[0..30] 是 NativePointer 代理，args[N] = value 会写回 xN
        this.path = args[0].readCString();
        this.t0 = Date.now();
    },
    onLeave(retval) {
        // retval 是 NativePointer，.replace(v) 改返回值
        console.log("open(" + this.path + ") = " + retval.toInt32()
                  + " took " + (Date.now() - this.t0) + "ms");
        if (retval.toInt32() < 0) retval.replace(0);
    }
});
listener.detach();

// 仅 onEnter — 改参数后让原函数自己跑（C 侧走 tail-jump 快路径，无栈帧残留）
Interceptor.attach(target, {
    onEnter(args) { args[1] = ptr(100); }
});

// Interceptor.replace — 完全替换（等价于 hook()，不跑原函数）
Interceptor.replace(Module.findExportByName("libc.so", "getpid"), function() {
    return 1234;
});

// 清理：单个 / 全部
listener.detach();
Interceptor.detachAll();
Interceptor.flush();           // no-op，兼容脚本
```

第三参数可选 stealth 模式（同 `hook()`）：`Interceptor.attach(target, cbs, Hook.WXSHADOW)`。

### Native Hook 怎么选

先按你的目标选择 API，再按检测强度选择 `stealth` 参数。

| 目标 | 推荐写法 | 原函数 | 说明 |
| --- | --- | --- | --- |
| 只看参数 | `Interceptor.attach(target, { onEnter })` | 自动执行 | 日志、统计、轻量过滤 |
| 改参数后继续执行 | `Interceptor.attach(target, { onEnter })` | 自动执行 | `args[n] = value` 会写回参数 |
| 看返回值或改返回值 | `Interceptor.attach(target, { onLeave })` | 自动执行 | `retval.replace(v)` 改返回值 |
| 有时跳过原函数 | `hook(target, fn)` | 手动 `this.$orig()` | 适合条件分支、绕过、完整替换 |
| Frida replace 风格 | `Interceptor.replace(target, fn)` | 手动 | 等价于 `hook(target, fn)` |
| 高频 C callback | `attachNative(target, {onEnter, onLeave})` | 自动执行 | CModule 热路径，支持 onEnter/onLeave |
| 高频完整替换 | `hookNative(target, callback)` | 手动 | CModule replace，回调内按需 `hook_invoke_trampoline(ctx, ctx->trampoline)` |

选择建议：

- 只改参数并继续跑原函数：优先用 `Interceptor.attach(..., { onEnter })`。
- 需要“有时调原函数、有时直接返回”：用 `hook()` / `Interceptor.replace()`，在回调里显式 `this.$orig()`。
- 固定调原函数：用 `Interceptor.attach` / `attachNative`，无 `onLeave` 时直接 tail-jump 原函数，不再回到 hook 代码。
- 高频热路径不要无条件 `this.$orig()` 透传；这种场景 `attach onEnter` 更省，或者把逻辑下沉到 DSL / native fast path。

### Stealth 模式

```js
hook(target, callback, Hook.NORMAL)     // 0: mprotect 直写（默认）
hook(target, callback, Hook.WXSHADOW)   // 1: 内核 shadow 页，/proc/mem 不可见
hook(target, callback, Hook.RECOMP)     // 2: 代码页重编译，仅 4B patch
hook(target, callback, 1)               // 数字也行
hook(target, callback, true)            // true = WXSHADOW
```

`--spawn-pure` 本身不依赖 WXSHADOW；WXSHADOW 是 agent 侧安装 native hook 时的 stealth patch 模式。设备内核需要支持对应 shadow 页能力，严格 stealth 场景下失败会直接返回错误，避免静默退回普通 mprotect 直写。

`Hook.WXSHADOW` 和 `Hook.RECOMP` 是按 hook 选择的两种 stealth backend，可以在同一进程里混用；不要在同一个目标地址上重复安装不同 backend。WXSHADOW 仍受同页多 hook 限制，遇到同 4KB 页多个目标时优先拆分测试或改用 RECOMP。

`Hook.RECOMP` 需要内核侧 `recompile.kpm` 已加载并能处理当前内核的 signal PC export 与 instruction abort 路径。若 KPM 未加载、符号不匹配或 dmesg 出现 signal PC export 未保护警告，RECOMP 可能只能注册映射但无法可靠重定向执行，应先修正 KPM 再测试业务 hook。

`Interceptor.attach(..., Hook.RECOMP)` 的同线程 `NativeFunction` 自测命中会跳过 JS 回调以避免 QuickJS 重入；这时 `hits=0` 但返回值正确是正常现象。恢复目标进程后，由目标 App 线程触发同一函数仍会进入 `onEnter` / `onLeave`。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `Interceptor.attach(target, {onEnter?, onLeave?}, stealth?)` | `AddressLike, Object, number?` | `InvocationListener` |
| `Interceptor.replace(target, replacement, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `Interceptor.detachAll()` | — | `undefined` |
| `listener.detach()` | — | `boolean` |
| `CModule(source, symbols?)` | `string, Object?` | `CModule` |
| `hookNative(target, callbackPtr, data?, stealth?)` | `AddressLike, NativePointer, AddressLike?, number?` | `NativePointer` trampoline |
| `attachNative(target, callbackPtr, data?, stealth?)` | `AddressLike, NativePointer, AddressLike?, number?` | `boolean` |
| `attachNative(target, {onEnter?, onLeave?, data?, mode?})` | `AddressLike, Object` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, ...AddressLike` (最多6个) | `number \| bigint` |
| `new NativeFunction(addr, retType, argTypes)` | `AddressLike, string, string[]` | `Function` (可调用，任意签名) |
| `diagAllocNear(addr)` | `AddressLike` | `undefined` |

---

## Java Hook

Frida 风格：**`this`** = 实例（静态方法时为 class 载体），**`arguments`** = Java 参数。

```js
Java.ready(function() {
    var Activity = Java.use("android.app.Activity");

    // hook 实例方法
    Activity.onResume.impl = function() {
        console.log("onResume:", this.$className);  // this = 实例 Proxy
        return this.$orig();                         // 调原方法
    };

    // hook 构造函数（参数走 arguments）
    var MyClass = Java.use("com.example.MyClass");
    MyClass.$init.impl = function(a, b) {
        console.log("new MyClass, arg0 =", a);
        return this.$orig(a, b);
    };

    // 修改参数传给原方法
    MyClass.test.impl = function(arg) {
        return this.$orig("patched_arg");
    };

    // 指定 overload（Java 类型名或 JNI 签名都行）
    MyClass.foo.overload("int", "java.lang.String").impl = function(i, s) {
        return this.$orig(i, s);
    };

    // 静态方法：this 没有实例 Proxy，但 $orig / $className / $static 可用
    Java.use("android.util.Log").i
        .overload("java.lang.String", "java.lang.String").impl = function(tag, msg) {
            console.log("[static]", this.$className, this.$static, tag, msg);
            return this.$orig(tag, msg);
        };

    // 直接返回值覆盖（不调 $orig）
    MyClass.getCount.impl = function() { return 42; };

    // 移除 hook
    Activity.onResume.impl = null;
});
```

### Java.use 对象操作

```js
var JString = Java.use("java.lang.String");
var s = JString.$new("hello");     // 创建对象
console.log(s.length());           // 调实例方法
console.log(s.$className);         // 类名

var Process = Java.use("android.os.Process");
console.log(Process.myPid());      // 调静态方法

// $new 重载（Frida 兼容 .overload(...)）
var bytes = [65, 66, 67];
var s2 = JString.$new.overload("[B")(bytes);   // String(byte[])
var s3 = JString.$new.overload("java.lang.String")("copy");  // String(String)

// 方法重载
var Arr = Java.use("java.util.Arrays");
Arr.toString.overload("[I")([1, 2, 3]);   // 锁定 int[] 版本
Arr.asList.overload("[Ljava.lang.Object;")([1, "mix", obj]);
```

### 字段访问（Frida 兼容 .value 模式）

字段通过 `.value` 读写，每次直接走 JNI，无缓存锁：

```js
// 静态字段
var Build = Java.use("android.os.Build");
console.log(Build.MODEL.value);          // 读: "Pixel 6"
Build.MODEL.value = "FakeModel";         // 写

// 实例字段（hook 回调中 / $new 创建的对象）
var Point = Java.use("android.graphics.Point");
var p = Point.$new(10, 20);
console.log(p.x.value, p.y.value);      // 读: 10, 20
p.x.value = 100;                         // 写: JVM 同步更新
console.log(p.toString());               // "Point(100, 20)"

// hook 中访问 this 字段
Activity.onResume.impl = function() {
    var name = this.mComponent.value;   // 读实例字段
    console.log("resuming:", name);
    return this.$orig();
};
```

**字段/方法同名**：Java 允许同名字段和方法共存。此时返回 hybrid——既可调用（方法）又有 `.value`（字段）：

```js
var map = HashMap.$new();
map.size();        // 调用 size() 方法
map.size.value;    // 读取 size 字段
```

### Java.ready

Spawn 模式下 app ClassLoader 未就绪，用 `Java.ready` 延迟执行。PID 注入模式下立即执行。

### Managed DSL 高频 Hook

DSL 是为应对高频 Java hook 开发的小型 JS-Java 动态编译器。普通 `Java.use().impl = function (...) { ... }` 每次命中都会进入 JS runtime；DSL 会把受限的 JS/Java 风格代码编译成 dex callback，让热路径在 ART/Java 侧执行，适合任何被高频调用的java方法。DSL 后续会继续优化语法、类型推断和可用能力。

#### 什么时候用 DSL

| 场景 | 建议 |
| --- | --- |
| 低频、调试、需要 JS 对象/闭包/console | 用 `impl` |
| 高频、只做判断/改参数/改返回/计数 | 用 DSL |
| 高频里需要少量数据回 JS | DSL 里 `send()`，JS 侧低频 `dslRead()` / `dslDrain()` |
| 逻辑还不稳定 | 先用 JS callback 探路，稳定后搬到 DSL |

DSL 语法接近 JS/Java，但不是完整 JS runtime。它不能访问 JS 变量、闭包、`console.log`、`setInterval`、Promise。把它理解成“写在 JS 字符串里的 Java 热路径代码”更准确。

#### 最推荐写法

```js
Java.ready(function () {
    var HashMap = Java.use("java.util.HashMap");

    HashMap.put
        .overload("java.lang.Object", "java.lang.Object")
        .dsl({ buff: 4096 })       // 可选。默认 4096，必须是 2 的幂，最大 1048576
        .dslImpl = `
            count("put");

            let n: int = this.size();
            let has: boolean = this.containsKey(arg0);
            let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);

            if ((n & 1023) == 0) {
                send("size", n);
            }

            if (has && selected != null) {
                java.lang.String.valueOf(selected);
            }

            return orig(arg0, arg1);
        `;

    // JS 侧低频拉取 DSL 发出的消息。不要在 DSL 热路径里 print 或进 JS。
    var drained = HashMap.put.dslRead(64);
    for (var i = 0; i < drained.length; i++) {
        var m = drained[i];        // { name: "size", value: 123, code: 1 }
        console.log(m.name, m.value);
    }
});
```

#### 不指定 overload

```js
HashMap.put.dslImpl = `
    count("put");
    return orig();
`;
```

不指定 overload 时，会把同一段 DSL 批量安装到该方法名的全部 overload。适合 DSL 只用 `orig()`、`count()` 这类不依赖具体参数签名的场景。

如果 DSL 里使用了固定参数数量、固定返回类型、某个特定字段/方法调用，建议显式 `.overload(...)`，错误信息也会更直接。

#### DSL 内置名字

| 名称 | 含义 |
| --- | --- |
| `this` | 实例方法的当前对象；静态方法中没有普通实例 |
| `arg0`, `arg1`, ... | Java 方法参数 |
| `orig()` / `orig(a, b, ...)` | 调原方法；可放在任意位置 |
| `last` | 上一条对象表达式语句的结果 |
| `result` | 部分调用/字段访问结果的临时目标；通常优先用局部变量接住 |

常见返回方式：

```js
return orig();             // 原参数调用原方法
return orig(arg0, arg1);   // 改参数后调用原方法
return null;               // 对象返回值可返回 null
return 0;                  // int/boolean 等按目标返回类型校验
return;                    // void 方法
```

#### 变量和类型

类型能推断时可以省略，但高频 hook 里建议复杂对象写清类型，方便 overload 推断和 dex 校验。

```js
let n: int = this.size();
let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);
let text: java.lang.String = java.lang.String.valueOf(selected);

let obj: java.lang.Object;    // 无初始化时必须写类型，默认 null/0/false
let asObj: java.lang.Object = text as java.lang.Object;
```

`let` / `var` 当前都按块作用域处理。

#### 方法调用

```js
let n: int = this.size();                         // 实例方法
let s: java.lang.String = java.lang.String.valueOf(arg0); // 静态方法
```

overload 能唯一推断时直接写 `obj.method(arg)`。报歧义时显式指定：

```js
this.get.overload("java.lang.Object")(arg0);
java.lang.String.valueOf.overload("java.lang.Object")(arg0);
```

接口接收者通常会自动走 interface 调用。推断不出来时显式写：

```js
it.hasNext.interface.overload("java.util.Iterator", "()Z")();
```

#### 字段访问

字段用 Java 原生风格写：无括号是字段，有括号是方法。

```js
let v: int = this.someField;
this.someField = 123;
this.someField += 1;
this.someField++;

let name: java.lang.String = com.example.Config.name;
com.example.Config.name = "patched";
```

字段按 Java 访问逻辑解析：从接收者静态类型开始查找，子类字段隐藏父类同名字段时优先子类；如果局部变量声明成父类类型，就访问父类字段。

#### 创建对象和数组

构造函数按普通 Java/JS 直觉写，参数类型会自动推断并选择唯一匹配的 constructor overload：

```js
let sb: java.lang.StringBuilder = new java.lang.StringBuilder("hi");
let copy: java.lang.StringBuilder = java.lang.StringBuilder.$new(sb);
let list: java.util.ArrayList = new java.util.ArrayList();
```

如果构造 overload 歧义，才把完整 JNI 构造签名放在第一个参数：

```js
let sb: java.lang.StringBuilder = new java.lang.StringBuilder("(Ljava/lang/String;)V", "hi");
```

数组：

```js
let arr: int[] = new int[4];
arr[0] = 7;
arr[0]++;

let objs: java.lang.Object[] = [arg0, arg1, null];
let first: java.lang.Object = objs[0];
let len: int = objs.length;
```

#### 条件和控制流

条件、三元、循环按 JS/Java 直觉写即可。几个差异点：

- 可能为 null 的对象必须先保护：`obj != null && obj.method()`。
- `switch case` 需要用 `{ ... }` 包住语句块。
- `try` 支持 `catch`，暂不支持 `finally`。
- 整数字面量当前按 int16 解析；较大常量建议通过 Java 字段/方法或计算得到。

```js
if (arg0 != null && this.containsKey(arg0)) {
    count("hit");
}

let selected: java.lang.Object = (arg0 != null ? arg0 : arg1);

if ((this.size() & 1023) == 0) {
    send("size", this.size());
}

switch (this.size()) {
    case 0: { return orig(arg0, arg1); }
    default: { count("nonzero"); }
}

try {
    java.lang.String.valueOf(arg0);
} catch (java.lang.Throwable e) {
    return orig(arg0, arg1);
}
```

#### DSL 和外部通信

`count("name")` 是热路径计数器，适合确认 DSL 是否命中。

DSL 热路径不会直接回调 JS，也不会直接和 host 通信。`count()` 和 `send()` 都编译进生成的 dex helper：

- `count("name")` 更新 helper 类里的 `static volatile int` 计数器。
- `send("channel", value)` 把消息写入 helper 类里的固定大小环形缓冲区。
- JS 侧在低频位置主动拉取这些数据，再用 `console.log`、RPC 或脚本逻辑发给外部。

这意味着高频命中时不会进入 QuickJS runtime；外部通信是“热路径写缓冲区，冷路径批量读取”的模型。

JS 侧有三层读取 API：

| API | 用途 |
| --- | --- |
| `method.dslRead(max)` | 推荐封装，返回 `{ code, name, value }` 数组 |
| `method.dslTake(name, max)` | 只读取某个 channel，返回 value 数组 |
| `method.dslDrain(max)` | 读取原始消息数组，不补 channel name |
| `Java.managedDrainMessages(info, max)` | 底层 API，直接按 `dslInfo` drain |

示例：

```js
// DSL
send("size", this.size());
send("text", java.lang.String.valueOf(arg0));

// JS
var items = HashMap.put.dslRead(128);
items.forEach(function (m) {
    if (m.name === "size") console.log("size =", m.value);
    if (m.name === "text") console.log("text =", m.value);
});

// 只取某个通道，直接拿 value 数组
var sizes = HashMap.put.dslTake("size", 128);

// 底层读取接口；info 可以是 method.dslInfo 或 Java.managedHookDsl(...) 的返回值
var raw = Java.managedDrainMessages(HashMap.put.dslInfo, 128);
```

限制：

- `send()` 的值只能是 `int` 或 `java.lang.String`。
- `buff` 是环形缓冲区容量，默认 `4096`，必须是 2 的幂，最大 `1048576`。
- 缓冲区满时会丢弃新的消息并增加 `dropped` 计数，热路径不会阻塞。
- `Java.managedDrainMessages()` 返回的数组带有 `head`、`tail`、`dropped`、`capacity` 属性；`dslRead()` 会补上 channel name。
- 高频方法里不要每次都 `send()`，除非你明确能接受缓冲区覆盖。需要完整流量时应把逻辑放在 DSL 内完成，只低频上报结果。

#### 调试和排错

确认 DSL 是否安装成功：

```js
console.log(JSON.stringify(HashMap.put.dslInfo));
```

常见错误：

| 错误/现象 | 处理 |
| --- | --- |
| `receiver ... may be null` | 加 `obj != null && obj.method()` |
| overload 歧义 | 写 `.overload(...)`，或给局部变量补类型 |
| 字段解析失败 | 确认接收者静态类型、字段名和 static/instance 用法 |
| `send() value must be int or java.lang.String` | 先 `String.valueOf(obj)` 或只发 int |
| 不指定 overload 后某个签名安装失败 | 改成显式 `.overload(...)` 分签名安装 |
| 想在 DSL 里 `console.log` | 不支持；用 `count()` / `send()` |

#### 高频写法

- 尽量让 DSL 内部完成判断、计数、返回值修改，只把摘要通过 `send()` 发给 JS。
- 不要把每次命中的完整数据都发回 JS；这会把问题重新变成跨 runtime 压力。
- 不要在 DSL 中做无界循环、阻塞等待、频繁分配大对象。
- 复杂对象、复杂返回值优先写清类型。
- 需要 hook 复杂业务对象时，先用 JS callback 探路，稳定后把热路径搬到 DSL。

### Java.choose 枚举存活实例（Frida 兼容）

扫描 ART 堆，把目标类的所有存活实例交给 `onMatch`：

```js
Java.choose("android.app.Activity", {
    onMatch: function(instance) {
        console.log(instance.$className, "=>", instance.toString());
        // return "stop";   // 提前终止
    },
    onComplete: function() { console.log("done"); },
    subtypes: true,         // 包含子类（rustFrida 扩展）
    maxCount: 1000          // 最多枚举数量，默认 16384；0 = 不限
});

// 第三参等价 subtypes（位置参数形式）
Java.choose("java.util.List", { onMatch: fn }, true);
```

**生命周期**：传给 `onMatch` 的 wrapper **仅在 onMatch 执行期间有效**。函数返回后 `__jptr` 被置 0。若要跨回调保留实例，请在 `onMatch` 内调 `String(obj.method())` 拷字段，或自行 `NewGlobalRef`。

**后端**：Android ≤13 走 `VMDebug.getInstancesOfClasses`；API 36 自动降级为堆暴力扫描。

### ClassLoader 控制

```js
var loaders = Java.classLoaders();             // → 数组: app + boot + system
Java.setClassLoader(loaders[0]);               // 切换 Java.use() 查找上下文
var MyCls = Java.findClassWithLoader(loaders[0], "com.example.MyClass");
```

`loader` 参数接受 loader 对象、`{__jptr}` wrapper 或 `NativePointer`。Spawn 模式下 app loader 就绪前 `Java.classLoaders()` 可能只返回 boot loader，应在 `Java.ready()` 里调。

### Stealth 模式（Java hook）

```js
Java.setStealth(0);  // Normal: mprotect 直写
Java.setStealth(1);  // WxShadow: shadow 页，CRC 校验不可见
Java.setStealth(2);  // Recomp: 代码页重编译
Java.getStealth();   // 查询当前模式 (0/1/2)
```

须在 `Java.use().impl` 之前设置。

### Deopt API

```js
Java.deopt();                  // 清空 JIT 缓存（InvalidateAllMethods）
Java.deoptimizeBootImage();    // boot image AOT 降级为 interpreter (API >= 26)
Java.deoptimizeEverything();   // 全局强制解释执行
Java.deoptimizeMethod("com.example.Test", "foo", "(I)V");  // 单方法降级
```

手动调用的工具函数，hook 流程不自动使用。

### 类型 Marshal 规则（Java ↔ JS 自动转换）

Hook 回调的 `arguments`、`$orig()` / `Class.method()` 返回值、字段 `.value` 读写、`Java.choose` 的 `onMatch` 参数都走同一套 marshal 规则。

#### Java → JS（参数 / 返回值 / 字段读）

**自动转换为原生 JS 值：**

| Java 类型 | JNI 签名 | JS 值 | 说明 |
| --- | --- | --- | --- |
| `boolean` | `Z` | `boolean` | |
| `byte` | `B` | `number` | 有符号 i8 |
| `char` | `C` | `string` | 长度为 1 的字符串 |
| `short` | `S` | `number` | i16 |
| `int` | `I` | `number` | i32 |
| `long` | `J` | `BigInt` | u64 |
| `float` | `F` | `number` | |
| `double` | `D` | `number` | |
| `java.lang.String` | `Ljava/lang/String;` | `string` | 走 `GetStringUTFChars` |
| `null` | — | `null` | |
| Java 原始类型数组 `T[]`（T 为 Z/B/C/S/I/J/F/D）| `[T` | `Array` of 对应 JS 值 | 一次 `GetXxxArrayRegion` 批量拷贝，无装箱 |
| Java 对象数组 `T[]` | `[LT;` | `Array` of wrapper（或 `string` 若 T=`String`）| 逐个 `GetObjectArrayElement` |
| Java 嵌套数组 `[[...` | `[[X` | `Array` of Array（递归 marshal）| 深度不限 |

**保留为 Java wrapper `{__jptr, __jclass}`（不自动转换，需手动处理）：**

- **装箱类型 NOT unboxed**：`Integer` / `Long` / `Float` / `Double` / `Boolean` / `Byte` / `Short` / `Character` 全部返回 wrapper，**不会**自动变成 JS number/boolean。需要原始值手动转：
  ```js
  var n = boxed.intValue();              // Integer → int
  var d = boxed.doubleValue();           // Double → number
  var s = String(boxed);                 // 走 toString
  ```
- **容器不展开**：`List` / `Map` / `Set` / `ArrayList` / `HashMap` 等保留 wrapper，手动遍历：
  ```js
  var list = obj.getList();
  for (var i = 0; i < list.size(); i++) {
      var item = list.get(i);            // 仍是 wrapper（除非是 String）
  }
  var keys = map.keySet().toArray();     // → JS Array of wrappers
  ```
- **其他任意对象类型**：用户类、`Context`、`Activity`、`File` 等一律 wrapper，通过 `.method()` / `.field.value` 链式访问。

**`$new` 强制 wrapper 特例**：`Java.use("java.lang.String").$new("hi")` 即使构造出 String 也保留为 wrapper（便于链式 `.length()` / `.charAt()`）——这是唯一跳过 String → JS string 自动转换的场景。

#### JS → Java（`$orig(args)` / `Class.method(args)` / 字段写 / `$new(args)`）

按目标参数的 JNI 签名 marshal：

| 目标签名 | 接受的 JS 值 |
| --- | --- |
| `Z` | `boolean` / `number`（非零即 true）|
| `B` / `S` / `I` / `J` | `number` / `BigInt` |
| `C` | `string`（取首字符）/ `number` |
| `F` / `D` | `number` |
| `Ljava/lang/String;` 或任意 `L...;` 场景下的 JS string | → `NewStringUTF` |
| 任意 `L...;`（已是 Java 对象）| `{__jptr}` wrapper / `Proxy` → 提取原始 jobject 指针 |
| 装箱类型 `Ljava/lang/Integer;` 等 | JS number/boolean/bigint 走 **autobox**（JNI `Xxx.valueOf()`）|
| `[B` / `[Z` / `[C` / `[S` / `[I` / `[J` / `[F` / `[D` | JS `Array` → `NewXxxArray + SetXxxArrayRegion` 批量填 |
| `[Ljava/lang/String;` | JS `Array` of string → 逐个 `NewStringUTF + SetObjectArrayElement` |
| `[Lxxx;` 任意引用数组 | 每个元素按 `Lxxx;` 递归 marshal（string / Proxy `__jptr` / autobox）|
| `[[X` / `[[Lxxx;` 嵌套数组 | 递归进入 `[X` 分支创建内层 Java 数组 |
| `Ljava/lang/Object;` / `Ljava/io/Serializable;` + JS Array | 自动降级 `Object[]`（元素按 `Ljava/lang/Object;` 再 marshal）|
| 任意类型 | `null` / `undefined` → JNI null (0) |

**autobox 规则**：目标签名精确匹配时按目标类型装箱（`Ljava/lang/Long;` → `Long.valueOf(J)`）；无精确签名时按 JS 值推断 —— 整数 fit i32 → `Integer`，否则 → `Double`；boolean → `Boolean`。

**多 overload 自动消歧（数组按元素范围打分）**：

```js
void foo(byte[] b)
void foo(int[] i)
void foo(long[] l)
```

| JS 输入 | `[B` 分 | `[S` 分 | `[I` 分 | `[J` 分 | 选中 |
| --- | --- | --- | --- | --- | --- |
| `[1, 2, 3]`（都在 byte 范围）| **10** | 9 | 8 | 7 | `byte[]` |
| `[1, 200, 3]`（溢出 byte，在 short）| -1 | **9** | 8 | 7 | `short[]` |
| `[1, 100000]`（溢出 short，在 int）| -1 | -1 | **8** | 7 | `int[]` |
| `[5000000000]`（溢出 int）| -1 | -1 | -1 | **7** | `long[]` |
| `[1n, 2n]`（全 BigInt）| -1 | -1 | -1 | **10** | `long[]` |
| `[true, false]` | -1 | -1 | -1 | -1 | `boolean[]` |
| `[1.5, 2.5]` | -1 | -1 | -1 | -1 | `float[]` / `double[]` |

手动覆写用 `.overload(sig)`：

```js
obj.foo.overload("[I")([1, 2, 3]);    // 强制 int[]（否则自动选 byte[]）
obj.foo.overload("[B")([1, 200, 3]);  // 强制 byte[]，200 按位截断为 -56
```

**常见陷阱：**

- 传普通 JS object（非 wrapper、无 `__jptr`）给非数组 `L...;` 参数会 marshal 成 0 → Java 侧 NPE。
- 传 `undefined` 等同 `null`，别依赖默认行为——显式写 `null`。
- `Map.put(Object, Object)` 传 `number` 会被 autobox 成 `Integer` / `Double`，取出来**仍是 wrapper**，要 `.intValue()` 才能拿回 JS number。
- JS string 会为**所有** `L...;` 目标类型创建 `java.lang.String`（即使签名是 `Ljava/lang/Object;`），不会抛类型错误。
- 强制 `.overload("[B")` 传入越界元素（如 200）按 `as i8` **按位截断**，不报错（和 Frida 一致）。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意 | `JavaObjectProxy` |
| `Class.method.impl = fn` | `function(...args) { this.$orig(...) }`（this = 实例/static 载体） | setter |
| `Class.method.impl = null` | — | setter |
| `Class.method.overload(...types)` | `string...` | `MethodWrapper` |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.choose(cls, callbacks, subtypes?)` | `string, {onMatch,onComplete?,subtypes?,maxCount?}, bool?` | `void` |
| `Java.classLoaders()` | — | `LoaderInfo[]` |
| `Java.findClassWithLoader(loader, cls)` | `Loader, string` | `JavaClassWrapper` |
| `Java.setClassLoader(loader)` | `Loader` | — |
| `Java.deopt()` | — | `boolean` |
| `Java.deoptimizeBootImage()` | — | `boolean` |
| `Java.deoptimizeEverything()` | — | `boolean` |
| `Java.deoptimizeMethod(cls, method, sig)` | `string, string, string` | `boolean` |
| `Java.setStealth(mode)` | `number (0/1/2)` | — |
| `Java.getStealth()` | — | `number` |
| `obj.field.value` | — | `any` (读字段) |
| `obj.field.value = x` | — | — (写字段) |
| `Java.getField(objPtr, cls, field, sig)` | `AddressLike, string, string, string` | `any` (低层 API) |

---

## JNI API

```js
Jni.addr("RegisterNatives")       // → NativePointer
Jni.FindClass                     // 属性直接取地址
Jni.find("FindClass")             // → { name, index, address }
Jni.table                         // 整张 JNI 函数表
Jni.addr(envPtr, "FindClass")     // 指定 JNIEnv
```

### Jni.env / Jni.structs

```js
Jni.env.ptr                         // 当前线程 JNIEnv*
Jni.env.getClassName(jclass)        // → "android.app.Activity"
Jni.env.getObjectClassName(jobject) // → 对象的类名
Jni.env.readJString(jstring)        // → JS string
Jni.env.getObjectClass(obj)         // → jclass
Jni.env.getSuperclass(clazz)        // → jclass (Object 返 null)
Jni.env.isSameObject(a, b)          // → boolean
Jni.env.isInstanceOf(obj, clazz)    // → boolean
Jni.env.exceptionCheck()            // → boolean
Jni.env.exceptionClear()
Jni.env.exceptionOccurred()         // → jthrowable | null

// 构造/引用 (Rust 直路, 不走 callNative → dladdr, hook context 内安全)
Jni.env.findClass("java/lang/String") // → jclass | null
Jni.env.newStringUtf("hello")         // → jstring | null
Jni.env.newLocalRef(obj)              // → jobject | null
Jni.env.deleteLocalRef(obj)           // → undefined

Jni.structs.JNINativeMethod.readArray(addr, count)  // → JNINativeMethodInfo[]
Jni.structs.jvalue.readArray(addr, typesOrSig)      // → any[]
```

**ref API 都接受**：`NativePointer` / BigInt / 十六进制字符串 / `{__jptr: ...}` wrapper。**所有方法都接受可选 env 首参**：`Jni.env.findClass(envPtr, "java/lang/String")`，省略则走 `ensure_jni_initialized` 自动 attach 当前线程。所有 JNI 调用失败后异常被兜底 clear，不会串到下一次调用。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.entries()` | — | `JniEntry[]` |
| `Jni.table` | — | `Record<string, JniEntry>` |
| `Jni.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.env.findClass(name)` | `string` | `NativePointer \| null` |
| `Jni.env.newStringUtf(str)` | `string` | `NativePointer \| null` |
| `Jni.env.newLocalRef(obj)` | `AddressLike` | `NativePointer \| null` |
| `Jni.env.deleteLocalRef(obj)` | `AddressLike` | `true` |
| `Jni.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |

### 实战：监控 RegisterNatives

```js
Interceptor.attach(Jni.addr("RegisterNatives"), {
    onEnter(args) {
        var cls = Jni.env.getClassName(args[1]);
        var n = Number(args[3]);
        console.log(cls + " (" + n + " methods)");

        var methods = Jni.structs.JNINativeMethod.readArray(args[2], n);
        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            var mod = Module.findByAddress(m.fnPtr);
            var where = mod === null ? m.fnPtr.toString() : mod.name + "+" + m.fnPtr.sub(mod.base);
            console.log("  " + (m.name || "<null>") + " " + (m.sig || "<null>") + " → " + where);
        }
    }
}, Hook.WXSHADOW);
```

---

## Memory

**双风格 Frida 兼容**：`Memory.readXxx(addr)` ≡ `addr.readXxx()`，所有 read/write 方法同时挂在 `Memory` 和 `NativePointer.prototype` 上。

```js
// Memory.* 风格
var pid = Memory.readU32(ptr("0x7f1234"));
Memory.writeU64(dst, 0xdeadbeefn);
var cls = Memory.readCString(ptr(this.x1));

// ptr.* 风格（推荐，支持链式）
var p = ptr("0x7f1234");
p.readU32();
p.writeU64(0xdeadbeefn);
p.add(8).readPointer().readCString();     // 解指针再读字符串
p.add(0x10).readByteArray(32);            // → ArrayBuffer

// 写入代码后刷 I-cache；若后续要执行这块内存，先按需 Memory.protect(code, size, "rwx")
var code = Memory.alloc(16);
code.writeU32(0xd65f03c0);                // ret
Memory.flushCodeCache(code, 16);
```

| API | 参数 | 返回 |
| --- | --- | --- |
| **读** | | |
| `Memory.readU8/U16(addr)` / `p.readU8/U16()` | `AddressLike` | `number` |
| `Memory.readU32/U64(addr)` / `p.readU32/U64()` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` / `p.readPointer()` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` / `p.readCString()` | `AddressLike` | `string` (最多 4096B) |
| `Memory.readUtf8String(addr)` / `p.readUtf8String()` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` / `p.readByteArray(len)` | `AddressLike, number` | `ArrayBuffer` (≤1GB) |
| **写** | | |
| `Memory.writeU8/U16/U32(addr, v)` / `p.writeU8/U16/U32(v)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, v)` / `p.writeU64(v)` | `AddressLike, bigint` | `undefined` |
| `Memory.writePointer(addr, v)` / `p.writePointer(v)` | `AddressLike, AddressLike` | `undefined` |
| `Memory.writeBytes(addr, bytes, stealth?)` / `p.writeBytes(bytes, stealth?)` | `AddressLike, ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `Memory.writest(addr, bytes)` / `p.writest(bytes)` | `AddressLike, 4B 倍数指令字节` | `undefined` |
| **分配 / 维护** | | |
| `Memory.alloc(size)` | `number` (≤ 256MB) | `NativePointer` (普通 heap RW，零初始化) |
| `Memory.allocUtf8String(s)` | `string` | `NativePointer` (普通 heap RW，末尾 `\0`) |
| `Memory.flushCodeCache(addr, size)` | `AddressLike, number` | `undefined` |
| `Memory.protect(addr, size, prot)` | `AddressLike, number, "rwx" 风格` | `boolean` |

**约束**：
- 无效地址抛 `RangeError`；`readCString` 超过 4096B 抛
- `Memory.alloc` / `Memory.allocUtf8String` 是普通 heap 分配，GC 时自动释放；勿 `munmap`
- 写入代码后必须 `Memory.flushCodeCache` 刷 I-cache
- `writeXxx` 和 `writeBytes(bytes, 0)` 不会自动 mprotect；写入范围必须完整落在可写 VMA 中，只读段写入会抛错，需先 `Memory.protect`

### Memory.protect / writeBytes / writest

| API | 适用段 | read 可见 | 用途 |
| --- | --- | --- | --- |
| `Memory.protect(addr, size, "rwx")` | 任意 | — | 改页权限（页级 mprotect） |
| `p.writeBytes(bytes, 0)` 默认 | 可写段 | 可见 | 覆盖 N 字节（数据/结构体） |
| `p.writeBytes(bytes, 1)` | r-x | 不可见 | wxshadow 覆盖 N 字节（短 patch，最多跨 2 页） |
| `p.writest(bytes)` | r-x | 不可见 | 1 条指令 → N 条指令替换（PC-rel 自动 relocate） |

`writeBytes(bytes, 1)` 由 wxshadow KPM 在内核侧完成 dcache/icache 维护；用户态不要再对 execute-only shadow 映射补做 clear-cache，否则部分内核会在 fault path 中卡住。

`unhook(addr)` 统一清理 hook / writest / writeBytes(1) 留下的 patch。

```js
var addr = Module.findExportByName("libc.so", "getpid");

// 隐身短 patch: getpid() → 42, readByteArray 仍看原字节
addr.writeBytes(new Uint8Array([0x40,0x05,0x80,0xd2, 0xc0,0x03,0x5f,0xd6]), 1);

// 指令级替换: 原第一条指令被这 3 条顶替, 原第二条及以后保留
addr.writest(new Uint8Array([
    0x80,0x46,0x82,0x52,  // MOVZ W0, #0x1234
    0xa0,0x79,0xb5,0x72,  // MOVK W0, #0xABCD, LSL #16
    0xc0,0x03,0x5f,0xd6,  // RET
]));

// 写数据段: 先开写权限
Memory.protect(dataAddr, 8, "rwx");
dataAddr.writeU64(0xdeadbeefn);
Memory.protect(dataAddr, 8, "r--");
```

**writest 细节**：patch 不带 RET/B 时末尾自动 fall-through 到 `addr+4`；`ADR/ADRP/BL/LDR literal/CBZ/TBZ/B.cond` 自动 relocate；patch 内部分支 ≤64 条指令有效；同地址重装需先 `unhook`。

## Module

| API | 参数 | 返回 |
| --- | --- | --- |
| `Module.findExportByName(module, symbol)` | `string, string` | `NativePointer \| null` |
| `Module.findBaseAddress(module)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | — | `ModuleInfo[]` |
| `Module.enumerateExports(name)` | `string` | `{type, name, address}[]` |
| `Module.enumerateImports(name)` | `string` | `{type, name, slot, address}[]` |
| `Module.enumerateSymbols(name)` | `string` | `{type, name, address, isGlobal, isDefined}[]` |
| `Module.enumerateRanges(name, prot?)` | `string, "rwx" 风格` | `{base, size, protection, file:{path}}[]` |
| `Module.load(path, flagsOrTagged?, tagged?)` | `string, int\|bool?, bool?` | `ModuleInfo` / 抛异常 |

```js
// 导出：defined + global/weak 符号
Module.enumerateExports("libc.so").slice(0, 3);
// [{type:"function", name:"__cxa_finalize", address:"0x7200f0e0a0"}, ...]

// 按内存权限过滤 (prot 里 '-' 是通配, "r-x" 会匹配 r-x 和 rwx)
Module.enumerateRanges("libc.so", "r-x");

// 外部引用符号 + PLT/GOT slot 地址
Module.enumerateImports("libart.so").filter(i => i.type === "function");
```

枚举的来源是模块的磁盘 ELF；memfd 或无文件支撑的合成模块返回空数组。

### Module.load — 运行时加载 SO

默认走 unrestricted linker (`__loader_dlopen`)，绕开 namespace 限制 + `hide_soinfo` 的 caller 解析问题。加载成功后从 `/proc/self/maps` 解析 `{name, base, size, path}` 返回；失败抛带 `dlerror` 原始消息的 `InternalError`。

第三个参数或第二个布尔参数为 `true` 时，先把 SO 读入 `memfd_create("wwb_<basename>")`，再用 `android_dlopen_ext` 的 `library_fd` 加载。这样 `/proc/<pid>/maps` 中会出现 `wwb_` 标记；默认或显式 `false` 保持普通路径加载。

```js
// 短名：走 linker 搜索路径
var m = Module.load("libz.so");
// { name: "libz.so", base: 0x7062dec000, size: 110592, path: "/vendor/lib64/libz.so" }

// 绝对路径
Module.load("/system/lib64/libsqlite.so");

// 自定义 flags（默认 RTLD_NOW = 2；RTLD_LAZY = 1）
Module.load("/data/local/tmp/mylib.so", 1);

// 显式普通加载：maps 中保留真实文件路径
Module.load("/data/local/tmp/mylib.so", false);

// tagged 加载：maps 中显示 /memfd:wwb_mylib.so (deleted)
Module.load("/data/local/tmp/mylib.so", true);
Module.load("/data/local/tmp/mylib.so", 2, true);

// 错误处理
try {
    Module.load("/does/not/exist.so");
} catch (e) {
    console.log(e.message);
    // → "Module.load: dlopen('/does/not/exist.so') failed: library \"...\" not found"
}

// 加载后立刻查符号
var m = Module.load("libcustom.so");
var addr = Module.findExportByName(m.name, "my_func");
```

**注意**：
- tagged/memfd 加载会改变模块在 maps 和 `dladdr()` 等路径视角下的名字，适合需要 `wwb_` 标记的场景；依赖真实文件路径自检的 SO 建议用默认加载。
- 若模块被 `hide_soinfo` 隐藏或 maps 聚合失败，返回 `{name, path, base: <dlopen handle>, size: 0}` 作 fallback。
- `Module.load` 不会重复加载同一个 SO — linker 对已加载模块返回现有 handle。

## ptr / NativePointer

```js
var p = ptr("0x7f12345678");   // hex string / number / BigInt / NativePointer
p.add(0x100).sub(0x10);        // 算术，返回新 NativePointer
p.toString();                  // → "0x7f12345678"
p.toInt();                     // → bigint (等价 toNumber)

// Frida 兼容读写（完整 API 见上面 Memory 章节）
p.readU32();                   // 等价 Memory.readU32(p)
p.writeU64(0xdeadbeefn);       // 等价 Memory.writeU64(p, ...)，目标范围必须可写
p.readPointer().readCString(); // 链式解引用
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` / `p.sub(offset)` | `AddressLike` | `NativePointer` |
| `p.toString()` / `p.toJSON()` | — | `string` (`"0x..."`) |
| `p.toNumber()` / `p.toInt()` | — | `bigint` |
| `p.readU8/U16/U32/U64/Pointer()` | — | `number \| bigint \| NativePointer` |
| `p.readCString()` / `p.readUtf8String()` | — | `string` |
| `p.readByteArray(len)` | `number` | `ArrayBuffer` |
| `p.writeU8/U16/U32/U64/Pointer(val)` | 值 | `undefined` |
| `p.writeBytes(bytes, stealth?)` | `ArrayBuffer\|TypedArray\|number[], 0\|1` | `undefined` |
| `p.writest(bytes)` | `ArrayBuffer\|TypedArray\|number[]` (4B 倍数) | `undefined` |

所有读写方法的语义、错误处理、i-cache 约束与 `Memory.*` 完全一致；`writeBytes` / `writest` 的行为见 Memory 章节的表格。

## console

`console.log(...)` / `console.info(...)` / `console.warn(...)` / `console.error(...)` / `console.debug(...)`

## File

Frida 兼容的同步文件 API。适合在 agent 内直接读写目标进程可访问的路径；`new File()` 底层按 `fopen()` 的 mode 字符串打开，GC 时会自动关闭，但长脚本建议显式 `close()`。

```js
// 静态读写
File.writeAllText("/data/local/tmp/demo.txt", "hello\n");
var text = File.readAllText("/data/local/tmp/demo.txt");

var bytes = new Uint8Array([0x41, 0x42, 0x43]).buffer;
File.writeAllBytes("/data/local/tmp/demo.bin", bytes);
var roundtrip = File.readAllBytes("/data/local/tmp/demo.bin");

// 流式读写
var f = new File("/data/local/tmp/demo.txt", "rb");
console.log(f.readLine());          // 保留行尾 \n，和 Frida 一致
console.log(f.tell());
f.seek(0, File.SEEK_SET);
console.log(f.readText(5));
f.close();

var out = new File("/data/local/tmp/out.bin", "wb");
out.write(roundtrip);               // string / ArrayBuffer / TypedArray / number[]
out.flush();
out.close();
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `File.readAllBytes(path)` | `string` | `ArrayBuffer` |
| `File.readAllText(path)` | `string` | `string` (UTF-8) |
| `File.writeAllBytes(path, data)` | `string, ArrayBuffer\|TypedArray\|number[]` | `undefined` |
| `File.writeAllText(path, text)` | `string, string` | `undefined` |
| `new File(path, mode)` | `string, string` | `File` |
| `file.tell()` | — | `number` |
| `file.seek(offset, whence?)` | `number, File.SEEK_*?` | `number` (`fseek` 结果) |
| `file.readBytes(size?)` | `number?` | `ArrayBuffer` |
| `file.readText(size?)` | `number?` | `string` (UTF-8) |
| `file.readLine()` | — | `string` |
| `file.write(data)` | `string\|ArrayBuffer\|TypedArray\|number[]` | `undefined` |
| `file.flush()` | — | `undefined` |
| `file.close()` | — | `undefined` |

常量：`File.SEEK_SET`、`File.SEEK_CUR`、`File.SEEK_END`。

## QBDI Trace

| API | 参数 | 返回 |
| --- | --- | --- |
| `qbdi.newVM()` | — | `number \| bigint \| null` |
| `qbdi.destroyVM(vm)` | `number \| bigint` | `boolean` |
| `qbdi.addInstrumentedModule(vm, name)` | `number \| bigint, string` | `boolean` |
| `qbdi.addInstrumentedModuleFromAddr(vm, addr)` | `number \| bigint, AddressLike` | `boolean` |
| `qbdi.instrumentAllExecutableMaps(vm)` | `number \| bigint` | `boolean` |
| `qbdi.addInstrumentedRange(vm, start, end)` | `number \| bigint, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeInstrumentedRange(vm, start, end)` | `number \| bigint, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeAllInstrumentedRanges(vm)` | `number \| bigint` | `boolean` |
| `qbdi.deleteAllInstrumentations(vm)` | `number \| bigint` | `boolean` |
| `qbdi.recordMemoryAccess(vm, flags)` | `number \| bigint, qbdi.MEMORY_*` | `boolean` |
| `qbdi.allocateVirtualStack(vm, size)` | `number \| bigint, number` | `boolean` |
| `qbdi.clearVirtualStacks(vm)` | `number \| bigint` | `boolean` |
| `qbdi.simulateCall(vm, retAddr, ...args)` | `number \| bigint, AddressLike, ...AddressLike` | `boolean` |
| `qbdi.call(vm, target, ...args)` | `number \| bigint, AddressLike, ...AddressLike` | `number \| bigint \| null` |
| `qbdi.switchStackAndCall(vm, target, stackSize, ...args)` | `number \| bigint, AddressLike, number, ...AddressLike` | `number \| bigint \| null` |
| `qbdi.run(vm, start, stop)` | `number \| bigint, AddressLike, AddressLike` | `boolean` |
| `qbdi.getGPR(vm, reg)` | `number \| bigint, number` | `number \| bigint \| null` |
| `qbdi.setGPR(vm, reg, value)` | `number \| bigint, number, AddressLike` | `boolean` |
| `qbdi.getFPR(vm, reg)` | `number \| bigint, number` | `{lo, hi} \| null` |
| `qbdi.setFPR(vm, reg, lo, hi)` | `number \| bigint, number, AddressLike, AddressLike` | `boolean` |
| `qbdi.getErrno(vm)` | `number \| bigint` | `number \| null` |
| `qbdi.setErrno(vm, value)` | `number \| bigint, number` | `boolean` |
| `qbdi.setTraceBundleMetadata(modulePath, moduleBase)` | `string, AddressLike` | `boolean` |
| `qbdi.registerTraceCallbacks(vm, target, outDir?)` | `number \| bigint, AddressLike, string?` | `boolean` |
| `qbdi.unregisterTraceCallbacks(vm)` | `number \| bigint` | `boolean` |
| `qbdi.lastError()` | — | `string \| null` |
| `qbdi.shutdown()` | — | `boolean` |

常用常量：`qbdi.REG_RETURN`, `qbdi.REG_BP`, `qbdi.REG_LR`, `qbdi.REG_SP`, `qbdi.REG_FLAG`, `qbdi.REG_PC`, `qbdi.MEMORY_READ`, `qbdi.MEMORY_WRITE`, `qbdi.MEMORY_READ_WRITE`

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.registerTraceCallbacks(vm, target);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

Trace 文件默认输出到 `/data/data/<package>/trace_bundle.pb`，配合 qbdi-replay + IDA 插件回放。

---

## 注意事项

- **Native hook 回调签名：** `function(a, b, c) { ... }`，`arguments[0..7]` = x0..x7 (BigInt)、`this` = register 上下文（`this.x0..x30` / `this.sp` / `this.pc` / `this.$orig()`）；改参数先写 `this.xN = v`，再 `this.$orig()`；`return value` 覆盖返回值
- **Java hook 回调签名：** `function(a, b, c) { ... }`，`this` = 实例（静态方法为 class 载体）、`arguments` = Java 参数、`this.$orig(...)` = 原方法；`return value` 改返回值
- **Java 字段访问必须用 `.value`：** `obj.field` 返回 FieldWrapper，`obj.field.value` 才是真实值
- **`Java.choose` 的 wrapper 仅在 `onMatch` 内有效**，跨回调保留需要自己提取字段值
- Spawn 模式下 Java hook 必须放在 `Java.ready(fn)` 里（`Java.classLoaders()` / `Java.choose` 同理）
- `Java.setStealth()` 必须在 `Java.use().impl` 之前调用
- `callNative()` 仅支持整数/指针参数（最多 6 个），需要浮点/任意签名用 `NativeFunction`
- 自修改代码后需 `Memory.flushCodeCache(addr, size)` 清 I-cache；`Memory.alloc` 返回普通 heap 内存，若要执行需先 `Memory.protect(addr, size, "rwx")`

---

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。使用者应确保在合法授权范围内使用本工具，遵守所在地区的法律法规。作者不对任何滥用、非法使用或由此造成的损失承担责任。使用本项目即表示您同意自行承担所有风险。
