#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 查找 NDK clang
NDK_BASE="$HOME/Android/Sdk/ndk"
NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)

if [ -z "$NDK_CC" ]; then
    # 尝试其他 API level
    NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
fi

if [ -z "$NDK_CC" ]; then
    echo "错误: 未找到 Android NDK clang，请确认 NDK 已安装在 ~/Android/Sdk/ndk/"
    exit 1
fi

echo "使用 NDK clang: $NDK_CC"

mkdir -p build

COMMON_FLAGS=(
    -shared -nostdlib
    -Wl,-T,helper.lds \
    -fvisibility=hidden \
    -fno-function-sections \
    -fno-data-sections \
    -fno-asynchronous-unwind-tables \
    -mbranch-protection=bti \
    -Os
)

$NDK_CC "${COMMON_FLAGS[@]}" \
    -o build/zymbiote.elf \
    zymbiote.c

$NDK_CC "${COMMON_FLAGS[@]}" \
    -Oz \
    -o build/zymbiote-pure.elf \
    zymbiote_pure.c

$NDK_CC "${COMMON_FLAGS[@]}" \
    -Oz \
    -o build/zymbiote-restore.elf \
    zymbiote_restore.c

echo "编译完成:"
ls -la build/zymbiote.elf build/zymbiote-pure.elf build/zymbiote-restore.elf
