#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 查找 NDK clang：优先显式指定的 $NDK_CC，其次 $ANDROID_NDK_HOME（CI），
# 最后回退到本地 SDK 目录 ~/Android/Sdk/ndk
if [ -z "$NDK_CC" ] && [ -n "$ANDROID_NDK_HOME" ]; then
    NDK_BASE="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
else
    NDK_BASE="${NDK_BASE:-$HOME/Android/Sdk/ndk}"
fi

if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
fi

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

$NDK_CC -shared -nostdlib \
    -Wl,-T,helper.lds \
    -fvisibility=hidden \
    -fno-function-sections \
    -fno-data-sections \
    -fno-asynchronous-unwind-tables \
    -Oz \
    -o build/zymbiote.elf \
    zymbiote.c

# ★ 硬约束：payload 只能占 libstagefright.so R+X 段末尾**一页**，
#   超过 4096 字节时 rust_frida 的 build_payload/inject 会直接报错拒绝注入。
#   -Oz（而非 -Os）是为了留出余量：保护位兜底等修复会持续增加代码体积，
#   实测 -Os 下 4120 字节已超页，-Oz 为 3960 字节（余量 136）。
PAYLOAD_SIZE=$(python3 -c "
import struct
raw = open('build/zymbiote.elf','rb').read()
phoff = struct.unpack_from('<Q', raw, 0x20)[0]
entsize, phnum = struct.unpack_from('<HH', raw, 0x36)
for i in range(phnum):
    off = phoff + i * entsize
    p_type, p_flags = struct.unpack_from('<II', raw, off)
    if p_type == 1 and (p_flags & 1):
        filesz = struct.unpack_from('<Q', raw, off + 32)[0]
        print(filesz)
        break
")
if [ "$PAYLOAD_SIZE" -gt 4096 ]; then
    echo "错误: zymbiote payload ${PAYLOAD_SIZE} 字节超过一页 (4096)，rust_frida 会拒绝注入"
    exit 1
fi
echo "payload 体积 ${PAYLOAD_SIZE}/4096 字节（余量 $((4096 - PAYLOAD_SIZE))）"

echo "编译完成: build/zymbiote.elf"
ls -la build/zymbiote.elf
