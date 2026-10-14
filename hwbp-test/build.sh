#!/bin/bash
#
# 构建 hwbp_test —— 普通 Android 可执行文件(不是 zymbiote 那种 -nostdlib payload,
# 所以直接链 libc,不需要链接脚本)。
#
# 照 zymbiote/build.sh 的 NDK 探测顺序:先 NDK_CC,再 ANDROID_NDK_HOME(CI),
# 最后回退本地 SDK 目录。
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -z "$NDK_CC" ] && [ -n "$ANDROID_NDK_HOME" ]; then
    NDK_BASE="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
else
    NDK_BASE="${NDK_BASE:-$HOME/Android/Sdk/ndk}"
fi

if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
fi
if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find "$NDK_BASE" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
fi
if [ -z "$NDK_CC" ]; then
    echo "错误: 未找到 Android NDK clang(设 NDK_CC 或 ANDROID_NDK_HOME)" >&2
    exit 1
fi

echo "使用 NDK clang: $NDK_CC"

mkdir -p build

# -O2 让读循环真的跑起来(-O0 下每轮都有额外开销,会盖住观察点本身的开销);
# -Wall -Wextra 让未用参数之类的问题在构建期就暴露,不留给设备现场。
#
# 不加 -lpthread:Android 的 bionic 把 pthread 并进了 libc,没有独立的
# libpthread.so,加 -lpthread 会直接 "unable to find library -lpthread"。
"$NDK_CC" \
    -O2 -Wall -Wextra -Wno-unused-parameter \
    -fno-omit-frame-pointer \
    -o build/hwbp_test \
    hwbp_test.c

# 必须显式检查:Android 上「能编出文件」和「能跑起来」不是一回事
# (架构错了 / 动态链接器路径不对都会到设备上才炸)。
file build/hwbp_test
ls -la build/hwbp_test

echo "编译完成: build/hwbp_test"