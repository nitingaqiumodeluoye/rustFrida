#!/usr/bin/env bash
# 单模块语法/类型检查：在本地对 Android target 跑 cargo check，不链接、不产出二进制。
#
# 用途：push 前先抓编译错误。CI 才是权威，但 CI 一轮要 1.5~3 分钟，
# 而 `cargo check` 只要几秒（热缓存下）。
#
# 为什么需要专门的桩 crate 而不是直接 `cargo check -p rust_frida`：
#   rust_frida 的 build.rs 与 injection.rs 通过 include_bytes! 引用
#   target/aarch64-linux-android/{debug,release}/libagent.so 与
#   loader/build/*.bin，本地没这些产物就编不过 —— 于是最该检查的源码反而
#   检查不了。这里用一个只含被改模块的桩 crate，绕开那些构建期依赖。
#
# 关键：桩 crate 必须**复刻真实模块结构**。曾经踩过的坑：
#   logger.rs 的宏是 #[macro_export] 的，真实 crate 里 kpm.rs 必须
#   `use crate::{log_warn, log_verbose};` 才能用；而早期版本的桩把宏定义写在
#   `mod kpm;` 之前，靠宏的文本作用域"蒙过"了检查，于是本地全绿、CI 报
#   `cannot find macro log_verbose in this scope`。所以这里用 main.rs + 平行
#   模块的方式还原真实布局。
#
# 用法：
#   scripts/check-module.sh rust_frida/src/kpm.rs
#   scripts/check-module.sh rust_frida/src/spawn.rs
#
# 退出码：0 = 无 error（warning 不阻塞）；1 = 有 error 或环境不满足。

set -uo pipefail

TARGET="${CHECK_TARGET:-aarch64-linux-android}"
SRC="${1:-}"

if [ -z "$SRC" ]; then
    echo "用法: $0 <要检查的源文件，如 rust_frida/src/kpm.rs>" >&2
    exit 1
fi
if [ ! -f "$SRC" ]; then
    echo "找不到源文件: $SRC" >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo 不在 PATH 上" >&2
    exit 1
fi
if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
    echo "缺少 target ${TARGET}；先跑: rustup target add ${TARGET}" >&2
    exit 1
fi

MODULE="$(basename "$SRC" .rs)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/src"

cat > "$WORK/Cargo.toml" <<EOF
[package]
name = "rfcheck"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "rfcheck"
path = "src/main.rs"

[dependencies]
libc = "0.2"

[workspace]
EOF

# main.rs 按真实布局声明平行模块：logger 提供被 #[macro_export] 的日志宏，
# 被测模块必须自己 use 进来（这正是要验证的点）。
cat > "$WORK/src/main.rs" <<EOF
#![allow(dead_code, unused_imports, unused_variables, unused_mut)]

mod logger;
mod ${MODULE};

fn main() {}
EOF

cp "$REPO/rust_frida/src/logger.rs" "$WORK/src/logger.rs"
cp "$SRC" "$WORK/src/${MODULE}.rs"

# 被测模块里 crate 相对路径依赖（如 crate::proc_mem）无法在桩里解析，
# 这类缺失的 mod 用空壳补上，避免报与本次改动无关的错。
grep -ohE 'crate::[a-z_]+' "$SRC" | sed 's/crate:://' | sort -u | while read -r dep; do
    [ "$dep" = "logger" ] && continue
    [ -f "$WORK/src/$dep.rs" ] && continue
    echo "#![allow(dead_code, unused_imports)]" > "$WORK/src/$dep.rs"
done
# `use crate::{a, b};` 形式的多个依赖
grep -ohE 'use crate::\{[^}]*\}' "$SRC" | sed -E 's/use crate::\{//; s/\}//' | tr ',' '\n' | tr -d ' ' |
while read -r dep; do
    [ -z "$dep" ] && continue
    [ "$dep" = "logger" ] && continue
    [ -f "$WORK/src/$dep.rs" ] && continue
    echo "#![allow(dead_code, unused_imports)]" > "$WORK/src/$dep.rs"
done

echo "== cargo check ${MODULE} (target=${TARGET}) =="
OUT="$(cd "$WORK" && cargo check --target "$TARGET" --offline 2>&1)"
RC=$?

# 桩里被补成空壳的模块会带来 never-used / cannot find 之类噪音，
# 只关心 error 行。
ERRORS="$(printf '%s\n' "$OUT" | grep -E '^error(\[|:)' || true)"

if [ -n "$ERRORS" ]; then
    echo "$ERRORS"
    echo
    echo "== 完整输出 =="
    printf '%s\n' "$OUT" | grep -vE '^\s*(Compiling|Checking|Finished)' | head -60
    exit 1
fi

if [ $RC -ne 0 ]; then
    echo "cargo check 退出码 $RC，但没有匹配到 error 行，完整输出：" >&2
    printf '%s\n' "$OUT" | tail -40 >&2
    exit 1
fi

echo "OK：无 error（仅 warning）"
exit 0
