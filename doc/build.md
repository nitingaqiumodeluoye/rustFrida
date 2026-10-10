# 构建：统一走 CI

本仓库的**唯一标准构建流程是 GitHub Actions**，不再在本地或远程构建机上手工编译。

流水线：`.github/workflows/build.yml`，名字 `Build (Android aarch64)`。

## 为什么

产物依赖一组**路径写死**的工具链，本地凑齐的成本高于直接让 runner 去做：

| 依赖 | 固定值 | 写死在哪 |
| --- | --- | --- |
| Android NDK | `r29`，装在 `/opt/android-ndk-r29` | `.cargo/config.toml` 的 linker / `[env]` / `LIBCLANG_PATH` |
| Rust 工具链 | `nightly` + `rust-src`（`aya-build` 编 `bpfel-unknown-none` 用 `-Z build-std`） | 流水线 |
| LLVM | `llvm-23-dev`（`bpf-linker` 需要） | 流水线 |
| `bpf-linker` | `0.11.1` | 流水线 |
| clang sysroot | `aarch64-linux-android33-clang` | `.cargo/config.toml` |

`.cargo/config.toml` 里 `[build] target = "aarch64-linux-android"`，且所有分支都被 `[env]` 钉住；工具链不在预期位置时 `cargo build` 会直接失败，而不是静默降级。所以「本地能过、CI 不过」和「CI 能过、本地不过」都不该出现——**只有 CI 跑过才算过**。

## 触发

| 方式 | 时机 |
| --- | --- |
| `push` 到 `master` / `main` | 自动 |
| 打 `v*` tag | 自动 |
| PR 到 `master` / `main` | 自动 |
| `workflow_dispatch` | 手动，任意分支 |

```bash
# 手动触发当前分支
gh workflow run build.yml --repo nitingaqiumodeluoye/rustFrida
```

## 产物

`dist/` 由 `Collect artifacts` 步骤收集，作为 artifact `rustfrida-aarch64-<sha>` 上传（保留 30 天）：

| 文件 | 说明 |
| --- | --- |
| `rustfrida` | 主程序，`include_bytes!` 内嵌 loader shellcode + `libagent.so` + zymbiote payload，自包含单文件 |
| `libagent.so` | 注入到目标进程的动态库（hook 引擎 / QuickJS / Java hook） |
| `zymbiote.elf` | zymbiote payload，便于把 CI 构建结果回写仓库 |
| `rfclient` | 主机端客户端（`x86_64-unknown-linux-gnu`） |
| `SHA256SUMS.txt` | 上面全部的校验和 |

`rustfrida` 用 `--features watch-so` 构建，因此内嵌了 ldmonitor 的 eBPF SO 加载监听，`--watch-so` 可用。

## 取产物

事件驱动等待，不要盲等固定时长：

```bash
REPO=nitingaqiumodeluoye/rustFrida

# 1) 找到这次 push 对应的 run
gh run list --repo "$REPO" --limit 5

# 2) 阻塞等待，进程一结束立即返回（拿准确退出码）
gh run watch <run-id> --repo "$REPO" --exit-status --interval 20
echo "退出码: $?"

# 3) 下载
gh run download <run-id> --repo "$REPO" -D out/ci-<run-id>
```

`out/` 已在 `.gitignore` 里，不会污染 `git status`。

失败时只看真正有用的行（跳过 Node 版本之类的噪音）：

```bash
gh run view <run-id> --repo "$REPO" --log \
  | sed 's/\x1b\[[0-9;]*m//g' \
  | grep -iE "error|warning: unused|failed"
```

## 部署

```bash
adb push out/ci-<run-id>/rustfrida /data/local/tmp/rustfrida
adb shell 'su -c "chmod 755 /data/local/tmp/rustfrida"'

# PID 注入 / spawn / server 模式见 README「部署 & 运行」
```

## 本地构建：仅用于诊断

只有在**明确需要本地复现 CI 特有失败**时才本地编译，且动身前先确认工具链齐备——否则会触发一整轮 NDK 下载（数百 MB）或编译中途才失败。

必须同时满足：

- NDK `r29` 放在 `/opt/android-ndk-r29`（不满足就得改 `.cargo/config.toml`，别改环境变量以外的路径）
- `rustup toolchain install nightly --profile minimal --component rust-src`
- `rustup target add aarch64-linux-android --toolchain nightly`
- `llvm-23-dev` 装在 `/usr/lib/llvm-23`
- `bpf-linker 0.11.1`

然后按顺序（`rustfrida` 通过 `include_bytes!` 内嵌前两者的产物，顺序错了会拿到旧字节）：

```bash
bash zymbiote/build.sh              # → zymbiote/build/zymbiote.elf
python3 loader/build_helpers.py     # → loader/build/{bootstrapper,rustfrida-loader}.bin
cargo build -p agent --release --locked --target aarch64-linux-android
cargo +nightly build -p rust_frida --release --locked \
  --features watch-so --target aarch64-linux-android
```

产物在 `target/aarch64-linux-android/release/`。

## 可选组件

不在流水线里，需要时单独构建（同样建议加进 CI 而不是本地编）。

**QBDI Trace 支持**：先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release                  # → libqbdi_helper.so
cargo build -p agent --release --features qbdi
cargo build -p rust_frida --release --features qbdi   # rustfrida 内嵌 qbdi-helper SO
```

**ldmonitor 独立命令行工具**：

```bash
cargo build -p ldmonitor --release
```
