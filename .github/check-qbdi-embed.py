#!/usr/bin/env python3
"""校验 rustfrida 二进制里内嵌的 QBDI helper SO 与构建出的 .so 是同一份字节。

为什么需要这个检查
------------------
`rust_frida/build.rs`（feature qbdi）把 helper 路径写进 `QBDI_HELPER_SO_PATH`，
`injection.rs` 再用 `include_bytes!(env!("QBDI_HELPER_SO_PATH"))` 把它嵌进宿主二进制。
`include_bytes!` 是**编译期**取字节，于是有两种静默错位：

1. qbdi-helper 与 rust_frida 的构建顺序颠倒 —— rustfrida 嵌到上一次构建的旧 SO；
2. `rust_frida/build.rs` 的 `rerun-if-changed` 没被 cargo 认作失效 —— 改了 helper
   源码但 rustfrida 没重编。

两种情况下构建都成功、产物都在，只有运行时才会看到「JS 里 qbdi 报符号/版本不对」，
或者更糟：下发的是新 SO、宿主内嵌的是旧 SO，而设备端按前者跑。所以在这里断言。

用法
----
    python3 .github/check-qbdi-embed.py <rustfrida 二进制> <libqbdi_helper.so>

退出码：0 = 内嵌字节与 .so 一致；1 = 不一致或参数/文件有问题。
"""

import sys


def die(msg: str) -> "None":
    # GitHub Actions 的 ::error:: 注解会直接标在 job 摘要上，不用翻日志
    print(f"::error::{msg}")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 3:
        die(f"用法: {sys.argv[0]} <rustfrida 二进制> <libqbdi_helper.so>")

    host_path, helper_path = sys.argv[1], sys.argv[2]

    try:
        with open(host_path, "rb") as f:
            host = f.read()
    except OSError as e:
        die(f"读不到宿主二进制 {host_path}: {e}")

    try:
        with open(helper_path, "rb") as f:
            helper = f.read()
    except OSError as e:
        die(f"读不到 helper SO {helper_path}: {e}")

    if not helper:
        die(f"{helper_path} 是空文件 —— qbdi-helper 没真正构建出来")

    # ELF magic。文件名对了但内容是 LFS 指针文本（134 B）这种坑，
    # 在别处出现过一次，这里顺手挡掉，免得把「嵌了个文本文件」当成通过。
    if not helper.startswith(b"\x7fELF"):
        die(f"{helper_path} 不是 ELF（前 4 字节 {helper[:4]!r}）")

    idx = host.find(helper)
    if idx < 0:
        die(
            "rustfrida 内嵌的 QBDI helper 与 dist/libqbdi_helper.so 不一致 —— "
            "检查 qbdi-helper 是否早于 rustfrida 构建，或 rust_frida/build.rs 的 rerun-if-changed 是否失效"
        )

    # 出现在多个位置不算错（对齐填充可能造成重复），报告第一处便于回溯
    print(
        f"OK: helper SO {len(helper)} 字节，内嵌于 {host_path} 偏移 {idx:#x}"
        f"（宿主 {len(host)} 字节）"
    )


if __name__ == "__main__":
    main()
