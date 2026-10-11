#!/usr/bin/env python3
"""loader shellcode 段布局守卫。

背景（决定了这个脚本为什么存在）：

loader 不是一个被 bionic 加载的 .so。它由 `loader/build_helpers.py` 用
`objcopy -O binary --only-section=.payload` 导出成一段裸二进制，再被宿主
（`rust_frida/src/injection.rs`）`pwrite` 到目标进程一处匿名 RWX 分配里。
而 `loader/helpers/helper.lds` 的 `.payload` 输出段【只收 .text/.rodata/.data】，
所以 loader 代码能引用的静态存储，必须落在这三段里。

最阴的坑是 `.bss`：一个不带初值的 static/全局会落进 NOBITS 段。NOBITS 没有
文件内容，objcopy 不会导出它，运行时那块地址既不在 .bin 里、也不在 loader 被
写入的那段分配中 —— 但代码里对它的引用看起来完全正常，编译、链接、静态检查
全都不会报。运行时写它就是写别人的内存。

真实踩过一次（本守卫要拦的就是它的复发）：

  `agent_vma_name` 原本是 `char agent_vma_name[80]` 栈数组，传给
  `prctl(PR_SET_VMA_ANON_NAME)`。5.10 一类内核的 `vma_set_name()` 保存的是
  用户态指针而不是拷贝字符串（Vector 的 memory_manager.cpp 注释、以及设备上
  实测到的 `[anon:<乱码>]` 都印证了这点），于是函数返回后栈被复用，可执行段的
  maps 行渲染成脏字节 —— 比不命名更显眼，等于自己送一个指纹给检测方。

  修法是把缓冲区做成 `static`。但若写成裸数组 `static char x[80];`，就正好掉进
  上面那个 .bss 坑：名字根本不在 .bin 里，运行时读到全零，prctl 拿到空串等于
  没命名。所以必须带非零初值把它钉进 .data。

判据（都是可机器检查的不变量，不是风格偏好）：

  1. 没有任何符号落在 NOBITS 段里。用符号表判定而不是看段名，是因为
     `.relro_padding` 这类链接器生成的填充天然是 NOBITS 却完全无害（没有符号、
     代码也不引用）—— 只按段名放行会误报，只按段名禁止会漏掉真正的问题。
  2. 名字缓冲区的初值 "wwb_so" 必须出现在导出镜像 `rustfrida-loader.bin` 里
     （= .data 随 .bin 一起下发，而不是被留在某个不导出的段里）。
  3. `.rela.dyn`（loader 自己处理重定位时要用）若存在，必须落在 .payload 内。

失败时会把完整段表打出来，便于直接看出是哪一段越界。
"""

import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SO_PATH = os.path.join(ROOT, "loader", "build", "rustfrida-loader.so")
BIN_PATH = os.path.join(ROOT, "loader", "build", "rustfrida-loader.bin")

SHT_SYMTAB = 2
SHT_NOBITS = 8
SHF_ALLOC = 0x2
STT_OBJECT = 1
STT_TLS = 6
# 名字缓冲区必须出现在导出镜像里的初值。与
# `rust_frida/src/injection.rs` 里 memfd_create 的名字一致。
NAME_MARKER = b"wwb_so"


def fail(msg, sections=None):
    print("FAIL: " + msg)
    if sections:
        print("\n--- 段表（全部） ---")
        for s in sections:
            print(
                "  {:<18} type={:<2} flags=0x{:<3x} addr=0x{:<8x} size=0x{:<8x} off=0x{:x}".format(
                    s["name"] or "<unnamed>",
                    s["type"],
                    s["flags"],
                    s["addr"],
                    s["size"],
                    s["off"],
                )
            )
    sys.exit(1)


def read_sections(path):
    with open(path, "rb") as fh:
        d = fh.read()

    if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
        fail("{} 不是 ELF64 little-endian".format(path))

    e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]

    if e_shoff == 0 or e_shnum == 0:
        fail("{} 没有段表（strip 过？）".format(path))

    sections = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        (
            name_off,
            sh_type,
            flags,
            addr,
            off,
            size,
            link,
            info,
            align,
            entsize,
        ) = struct.unpack_from("<IIQQQQIIQQ", d, o)
        sections.append(
            {
                "index": i,
                "name_off": name_off,
                "type": sh_type,
                "flags": flags,
                "addr": addr,
                "off": off,
                "size": size,
                "link": link,
                "info": info,
                "align": align,
                "entsize": entsize,
            }
        )

    shstr = sections[e_shstrndx]
    base = shstr["off"]
    for s in sections:
        start = base + s["name_off"]
        end = d.index(b"\x00", start)
        s["name"] = d[start:end].decode("ascii", "replace")

    return d, sections


def cstr(d, off, limit=None):
    end = d.find(b"\x00", off)
    if end < 0:
        return "<bad>"
    raw = d[off:end]
    if limit is not None:
        raw = raw[:limit]
    return raw.decode("ascii", "replace")


def read_no_bits_users(d, sections):
    """返回 {段索引: [符号名]}，只统计真的占存储空间的 OBJECT/TLS 符号。"""
    users = {}
    symtab = next((s for s in sections if s["type"] == SHT_SYMTAB), None)
    if symtab is None:
        return users, False

    if symtab["link"] >= len(sections):
        return users, False
    strtab = sections[symtab["link"]]
    entsize = symtab["entsize"] or 24

    for i in range(symtab["size"] // entsize):
        o = symtab["off"] + i * entsize
        name_off, info, _other, shndx, _value, size = struct.unpack_from("<IBBHQQ", d, o)
        if shndx == 0 or shndx >= len(sections):
            continue
        if (info & 0xF) not in (STT_OBJECT, STT_TLS):
            continue
        users.setdefault(shndx, []).append(cstr(d, strtab["off"] + name_off))

    return users, True


def main():
    for path in (SO_PATH, BIN_PATH):
        if not os.path.isfile(path):
            fail("缺少构建产物 {}（先跑 python3 loader/build_helpers.py）".format(path))

    d, sections = read_sections(SO_PATH)

    payload = [s for s in sections if s["name"] == ".payload"]
    if not payload:
        fail("找不到 .payload 段", sections)
    payload = payload[0]
    payload_end = payload["addr"] + payload["size"]

    def inside_payload(s):
        return s["addr"] >= payload["addr"] and s["addr"] + s["size"] <= payload_end

    # 1) NOBITS 段里不允许有符号。
    users, has_symtab = read_no_bits_users(d, sections)
    if not has_symtab:
        fail(
            "{} 里没有 symtab，无法判定 NOBITS 段是否被引用；"
            "loader 的链接不允许 strip".format(os.path.relpath(SO_PATH, ROOT)),
            sections,
        )

    offenders = []
    for s in sections:
        if s["type"] != SHT_NOBITS or s["size"] == 0:
            continue
        names = users.get(s["index"], [])
        if names:
            offenders.append((s, names))

    if offenders:
        detail = "; ".join(
            "{} 里的 {}".format(
                s["name"] or "<unnamed>",
                ", ".join(sorted(set(names))[:6]) + ("…" if len(set(names)) > 6 else ""),
            )
            for s, names in offenders
        )
        fail(
            "NOBITS 段里有符号：{}。这些符号不在 .payload 里、不会被 objcopy 导出，"
            "loader 运行时引用到的就是未初始化内存（写它等于写别人的数据）。"
            "给对应的 static/全局加非零初值把它钉进 .data。".format(detail),
            sections,
        )

    # 2) 名字缓冲区必须真的在导出镜像里。
    with open(BIN_PATH, "rb") as fh:
        blob = fh.read()
    if NAME_MARKER not in blob:
        fail(
            "导出镜像 {} 里找不到 {!r}。名字缓冲区（agent_vma_name）没有随 .bin 下发，"
            "运行时 prctl 会拿到空串 = 段不会被命名 = maps 里露出一条无名的匿名 "
            "可执行段。检查它是否掉进了不导出的段。".format(
                os.path.relpath(BIN_PATH, ROOT), NAME_MARKER
            ),
            sections,
        )

    # 3) loader 自己处理 DT_RELA 重定位（rustfrida_link_agent 里的 rela 循环），
    #    重定位表必须真实存在于被导出的那段内存里，否则它读到的是一堆零。
    for s in sections:
        if s["name"] != ".rela.dyn" or not (s["flags"] & SHF_ALLOC) or s["size"] == 0:
            continue
        if not inside_payload(s):
            fail(
                ".rela.dyn 落在 .payload 之外（addr=0x{:x} size=0x{:x}，"
                ".payload=0x{:x}..0x{:x}）：loader 的重定位表不会被导出".format(
                    s["addr"], s["size"], payload["addr"], payload_end
                ),
                sections,
            )

    print("ok: loader 段布局")
    print(
        "  .payload   0x{:x}..0x{:x} (0x{:x} bytes)   .bin {} bytes".format(
            payload["addr"], payload_end, payload["size"], len(blob)
        )
    )
    print("  NOBITS 段里的符号: 0")
    print(
        "  {!r} 在 .bin 中（偏移 0x{:x}）".format(
            NAME_MARKER.decode(), blob.index(NAME_MARKER)
        )
    )
    for s in sections:
        if s["type"] == SHT_NOBITS or s["name"] in (".text", ".rodata", ".data"):
            print(
                "  {:<18} type={:<2} size=0x{:<8x} payload内={}".format(
                    s["name"] or "<unnamed>",
                    s["type"],
                    s["size"],
                    "是" if inside_payload(s) else "否",
                )
            )


if __name__ == "__main__":
    main()
