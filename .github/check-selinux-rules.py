#!/usr/bin/env python3
"""SELinux 补丁规则不变量检查。

背景（这是一次真实线上问题，不是假想）
--------------------------------------
`rust_frida/src/selinux.rs` 的 RULES 用 `domain` 作为源类型。`domain` 是
SELinux 的属性（attribute），成员是【所有域】—— 包括骨架里的 app_zygote。
所以任何以 `domain` 为源的 allow 规则，实际效果都是「给所有域授权」。

其中这条：

    ("domain", "tmpfs", "dir", &["?mounton", "read", "open", "getattr", "search"])

给所有域放开了 tmpfs 目录的 read/open/search。而 Android 上 `/mnt`、
`/mnt/obb`、`/mnt/asec` 的 label 正是 `u:object_r:tmpfs:s0`，于是任何域都能
`opendir` + `readdir` 列举它们 —— 这正是很多完整性/反注入 SDK 用来判定
「权限边界越权」的特征。实测让 TrustAttestor 报出
`system.permission.boundary`（L1 系统完整性 BREACH），而重启后（内核策略回到
出厂）同一台设备是 PASS，即纯属 rustfrida 自己造成的误报。

修法是：tmpfs:dir 只保留 getattr。理由是 agent SO 通过 memfd 的
【fd + SCM_RIGHTS】交给目标进程，走 /proc/self/fd/N（各路径段属 procfs），
根本不需要按路径遍历 tmpfs 目录；目标进程需要的是 tmpfs【file】的
read/open/execute/map，那条规则保留。

本脚本把「不要再把 dir 的列举类权限授给 tmpfs」钉成机器可检查的不变量，
避免以后加规则时无意中把误报引回来。
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SELINUX_RS = REPO_ROOT / "rust_frida" / "src" / "selinux.rs"

# dir class 上「能列举目录内容」的权限。放开了就等于允许 readdir。
LISTING_PERMS = {"read", "open", "search"}

# 解析结果少于这个数量说明 RULES 的写法变了、正则失配 —— 此时必须报错，
# 否则「解析出 0 条规则」会让所有断言都空转通过（静默失效）。
MIN_EXPECTED_RULES = 20

RULE_RE = re.compile(
    r'\("(?P<source>[^"]*)","(?P<target>[^"]*)","(?P<cls>[^"]*)",\s*&\[(?P<perms>[^\]]*)\]'
)
PERM_RE = re.compile(r'"([^"]*)"')


def strip_optional(name: str) -> str:
    """`?tmpfs` → `tmpfs`（`?` 前缀表示类型缺失时静默跳过）"""
    return name[1:] if name.startswith("?") else name


def load_rules(path: Path = SELINUX_RS):
    text = path.read_text(encoding="utf-8")

    start = text.index("const RULES")
    end = text.index("\n];", start)
    block = text[start:end]

    # 去掉注释再压缩空白：RULES 里的条目有单行的也有多行的，
    # 压平之后同一条正则就能覆盖两种写法。
    block = re.sub(r"//[^\n]*", "", block)
    block = re.sub(r"\s+", "", block)

    rules = []
    for m in RULE_RE.finditer(block):
        perms = [strip_optional(p) for p in PERM_RE.findall(m.group("perms"))]
        rules.append(
            {
                "source": m.group("source"),
                "target": strip_optional(m.group("target")),
                "class": m.group("cls"),
                "perms": perms,
            }
        )
    return rules


def main() -> int:
    # 可选参数：换成另一个 selinux.rs 路径。目的是能拿「修复前的版本」
    # 自测这个脚本真的会拦下来，而不是只会返回 ok。
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else SELINUX_RS

    if not target.exists():
        print(f"FAIL: 找不到 {target}", file=sys.stderr)
        return 1

    rules = load_rules(target)
    if len(rules) < MIN_EXPECTED_RULES:
        print(
            f"FAIL: 只解析出 {len(rules)} 条规则（预期 >= {MIN_EXPECTED_RULES}）。"
            "RULES 的写法变了，本脚本的正则需要同步更新 —— "
            "在修好之前它无法起到检查作用，所以按失败处理。",
            file=sys.stderr,
        )
        return 1

    problems = []
    for rule in rules:
        # 只关心「以 domain 属性为源」的规则 —— 那才是放大到所有域的授权。
        # $self 之类的窄源不在此列。
        if rule["source"] != "domain":
            continue
        if rule["target"] != "tmpfs" or rule["class"] != "dir":
            continue
        offenders = sorted(set(rule["perms"]) & LISTING_PERMS)
        if offenders:
            problems.append((rule, offenders))

    if problems:
        print("FAIL: 检测到会把 tmpfs 目录列举权限授权给【所有域】的规则：", file=sys.stderr)
        for rule, offenders in problems:
            print(
                f'  ("{rule["source"]}", "{rule["target"]}", "{rule["class"]}", '
                f'&{rule["perms"]!r})',
                file=sys.stderr,
            )
            print(f"     越界权限: {', '.join(offenders)}", file=sys.stderr)
        print(
            "\n影响：任何域（含 app_zygote）都能 opendir + readdir 列举 /mnt、\n"
            "/mnt/obb、/mnt/asec（label 为 u:object_r:tmpfs:s0），会被完整性检测\n"
            "判为权限边界越权 —— 之前就是这样让 TrustAttestor 误报\n"
            "system.permission.boundary 的。\n"
            "\n如果确实需要这份能力，请把源类型从 `domain` 收窄到具体域（如 $self），\n"
            "而不是放开给所有域。",
            file=sys.stderr,
        )
        return 1

    tmpfs_dir = [
        r for r in rules if r["target"] == "tmpfs" and r["class"] == "dir"
    ]
    print(f"ok: 解析 {len(rules)} 条规则；tmpfs:dir 规则 {len(tmpfs_dir)} 条，"
          f"均未向所有域授予目录列举权限 {sorted(LISTING_PERMS)}")
    for r in tmpfs_dir:
        print(f'    ("{r["source"]}", "{r["target"]}", "{r["class"]}", &{r["perms"]!r})')
    return 0


if __name__ == "__main__":
    sys.exit(main())
