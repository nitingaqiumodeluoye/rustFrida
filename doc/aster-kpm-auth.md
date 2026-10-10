# Aster 换管理器之后，root 调 KPM 全部失败

记录 2026-09-19 在红米 K40（alioth，`7829721`，kernel `4.19.157`，KP `d08`）上的定位。

现象：

```text
ERR spawn io.liankong.riskdetector 失败:
清理 code-swap COW 页失败:
KernelPatch ctl0 karinahide madvise 9567 0x78e87bf000 0x3000 失败，返回 -1
```

**不是 karinahide 的 madvise 坏了。** rustFrida 以 uid 0 调 KernelPatch，授权门直接 `-EPERM`，supercall 挂在真实 syscall 45（`truncate`）上，内核把 `[-4095, -1]` 全部折成 errno，用户态只看到 `-1`。模块的 ctl0 根本没进去：内核侧 `kp_module_control0` 的 `name %s, args: %s` 一条都没打。

## 为什么

设备上的旧管理器 `me.bmax.apatch` 已卸载，换成了 Aster（`me.yuki.aster`，uid **10272**）。KPM 命令只认「受信任管理器」这一个身份；root 只在 su 白名单里，过不了授权门。

仓库 `.kp/kernel/patch/common/supercall.c` 的 `before()` 是这样分的：

```c
int is_authed = 0;
if (has_preset_superkey()) {
    /* 读 key，与预置 superkey 逐字比较 */
    is_authed = !auth_superkey(key);
    is_trusted_caller = is_authed;
}
if (is_trusted_manager_uid(uid)) {
    is_trusted_caller = 1;
    is_authed = 1;
} else if (is_su_allow_uid(uid)) {
    is_trusted_caller = 1;          /* 只放行，不抬 is_authed */
}
if (!is_trusted_caller) return;
/* kpver / kver 在这里，密钥错了也能成功 */
args->ret = supercall(is_authed, cmd, ...);
```

`supercall()` 里所有 KPM 命令都在这句之后：

```c
if (!is_authed) return -EPERM;
case SUPERCALL_KPM_LOAD / UNLOAD / CONTROL / NUMS / LIST / INFO:
```

`is_trusted_manager_uid_android()`（`userd.c`）就是 `uid == trusted_manager_uid`。这个 uid 由 `trusted_managers[]` 里的 **包名 + APK 签名摘要** 扫出来。仓库这份表只有 `me.bmax.apatch` 和 `com.example.apatch`，**没有 `me.yuki.aster`**。设备上的 Aster 内核已经把表换成自己的签名，所以 10272 能过，uid 0 不能过。

实测（同一台设备、同一时刻）：

| 调用者 | key | `kpm_nums` |
|---|---|---|
| root (uid 0) | `su` | EPERM |
| root | 空串 | EPERM |
| root | `1iZ81mPsbSxenKl`（`SKEY_GET` 读出来的值） | EPERM |
| root | NULL / `0xdead0000` | EPERM |
| Aster uid 10272 | `su` | 8 |
| Aster uid 10272 | NULL / 空串 / 非法指针 | 8 |

管理器那一列是决定性的：非法指针也成功，说明 `before()` **根本没有解引用 key**。仓库源码里只有 `has_preset_superkey()` 为假才会跳过读 key。因此设备上这段比较不执行，`-EPERM` 来自「root 不是受信任调用者」，不是「key 写错了」。

`SKEY_GET` 仍能返回 `1iZ81mPsbSxenKl`，那是 `predata_init()` 在 superkey 为空时生成的随机串，写在 `.start.data` 运行时内存里，**不参与这次判定**。`reset_superkey()` 也只是 `lib_strlcpy` 进这块内存，不改 `superkey_is_user_set`（那个标志只在 `predata_init()` 算一次），也不落盘。

另外两个让报错特别难读的点：

1. `kpver` / `kver` 在 `if (!is_authed)` **之前**。key 错了、甚至根本没授权，`kpatch su kpver` 照样返回 `d08`。
2. supercall 挂在 `__NR_truncate`（45）上。模块返回 `-EINVAL/-ENOMEM/-ESRCH/-ENOENT` 和授权门的 `-EPERM`，到 libc 全是 `-1`。

所以下面两条当时提出来的修法都不成立：

| 方案 | 结果 |
|---|---|
| 把 `SUPERCALL_KEY` 改成 `1iZ81mPsbSxenKl` | 无效。key 不被读取 |
| 以管理器 uid 调 `SUPERCALL_SKEY_SET` 把 superkey 写成 `su` | 无效。只改运行时内存，不改变「是否读 key」 |

`kpm.rs` 顶部关于 `SUPERCALL_KEY` 的注释仍写着「非管理器进程必须提供与预置值逐字相同的 superkey」。那是按仓库 `.kp` 源码写的，**和这台设备的实测相反**，不要按那段注释去改 key。

## 怎么做

rustFrida 本体必须留在 uid 0：ptrace、改 SELinux 策略都要 root。只把**这一次** KPM 调用放到子进程里，`setuid` 到管理器 uid 再进 supercall。父进程保持 root。

探针 `khfork` 在设备上验证过：父进程 `kpm_nums = EPERM`；`fork` 后子进程 `setuid(10272)`，`kpm_nums = 8`，`kpm_list` 列出全部模块（含 karinahide）。

实现在 `rust_frida/src/kpm.rs` 的 `control()`：

1. `pipe` + `fork`。
2. 子进程 `setuid(TRUSTED_MANAGER_UID)`。失败则经管道回传哨兵 `-7001`。
3. 成功则 `syscall(45, key, versioned_cmd, module, args, out, outlen)`，**紧跟着**读 `last_os_error()`。
4. 把 `(ret, errno)` 共 8 字节写回管道，`_exit(0)`。子进程不做别的，避免把 rustFrida 的 fd / 锁带进另一个 uid。
5. 父进程读满 8 字节，`waitpid`，再按 ret / errno 报错。

常量：

```rust
const TRUSTED_MANAGER_UID: u32 = 10272; // me.yuki.aster，这台设备
const SUPERCALL_KEY: &str = "su";       // 此路径下不被内核读取，保留原值
```

换管理器、或 Aster 重装导致 uid 变化时，必须改 `TRUSTED_MANAGER_UID`。uid 用下面这条看：

```sh
pm list packages -U | grep me.yuki.aster
```

setuid 失败时的报错会直接写出这个常量，不要去改 `SUPERCALL_KEY`。

构建统一走 CI（`.github/workflows/build.yml`），见 `doc/build.md`。

```bash
REPO=nitingaqiumodeluoye/rustFrida
git push origin master
gh run list --repo "$REPO" --limit 5
gh run watch <run-id> --repo "$REPO" --exit-status
gh run download <run-id> --repo "$REPO" -D out/ci-<run-id>
```

当时那次改动（`kpm.rs` 借管理器 uid 调 ctl0）产物 md5 `b70441e950a5613d21cee855015115fb`，由旧流程在 `4h4g` 构建机上编出（**已废弃，现统一走 CI**）。

## 还没做完

二进制已经推到设备并替换 `/data/local/tmp/rustfrida`，server 也起来过（当时 PID 31185，uid 0）。**没有跑完** `spawn io.liankong.riskdetector`，所以「子进程 setuid 之后，karinahide 的 madvise 是否真的清掉 COW 页」没有设备侧结论。`khfork` 只证明了 `kpm_nums` / `kpm_list` 能过授权门。

---

## 2026-10-10 复现：红米 K50（rubens，5.10.66，FolkPatch）

同一病症在另一台设备上重现，并且推翻了上表里「ENOENT = 模块没加载」那一行。

### ENOENT 不是「模块不存在」，是授权被拒的伪装

设备侧 `/data/local/tmp/rustfrida.log` 全部是：

```text
KernelPatch ctl0 karinahide madvise 7464 0x79f507f000 0x3000 失败:
syscall=-1, errno=2 (找不到该 KPM 模块（尚未加载，或名字写错）)
```

但**这是误报**。授权失败时 `before()` 提前 `return`，既不设 `skip_origin` 也不设 `ret`，
于是原始 syscall 45 真的执行：`truncate("su", <ver_xx_cmd>)` → 路径不存在 → **ENOENT**。
模块确实不在时的 `-ENOENT` 是 `module_control0()` 返回的，两者 errno 相同。

决定性判别：`module_control0()` 入口有 `logkfi("name %s, args: %s")`
（`printk("[+] KP I …")`），授权一旦放行必然进 dmesg。实测：

| 探测 | 结果 |
| --- | --- |
| `dmesg \| grep -c "KP I module_control0"` | **0** |
| `dmesg \| grep -ci karinahide` | **0** |
| `dmesg \| grep -c "Failed to load KPM"` | 0 |

即：**根本没进模块**，ENOENT 来自落空的 truncate。所以「按 ENOENT 去查模块加载」是错方向。

### uid 常量又过期了

本机是 FolkPatch，内核来自 `LyraVoid/KernelPatch`（`app/src/main/assets/kpimg.version` = 0.13.9，
下载源见 `app/build.gradle.kts` 的 `downloadKpimg`）。它的 `trusted_managers[]` **只有一项**
`me.yuki.folk`（bmax121 原版才是 `me.bmax.apatch` / `com.example.apatch`）。

```
$ pm list packages -U | grep yuki
package:me.yuki.folk uid:10236
$ grep '^me.yuki.folk ' /data/system/packages.list
me.yuki.folk 10236 0 /data/user/0/me.yuki.folk default:targetSdkVersion=31 …
```

而 `kpm.rs` 里仍是 K40 时代的 `10272`（`me.yuki.aster`），本机根本没有这个 uid。
于是子进程 `setuid(10272)` 虽然成功，但既不是管理器、也不在 su 白名单，
`is_trusted_caller = 0` → 提前 return → ENOENT。

（附带一提：本机 `has_preset_superkey()` 为真，所以 `is_su_allow_uid` 那条
「无预置 key 时把 su 调用者也算已认证」的补丁**不生效**；uid 0 依然过不了门。）

### 改法

`kpm.rs`：

1. **`TRUSTED_MANAGER_UID` 常量改为运行时解析**。按 `TRUSTED_MANAGER_PACKAGES`
   （`me.yuki.folk` / `me.yuki.aster` / `me.bmax.apatch`）依次查
   `/data/system/packages.list`（读不到再看 `.tmp`）—— 内核 `userd.c` 用的也是这两个文件。
   命中即缓存（`OnceLock`），全候选都查不到才回退到常量。换管理器/重装不再需要改代码。
2. **ENOENT 时用无副作用的 `SUPERCALL_KPM_NUMS`(0x1030) 探测一次**，把结论写进报错：
   探测成功 → 确实是「模块不存在」；探测同样失败 → 明确报「uid N 没有通过授权门」，
   不再让人去查模块。

### 修正后的 errno 表

| errno | 含义 |
| --- | --- |
| 管道 / fork / `-7001` | 降权这层失败（uid 解析错了，或 setuid 被拒） |
| `EPERM` | 授权过了，模块侧返回的权限错 |
| `ENOENT` | **有歧义**，看同一错误里的探测结论：探测通过 = 模块没加载；探测也失败 = 授权没过 |
| `EINVAL` / `ENOMEM` / `ESRCH` / `EOPNOTSUPP` | 授权已过，这才是 madvise 参数或模块符号的问题 |

### 另一件独立的事

修正授权后仍未跑通——因为 **karinahide 本身没加载**：

```
$ ls /data/adb/ap/kpm/
Nohello  audit_bypass
$ dmesg | grep -ci karinahide
0
```

`load_ap_kpm_modules()` 扫的是 `AP_KPM_DIR "%s/%s.kpm"`，即每个模块一个同名子目录
（如 `karinahide/karinahide.kpm`，同目录下有 `disable` 文件则跳过）。
把模块放进去重启后即会自动加载。
