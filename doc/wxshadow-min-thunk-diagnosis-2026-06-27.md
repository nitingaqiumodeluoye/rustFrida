# 2026-06-27 WXSHADOW Minimal Thunk Diagnosis

## 目标

将 `Hook.WXSHADOW` replace 路径临时切换为最小常量返回 thunk，完成一次有效的设备侧二分诊断，并将改动推送到远程仓库供服务器编译。

## 背景

- 之前已经在 `quickjs-hook/src/hook_engine_inline.c` 中加入最小 thunk 诊断逻辑。
- 旧实现依赖 `RF_DIAG_WXSHADOW_MIN_REPLACE` 环境变量。
- 复盘后确认该诊断实际上没有生效，因为 `hook_replace()` 运行在被注入目标进程内，而环境变量只加在宿主 `rustfrida` 进程上。

## 本次改动

文件：

- `quickjs-hook/src/hook_engine_inline.c`

改动内容：

- 新增 `should_force_minimal_wxshadow_replace()`，临时返回 `1`。
- 删除 replace 路径中对 `getenv("RF_DIAG_WXSHADOW_MIN_REPLACE")` 的依赖。
- 当 `stealth == 1` 时，强制使用最小 `mov x0, #123; ret` thunk。
- 增加日志：
  - `[STEALTH1] diagnostic: forcing minimal const replace thunk target=%p`

## 这样做的目的

把问题明确二分为两种可能：

1. 如果设备仍然重启，问题更接近“跳到 wxshadow thunk 本身就会触发异常”。
2. 如果设备不再重启，问题更接近“完整 HookContext / callback replace 链路导致异常”。

## 提交边界

- 只提交本次诊断相关文件。
- 不纳入以下本地噪音：
  - `qbdi/libQBDI.a` 删除
  - `demo_verify.js`
  - `rf_*.js`
  - 本地 `rustfrida` 二进制

## 推送前状态

- 基线提交：`724ec13`
- 工作分支：`master`
- 远程：`origin https://github.com/nitingaqiumodeluoye/rustFrida.git`

## 提交结果

- 新提交：`d389820 quickjs-hook: force minimal wxshadow replace thunk diagnosis`
- 提交内容只包含：
  - `quickjs-hook/src/hook_engine_inline.c`
  - `doc/wxshadow-min-thunk-diagnosis-2026-06-27.md`

## 后续验证点

服务器基于本次提交重新编译后，需要重点确认：

- `Hook.WXSHADOW` replace 路径是否仍导致设备重启
- 日志中是否出现强制最小 thunk 的诊断日志
- `crcdemoapp` 上的行为是否对应返回值被临时固定为 `123`

## 2026-06-28 补充状态

- 用户确认继续使用 `123`，不再推进 `666` 变更。
- 本地已将诊断 thunk 和 `rf_native_wxshadow.js` 的返回值恢复为 `123`。
- 最新判断：最小 thunk 不是稳定通过。它曾在 KPM 手动加载后成功过一次，但后续 `Hook.WXSHADOW` 又触发设备掉线/重启。
- 当前下一步是定位重启发生在：
  - `wxshadow_patch()` / inline patch 安装阶段
  - 还是目标函数实际跳转到最小 thunk 之后

## 2026-06-28 前置 I-cache flush 诊断

新增判断：`Hook.WXSHADOW` 和纯 `wxshadow_client` 的主要差异不是 KPM patch 能力，而是 rustFrida 会把目标函数改成跳到一个新分配的 thunk。旧顺序是在 shadow patch 发布后才 flush thunk/trampoline，这在目标函数被实时调用时可能产生短竞态窗口。

本次本地改动：

- 在 `hook_attach()` 中，`patch_target()` 之前 flush `entry->trampoline` 和 `thunk_mem`
- 在 `hook_replace()` 中，`patch_target()` 之前 flush `entry->trampoline` 和 `thunk_mem`
- 增加日志：
  - `[STEALTH1] preflush attach code before wxshadow publish ...`
  - `[STEALTH1] preflush replace code before wxshadow publish ...`

验证预期：

- 如果这版稳定，重启原因大概率是旧顺序中的“inline jump 已发布但 thunk/trampoline I-cache 尚未同步”竞态。
- 如果这版仍重启，再继续做下一层：让 `Hook.WXSHADOW` 直接 patch `mov x0,#123; ret` 到目标函数，不经过 near thunk，以确认问题是否在“跳到匿名 RWX thunk”。

## 2026-06-28 preflush 验证结果

- `e6690ce` 产物已下发并在设备侧确认 SHA-256。
- 短运行中，`Hook.WXSHADOW` replace 日志显示：
  - `[STEALTH1] preflush replace code before wxshadow publish ...`
  - `wxshadow stealth patch OK: addr=... len=4`
  - `hook result=true`
- 短运行可以正常进入 shutdown cleanup，设备没有立即掉线。
- 保持 hook 存活并点击 App 的“函数结果实时计算”后，设备发生整机重启。

结论：

- preflush 排除了“安装后立即跳到未 flush thunk”的一部分竞态，但没有解决真实执行时重启。
- 当前疑点进一步收敛到：shadow patch 中的 inline branch 跳往 rustFrida 分配的 near thunk。

## 2026-06-28 直接 patch 诊断

新增下一层诊断：

- `Hook.WXSHADOW` replace 在强制诊断模式下，不再生成 near thunk。
- 直接通过 `wxshadow_patch()` 把目标函数 patch 为：
  - `mov x0, #123`
  - `ret`
- 这用于确认问题是否由“branch 到匿名 thunk”触发。
