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

## 后续验证点

服务器基于本次提交重新编译后，需要重点确认：

- `Hook.WXSHADOW` replace 路径是否仍导致设备重启
- 日志中是否出现强制最小 thunk 的诊断日志
- `crcdemoapp` 上的行为是否对应返回值被临时固定为 `123`
