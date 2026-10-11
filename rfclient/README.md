# rfclient — rustFrida 主机端客户端

在**主机**（Linux/macOS/Windows）上连接设备端 `rustfrida --server --listen` 的
TCP 控制服务器，像本地 REPL 一样注入、执行脚本、调用 RPC。

## 构建

> `rfclient` 是主机端二进制，已随 CI 流水线一起构建，直接取产物即可：
> `out/ci-<run-id>/rfclient`。构建方法见 [`../doc/build.md`](../doc/build.md)。

```bash
REPO=nitingaqiumodeluoye/rustFrida
gh run watch <run-id> --repo "$REPO" --exit-status
gh run download <run-id> --repo "$REPO" -D out/ci-<run-id>
chmod +x out/ci-<run-id>/rfclient
```

仅在需要本地复现 CI 失败时才手动编（仓库 `.cargo/config.toml` 默认 target 是
`aarch64-linux-android`，必须显式指定宿主三元组）：

```bash
cargo build -p rfclient --release --locked --target x86_64-unknown-linux-gnu
# 产物: target/x86_64-unknown-linux-gnu/release/rfclient
```

## 使用

```bash
# 1. 设备端启动 daemon（含 TCP 控制服务器）
adb push out/ci-<run-id>/rustfrida /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/rustfrida"
adb shell su -c "nohup /data/local/tmp/rustfrida >/data/local/tmp/rustfrida.log 2>&1 </dev/null &"

# 2. 端口转发（设备直连网段可省略）
adb forward tcp:15819 tcp:15819

# 3. 主机端
rfclient -H 127.0.0.1:15819 list                            # 列出会话
rfclient -H 127.0.0.1:15819 ps com.example                  # 枚举设备进程（可省参数列全部）
rfclient -H 127.0.0.1:15819 attach <pid>                   # 注入已运行进程
rfclient -H 127.0.0.1:15819 spawn com.example.app -l s.js  # 从主机读取脚本并注入
rfclient -H 127.0.0.1:15819 use 1                           # 复用会话（重连会补发错过的日志）

# Windows：脚本路径位于 Windows 主机，不需要推送到手机
.\rfclient.exe -H 127.0.0.1:15819 spawn com.example.app -l .\register-natives-trace.js

# Frida -U 等价用法：自动选择 ADB online 设备并建立临时 forward
.\rfclient.exe -U list
.\rfclient.exe -U --serial 7829721 spawn com.example.app -l .\register-natives-trace.js
.\rfclient.exe -U --serial 7829721 -l .\register-natives-trace.js  # 连接已唤醒的 Gadget
```

进入交互 REPL 后与设备端一致：

```
rf> jsinit
rf> jseval '"hello" + 1'
rf> loadjs script.js
rf> rpccall myMethod '[1,2]'
rf> hfl libnative.so 0x1234
rf> jslist          # 列出已加载脚本（id / 名称 / 持有 hook 数）
rf> jsdrop 2        # 卸载 #2 脚本注册的全部 hook（含日志归属前缀）
rf> capture on      # 捕获目标进程 stdout/stderr 到本连接（输出带 [out] 前缀）
rf> forward 8080    # 本机 127.0.0.1:8080 -> 目标进程内 127.0.0.1:8080
rf> forward 9222 127.0.0.1:9222   # 访问 app 内嵌调试端口，无需 adb forward
rf> forwards        # 查看进行中的转发
rf> unforward 8080
rf> exit       # 仅断开主机客户端，session 保留
rf> shutdown   # TCP 安全断开，目标进程和 hook 保留
```

### 多脚本与日志归属

`loadjs` 每次都会登记一个单调递增的脚本 id，求值期间与 hook 回调期间的
`console.log` 输出会带 `[script#N 文件名]` 前缀，多脚本同时运行时输出可归属。
`jsdrop <id>` 卸载该脚本注册的全部 native/Java hook 并释放回调。

语义边界：这是**单 JS 上下文**（非隔离沙箱），`jsdrop` 不清理脚本写入全局对象的
属性。需要干净环境时用 `jsclean` 重建引擎。

### 端口转发（open_channel）

`forward` 的 connect 发生在**目标进程的网络命名空间**里，因此能直接访问 app 自身的
本地服务（内嵌 HTTP 调试端口等）。需要 agent 与 server 均为本次协议版本。

带认证的设备端启动（并连接）：

```bash
adb shell su -c "/data/local/tmp/rustfrida --server --token s3cret"
rfclient -H 127.0.0.1:15819 --token s3cret list
rfclient -U --token s3cret -f com.example.app
```

## 协议

### 引导（文本行）

一行文本请求（`list` / `ps [filter]` / `attach <pid|name>` / `spawn <pkg> [-l -]` / `use <sid>` / `gadget`），
必要时附加 `token=<值>`（服务端以 `--token` 启动时；`list` 豁免）。
`-l -` 后紧跟一个脚本帧，脚本帧由主机端读取并发送；响应 `OK ...` / `ERR ...`
（`list` 多行 + 空行结束）。

### 帧协议

引导成功后进入帧级中继，帧格式与 `rust_frida/src/communication.rs`、
`agent/src/communication.rs` 完全一致：`1B kind + 4B LE len + payload`。

**v1（legacy）**——设备端本地 REPL 与旧客户端使用：

| 方向 | kind | 说明 |
| --- | --- | --- |
| host→agent | `1` CMD | 命令文本，响应无 reqid |
| agent→host | `0x80`~`0x87` | HELLO/LOG/COMPLETE/EVAL_OK/EVAL_ERR/RPC_OK/RPC_ERR/BYE |

**v2**——主机端 rfclient 默认使用，由 agent 的 `HELLO` 载荷 `proto=2` 宣告：

| 方向 | kind | 载荷 | 说明 |
| --- | --- | --- | --- |
| host→agent | `4` CMD_TAGGED | `4B LE reqid + 命令` | 响应回填同一 reqid |
| host→agent | `5` PING | 空 | 链路保活探测，agent 回 PONG |
| agent→host | `0x90`~`0x94` | `4B LE reqid + 载荷` | EVAL_OK/ERR、RPC_OK/ERR、COMPLETE |
| server→host | `0x95` EVENT | TSV `detach\treason=…\tpid=…` | 结构化事件（会话结束原因） |
| agent→host | `0x97` PONG | 空 | 保活应答 |
| server→host | `0x95` EVENT | TSV `replay\tframes=N\tbytes=M\tdropped=K` | 重连补发提示 |
| host→agent | `6` CHANNEL_OPEN | `4B LE channel_id + 地址` | 请 agent 在目标进程内 connect |
| 双向 | `0x98` CHANNEL_DATA | `4B LE channel_id + 原始字节` | 通道数据 |
| 双向 | `0x99` CHANNEL_CLOSE | `4B LE channel_id` | 关闭通道 |
| agent→host | `0x9A` CHANNEL_OPENED | `4B LE channel_id + 1B status + 消息` | 连接结果（0=成功） |

要点：

- **reqid 匹配**：`EVAL_OK` / `RPC_OK` 等同语义响应通过 reqid 与请求配对，超时后被
  放弃的迟到响应会打印为 `[stale]` 并丢弃，不会污染下一条命令（修复 legacy 单槽缺陷）。
  `reqid=0` 保留给 v1 语义，因此设备端 REPL/服务内部命令完全不受影响。
- **心跳**：客户端空闲时每 15s 发 PING，连续 45s 无任何入站帧即判定链路半开并退出。
- **协议协商**：agent 一律在 HELLO 里带 `proto=2`；客户端最多等 1.5s，超时或载荷不带
  `proto=2` 时退回 v1 语义（兼容旧 agent / 旧 gadget）。
- **认证**：`rustfrida --server --token <T>`（或 gadget 配置 `interaction.auth_token`）启用后，
  除 `list` 外的引导请求必须携带 `token=<T>`；比对为恒定时间。客户端用 `--token`
  或环境变量 `RFCLIENT_TOKEN` 提供。
- **断线补投**：客户端断开后 session 仍持有有界积压（上限 4 MB，超限丢最老的帧并计数），
  只缓存 LOG/EVENT（属于已消失客户端的响应帧不补发）。`use <sid>` 重连时先收到
  `[event] replay frames=… dropped=…`，再按原顺序补发错过的日志，随后转入实时输出。

- **多脚本归属**：`loadjs` 登记递增脚本 id，日志前缀 `[script#N 名称]`；`jslist`/`jsdrop` 管理。
- **stdout/stderr 捕获**：agent 在目标进程里 `pipe`+`dup2` fd 1/2，输出以 LOG 帧回流（前缀 `[out]`）。
  没人在读时管道会写满，所以捕获期间必须保持主机连接。
- **open_channel**：`forward` 在本机监听并让 agent 在目标进程里 connect，帧在控制连接上多路复用。
  通道中继线程在 agent 卸载前会被 `shutdown_all()` 收尾（否则会执行已 unmap 的代码）。

## 说明

- `jsrepl` 是设备端子 REPL（读设备 stdin），TCP 下不可用，请用 `jseval` 逐行求值
- `spawn/attach -l` 的脚本由主机端读取，通过控制连接传输，在目标进程 resume 前加载；手机端不需要脚本文件
- `-U` 使用 `adb devices` 选择 online 设备，再自动执行临时 `adb -s <serial> forward`；客户端退出后清理该转发
- `-U` 默认连接设备端 TCP `15819`，可用 `--device-port` 指定其他 `rustfrida --listen` 端口
- `-U -f <包名>` 会优先使用 `rustfrida-server`；没有 server 时自动启动内置 Gadget 的应用并连接
- `attach <名字>` 先精确匹配，再退化为大小写不敏感的子串匹配；多匹配会列出候选并要求用 PID 精确指定
- `ps [filter]` 枚举设备进程（输出 `PID\tNAME`），免去手工 `adb shell ps | grep`
- 已运行的 Gadget 也可用 `-U Gadget -l <脚本>` 直接连接，通常只用于诊断
- stdin 关闭时客户端会继续接收日志，默认在连续 5 秒无新消息后断开；可用 `--linger <秒>` 调整，`--linger 0` 恢复立即断开
- TCP 客户端断开不会自动 shutdown session，可使用 `use <sid>` 重新连接；TCP 的 `shutdown` 会安全 detach，目标进程和 hook 保留
- 同一会话被多个客户端 `use` 会互相干扰（v1 未做互斥）
- 协议 v2 的 reqid 匹配让每条命令的响应可独立归属，`[stale]` 行表示收到了已超时请求的
  迟到响应（属正常保护行为，不是错误）；心跳超时（默认 45s 无响应）会以退出码 1 结束，
  可用 `--linger 0` + 手动 `use` 重连规避长时间无输出的场景
- `--token` 也可用环境变量 `RFCLIENT_TOKEN` 提供；`list` 无需认证，便于 `-U` 探测端点类型
