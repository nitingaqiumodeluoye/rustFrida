# rfclient — rustFrida 主机端客户端

在**主机**（Linux/macOS/Windows）上连接设备端 `rustfrida --server --listen` 的
TCP 控制服务器，像本地 REPL 一样注入、执行脚本、调用 RPC。

## 构建

> 仓库 `.cargo/config.toml` 默认 target 是 `aarch64-linux-android`，
> 构建 rfclient 时需显式指定主机 target。

```bash
# 主机三元组示例（按本机 rustup 已安装的 target 选择）
cargo build -p rfclient --release --target x86_64-unknown-linux-gnu
# 产物: target/x86_64-unknown-linux-gnu/release/rfclient
```

## 使用

```bash
# 1. 设备端启动 daemon（含 TCP 控制服务器）
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/
adb shell su -c "chmod 755 /data/local/tmp/rustfrida"
adb shell su -c "nohup /data/local/tmp/rustfrida >/data/local/tmp/rustfrida.log 2>&1 </dev/null &"

# 2. 端口转发（设备直连网段可省略）
adb forward tcp:15819 tcp:15819

# 3. 主机端
rfclient -H 127.0.0.1:15819 list                            # 列出会话
rfclient -H 127.0.0.1:15819 attach <pid>                   # 注入已运行进程
rfclient -H 127.0.0.1:15819 spawn com.example.app -l s.js  # 从主机读取脚本并注入
rfclient -H 127.0.0.1:15819 use 1                           # 复用会话

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
rf> exit       # 仅断开主机客户端，session 保留
rf> shutdown   # TCP 安全断开，目标进程和 hook 保留
```

## 协议

- **引导**：一行文本请求（`list` / `attach <pid|name>` / `spawn <pkg> [-l -]` / `use <sid>`），
  `-l -` 后紧跟一个脚本帧，脚本帧由主机端读取并发送；响应 `OK ...` / `ERR ...`
  （`list` 多行 + 空行结束）
- **中继**：引导成功后进入帧级中继，帧协议与 `rust_frida/src/communication.rs` 完全一致
  （`1B kind + 4B LE len + payload`），主机端 REPL 与设备端本地 REPL 命令面一致

## 说明

- `jsrepl` 是设备端子 REPL（读设备 stdin），TCP 下不可用，请用 `jseval` 逐行求值
- `spawn/attach -l` 的脚本由主机端读取，通过控制连接传输，在目标进程 resume 前加载；手机端不需要脚本文件
- `-U` 使用 `adb devices` 选择 online 设备，再自动执行临时 `adb -s <serial> forward`；客户端退出后清理该转发
- `-U` 默认连接设备端 TCP `15819`，可用 `--device-port` 指定其他 `rustfrida --listen` 端口
- `-U -f <包名>` 会优先使用 `rustfrida-server`；没有 server 时自动启动内置 Gadget 的应用并连接
- 已运行的 Gadget 也可用 `-U Gadget -l <脚本>` 直接连接，通常只用于诊断
- stdin 关闭时客户端会继续接收日志，默认在连续 5 秒无新消息后断开；可用 `--linger <秒>` 调整，`--linger 0` 恢复立即断开
- TCP 客户端断开不会自动 shutdown session，可使用 `use <sid>` 重新连接；TCP 的 `shutdown` 会安全 detach，目标进程和 hook 保留
- 同一会话被多个客户端 `use` 会互相干扰（v1 未做互斥）
