# rfclient-gui — rustFrida 主机端图形客户端

`rfclient`（CLI）的图形版本。两者共用 [`rfclient-core`](../rfclient-core)：
协议帧、reqid 匹配、心跳、端口转发、引导握手全在 core 里，GUI 只负责界面。

拿到产物（CI 与 CLI 同一个 job，同一个 artifact）：

```bash
gh run download <run-id> --repo nitingaqiumodeluoye/rustFrida \
  -n rfclient-windows-x86_64-<sha> -D out/win
# out/win/rfclient.exe      — 命令行
# out/win/rfclient-gui.exe  — 图形界面
```

两个 exe 都用 `x86_64-pc-windows-msvc` + `+crt-static` 构建，**不需要安装
VC++ 可再发行组件包**，拷到任意 Windows x64 上直接跑。

本地构建（仓库 `.cargo/config.toml` 默认 target 是 Android，必须显式指定宿主三元组）：

```bash
cargo build -p rfclient-gui --release --target x86_64-pc-windows-msvc
```

## 界面

```
┌──────────────────────────────────────────────────────────────┐
│ 服务器 [127.0.0.1:15819] 令牌 [****] ● 已连接  [刷新会话] [刷新进程] [断开] │
├───────────────────────┬──────────────────────────────────────┤
│ 进程  过滤[____]       │ 脚本 | 求值/命令 | 端口转发 | 输出捕获  │
│  PID    名称    注入   │                                      │
│  4242   com.a  [注入]  │  文件名 [script.js] [选择文件…]        │
│                       │  ┌────────────────────────────────┐  │
│ 会话                  │  │ // 脚本内容                    │  │
│  ID PID 标签    接入   │  └────────────────────────────────┘  │
│  1  4242 com.a [接入]  │  [加载脚本] [刷新列表] [清空引擎]      │
│                       │                                      │
│ 启动并注入             │  ID 名称   native java 字节          │
│ [com.example.app][spawn]│  1 hook.js   3      2   1024 [卸载]  │
│ [连接已运行的 Gadget]  │                                      │
├───────────────────────┴──────────────────────────────────────┤
│ 日志  ☑自动滚动  过滤[____]  [清空]                            │
│ [client] agent 已就绪（协议 v2：reqid 匹配 + 心跳）             │
│ [agent] [script#1 hook.js] hit!                               │
│ [out]   目标进程的 stdout                                     │
│ [forward] 转发已启动: 127.0.0.1:8080 → 127.0.0.1:80            │
└──────────────────────────────────────────────────────────────┘
```

- **日志常驻底部**，不在标签页里：调试时它是主要信息面，不该需要切换才能看见。
- 日志按来源着色与加前缀（`[agent]` / `[out]` / `[event]` / `=>` / `[错误]` / `[forward]`），
  `[script#N 名字]` 前缀来自 agent 的脚本归属，用来分辨是哪份脚本打的日志。
- 日志是**环形缓冲**（上限 20k 行）。控制连接的 LOG 帧是无节流的，
  只追加不截断就只是把内存问题从事件队列搬到 UI 列表里。

## 首版范围

已实现：连接（attach / use / spawn / gadget）、会话表、进程表、脚本加载与卸载、
`jseval`、原始命令下发、端口转发管理、输出捕获开关。

刻意**没有**做：

- **多会话标签页**。一条 TCP 连接只承载一个会话（这是协议本身的结构，
  不是界面的取舍），换目标就是重连。要并行看多个目标得有多个连接，
  那需要先把 GUI 的状态改成「一个连接一个面板」，属于下一版的事。
- **结构化数据视图**。agent 目前没有 JS `send()`/`on('message')`，
  拿不到结构化的表格数据，所以脚本/进程表都只能靠解析文本应答。
- **打包成单文件**。两个 exe 各自独立，没有安装器。

## 实现上几个刻意的选择

- **渲染后端用 glow（OpenGL），不用 eframe 默认的 wgpu**：调试工具经常跑在虚拟机、
  远程桌面、老显卡上，那些环境里 DX12/Vulkan 未必可用，OpenGL 几乎总能起来；
  依赖树也小很多。
- **后台线程从不直接碰界面**：它们只写日志环形缓冲与连接状态，再通过一个
  `Wake` 回调（内部就是 `egui::Context::request_repaint`）让界面重绘。
  界面的唯一写入者是渲染帧。见 `src/conn.rs`。
- **事件必须由常驻线程排空**，不能指望「渲染帧里 drain 一次」：窗口最小化或
  用户不动鼠标时 egui 可能完全不渲染，那时没人排空，队列会一直涨。
- **不做 `std::process::exit`**：core 把断连上报成 `Event::Disconnected`，
  GUI 只更新状态栏。CLI 之所以要退出进程，是因为 `rustyline::readline`
  无法被取消 —— 那是终端特有的限制，不该传染到图形界面。
- **建连与查询都在后台线程**：最长 10 秒的 TCP 等待放在 UI 线程上就是界面假死。

## 模块

```
src/main.rs   eframe 启动参数（窗口尺寸、glow 后端）
src/app.rs    界面布局与交互，把点击翻译成 Client 调用
src/conn.rs   连接/查询/事件排空/在途命令（不依赖 egui，只靠 Wake 回调）
src/logbuf.rs 日志环形缓冲与来源着色
```
