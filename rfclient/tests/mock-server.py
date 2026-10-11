#!/usr/bin/env python3
"""rfclient 重构后的本地回归用 mock 控制服务器。

只实现协议里被 CLI 用到的那几条路径，用来在没有设备的情况下验证
「引导握手 + 帧收发 + 事件/应答分流」是否仍然正确。

用法:
    python3 -u rfclient/tests/mock-server.py <port> [mode]

mode:
    list      -- 只回 list 的多行文本响应
    ps        -- 回 PID/NAME 表，并把收到的整行回显成进程名（用于断言令牌已注入）
    session   -- 回 OK（含 proto=2），帧模式：HELLO/LOG + 对 tagged 命令回应答
    legacy    -- 回 OK（不带 proto），HELLO 声明 proto=1，用 legacy 帧收发
    stale     -- 同 session，但额外先发一个 reqid 不匹配的应答（验证 stale 丢弃）
"""
import socket
import struct
import sys
import threading

FRAME_HELLO = 0x80
FRAME_LOG = 0x81
FRAME_EVAL_OK_TAGGED = 0x90
FRAME_EVAL_OK = 0x83
FRAME_CMD = 1
FRAME_CMD_TAGGED = 4
FRAME_PING = 5
FRAME_PONG = 0x97


def frame(kind: int, payload: bytes) -> bytes:
    return bytes([kind]) + struct.pack("<I", len(payload)) + payload


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def read_line(conn: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        buf += read_exact(conn, 1)
    return buf.decode(errors="replace").strip()


def serve(conn: socket.socket, mode: str) -> None:
    line = read_line(conn)
    print(f"[mock] bootstrap: {line!r}", flush=True)

    if mode == "list":
        # 会话表：LABEL 列非 karina → 判定为 server
        conn.sendall("ID\tPID\tLABEL\tSTATUS\n1\t1234\tcom.example\tactive\n\n".encode())
        return

    if mode == "ps":
        # 把收到的引导行原样作为进程名回显：这样「令牌有没有带上」
        # 就变成一条可直接断言的输出，不必去猜请求内容。
        conn.sendall("PID\tNAME\n".encode())
        conn.sendall(("4242\t" + line + "\n").encode())
        conn.sendall(b"\n")
        return

    # 交互模式：先回 OK 行（带 proto=2 提示），再发帧
    # 交互模式：先回 OK 行，再发帧。
    # legacy 模式刻意不带 proto= 提示，迫使客户端走「等 HELLO 再定案」的分支。
    legacy = mode == "legacy"
    if legacy:
        conn.sendall(b"OK sid=1 pid=1234\n")
        conn.sendall(frame(FRAME_HELLO, b"proto=1"))
    else:
        conn.sendall(b"OK sid=1 pid=1234 proto=2\n")
        conn.sendall(frame(FRAME_HELLO, b"proto=2"))
    conn.sendall(frame(FRAME_LOG, b"mock ready\n"))
    if mode == "stale":
        # 一个没人认领的 reqid：客户端应打印 [stale] 并丢弃，而不是误配给下一条命令
        conn.sendall(frame(FRAME_EVAL_OK_TAGGED, struct.pack("<I", 9999) + b"ghost"))

    while True:
        try:
            kind = read_exact(conn, 1)[0]
        except EOFError:
            print("[mock] client closed", flush=True)
            return
        length = struct.unpack("<I", read_exact(conn, 4))[0]
        payload = read_exact(conn, length) if length else b""

        if kind == FRAME_CMD:
            cmd = payload.decode(errors="replace")
            print(f"[mock] cmd (legacy): {cmd!r}", flush=True)
            if cmd.startswith("shutdown"):
                conn.sendall(frame(0x87, b""))
                return
            conn.sendall(frame(FRAME_EVAL_OK, f"legacy-echo:{cmd}".encode()))
        elif kind == FRAME_CMD_TAGGED:
            reqid = struct.unpack("<I", payload[:4])[0]
            cmd = payload[4:].decode(errors="replace")
            print(f"[mock] cmd reqid={reqid}: {cmd!r}", flush=True)
            if cmd.startswith("shutdown"):
                conn.sendall(frame(0x87, b""))  # BYE
                return
            # 回一个 tagged EVAL_OK，内容里带上收到的命令，便于断言路由正确
            conn.sendall(frame(FRAME_EVAL_OK_TAGGED, struct.pack("<I", reqid) + f"echo:{cmd}".encode()))
        elif kind == FRAME_PING:
            conn.sendall(frame(FRAME_PONG, b""))
        else:
            print(f"[mock] unhandled frame kind={kind}", flush=True)


def main() -> int:
    port = int(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "session"
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    print(f"[mock] listening 127.0.0.1:{port} mode={mode}", flush=True)

    def accept_loop() -> None:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=serve, args=(conn, mode), daemon=True).start()

    accept_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
