#!/system/bin/sh
# 在设备上跑:靶子 + 观察者,同一个 shell 里,保证两者都活到结束。
#
# 为什么必须写成一个脚本:adb shell 一断开就会带走它启动的后台进程,
# 而靶子必须活得比观察者的启动更久。把它们放在同一条连接里最省事。

set -u

TARGET=/data/local/tmp/hwbp_test
OBS=/data/local/tmp/rustfrida
LOG=/data/local/tmp/target.log

DELAY=${1:-14}
OBS_SECS=${2:-22}
MODE=${3:-write}
LATE=${4:-1}

rm -f "$LOG"

# 先起靶子,它会立刻打印 pid 和地址
"$TARGET" --delay "$DELAY" --interval 300 --rounds 25 \
          --threads 2 --late "$LATE" --mode "$MODE" >"$LOG" 2>&1 &
TPID=$!

# 等它把地址打出来
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$LOG" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" | head -1)

echo "########## 靶子 pid=$PID 地址=$ADDR ##########"

if [ -z "$PID" ] || [ -z "$ADDR" ]; then
    echo "错误: 没从靶子日志里取到 pid/地址"
    cat "$LOG"
    kill "$TPID" 2>/dev/null
    exit 1
fi

# 观察者放在前台跑,超时用 SIGINT 触发它的优雅退出
timeout -s INT "$OBS_SECS" "$OBS" --pid "$PID" --hwbp-watch "$ADDR"
OBSRC=$?

echo "########## 观察者退出码=$OBSRC ##########"

# 等靶子自己收工(它 rounds 跑完就退出);不等也行,这里给最多 20 秒
for i in $(seq 1 20); do
    kill -0 "$TPID" 2>/dev/null || break
    sleep 1
done
kill -TERM "$TPID" 2>/dev/null

echo "########## 靶子日志 ##########"
cat "$LOG"

echo "########## hwbp 内核侧状态 ##########"
dmesg | grep -iE "hwbp" | tail -12