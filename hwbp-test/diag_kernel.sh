#!/system/bin/sh
# 内核侧单独诊断:绕开宿主,直接用 kpm_loader 发 ctl0 命令。
#
# 目的:把「宿主读错了」和「内核里真没有节点」分开。watch 之后立刻 list,
# 再 hits 一次,看内核到底怎么答。

set -u

TARGET=/data/local/tmp/hwbp_test
LOADER=/data/local/tmp/kpm_loader
LOG=/data/local/tmp/target.log

rm -f "$LOG"
"$TARGET" --delay 60 --interval 300 --rounds 200 --threads 0 --late 0 >"$LOG" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$LOG" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" | head -1)
TID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$LOG" | head -1)

echo "########## 靶子 pid=$PID tid=$TID addr=$ADDR ##########"

echo "--- 1) watch ---"
"$LOADER" control hwbp "watch $ADDR $TID 4 64" 2>&1 | head -3

echo "--- 2) list(内核里到底有没有这个节点)---"
"$LOADER" control hwbp list 2>&1 | tail -2

echo "--- 3) hits(期望 ret=0;hits 的输出是二进制,ret 才是重点)---"
"$LOADER" control hwbp "hits $ADDR 0 0" 2>&1 | head -2

echo "--- 4) unwatch ---"
"$LOADER" control hwbp "unwatch $ADDR $TID" 2>&1 | head -3

echo "--- 5) 再 list(应为空)---"
"$LOADER" control hwbp list 2>&1 | tail -2

echo "--- 6) 靶子日志(确认进程还活着)---"
head -4 "$LOG"

echo "--- 7) 内核日志 ---"
dmesg | grep -iE "hwbp" | tail -10

kill -TERM "$TPID" 2>/dev/null