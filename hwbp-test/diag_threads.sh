#!/system/bin/sh
# 内核侧直接测「按线程下发」的归属是否正确 —— 绕开宿主。
#
# 现象:宿主只收到 tid=32572 的命中(64 次),另两个线程 0 次,
# 而靶子每个线程都只写 25 次。64 次意味着某个节点吃到了全部线程的写入。
#
# 这里手工对每个线程分别下发,然后读 list 看每节点的真实计数。

set -u
TARGET=/data/local/tmp/hwbp_test
LOADER=/data/local/tmp/kpm_loader
LOG=/data/local/tmp/t2.log

rm -f "$LOG"
"$TARGET" --delay 25 --interval 200 --rounds 15 --threads 2 --late 1 >"$LOG" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$LOG" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" | head -1)
echo "########## pid=$PID addr=$ADDR ##########"

echo "--- 目标线程列表 ---"
ls /proc/$PID/task

echo "--- 逐线程下发 ---"
for t in $(ls /proc/$PID/task); do
    echo -n "  tid=$t -> "
    "$LOADER" control hwbp "watch $ADDR $t 4 500" 2>&1 | head -1
done

echo "--- 下发后 list(节点顺序 = list_add 插到头部,故与下发顺序相反)---"
"$LOADER" control hwbp list 2>&1 | tail -1

echo "--- 等靶子写完(15 轮 × 200ms + delay 25s)---"
sleep 34

echo "--- 结束后的 list:每节点的 addr:tid:hit_count ---"
"$LOADER" control hwbp list 2>&1 | tail -1

echo "--- 靶子各线程实际写入次数 ---"
grep '^\[w\]' "$LOG" | sed -n 's/.*tid=\([0-9]*\).*/\1/p' | sort | uniq -c

echo "--- 靶子日志里声明的线程 ---"
grep '^\[start\]' "$LOG"

kill -TERM "$TPID" 2>/dev/null
dmesg | grep -iE "hwbp" | tail -8