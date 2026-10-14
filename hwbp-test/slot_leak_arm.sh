#!/system/bin/sh
# 补充探针:测我们那个已归档 KPM 的 **arm → release** 路径会不会漏槽位。
#
# 为什么单独测这个:前面的 slot_leak_probe.sh 证明了
#   (a) stackplz 的 system-wide 模式连跑 6 次不漏;
#   (b) 我们 KPM 的 load/unload(不 arm 任何观察点)连做 5 次也不漏。
# 但之前 diag 脚本**真的 arm 过** per-task 观察点再 clear/unload —— 那条路径
# 才是唯一没测过的。内核的约束是同一池子里 tsk_pinned 与 cpu_pinned 一起算
# (kernel/events/hw_breakpoint.c:  max(cpu_pinned)+max(tsk_pinned)+... < HBP_NUM),
# 所以**一个漏掉的 task-bound 事件一样能堵死 system-wide 的 open**。
#
# 用法:slot_leak_arm.sh <cycles>
# 每轮:load → watch(per-task) → unwatch → unload,然后跑一次 stackplz 看还开不开得了。

set -u
cd /data/local/tmp || exit 1

CYCLES=${1:-6}
TARGET=/data/local/tmp/hwbp_test
SP=/data/local/tmp/stackplz
LOADER=/data/local/tmp/kpm_loader
TL=/data/local/tmp/arm_t.log
OUT=/data/local/tmp/arm_out.log

echo "########## arm/release 泄漏探针: cycles=$CYCLES ##########"
"$TARGET" --delay 3 --interval 250 --rounds 200 --threads 1 --late 0 \
          --mode both >"$TL" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$TL" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$TL" | head -1)
echo "    靶子 pid=$PID addr=$ADDR"
if [ -z "$PID" ] || [ -z "$ADDR" ]; then
    echo "取不到 pid/addr"; kill "$TPID" 2>/dev/null; exit 1
fi

i=1
while [ "$i" -le "$CYCLES" ]; do
    printf "  第 %d 轮: " "$i"

    "$LOADER" load /data/local/tmp/hwbp.kpm >/dev/null 2>&1
    T=$(ls /proc/$PID/task | head -1)
    "$LOADER" control hwbp "watch $ADDR $T 4 500 rw" >/dev/null 2>&1
    sleep 1
    n=$("$LOADER" control hwbp list 2>&1 | tail -1 | grep -o "nodes=[0-9]*" | head -1)
    "$LOADER" control hwbp unwatch "$ADDR" 0 >/dev/null 2>&1
    "$LOADER" unload hwbp >/dev/null 2>&1
    printf "[arm/clear done, %s] " "$n"

    rm -f "$OUT"
    timeout -s INT 6 "$SP" --pid "$PID" --brk "$ADDR:rw" >"$OUT" 2>&1
    hits=$(grep -c "event_addr" "$OUT" 2>/dev/null || echo 0)
    if [ "$hits" != "0" ]; then
        echo "stackplz OK(命中 $hits)"
    elif grep -q "no space left on device" "$OUT"; then
        echo "stackplz ENOSPC ← 槽位被这轮的 arm/release 漏掉了"
    else
        echo "stackplz 其它错误:"; grep -E "error|panic" "$OUT" | head -1 | sed 's/^/      /'
    fi
    i=$((i + 1))
done

echo "------------------------------------------------------"
echo "若每一轮都 OK ⇒ 我们的 arm/release 路径不漏槽位。"
echo "若某轮开始 ENOSPC ⇒ 就是这条路径在漏,且每轮漏 1 个(归档模块的一个真 bug)。"
kill -TERM "$TPID" 2>/dev/null
