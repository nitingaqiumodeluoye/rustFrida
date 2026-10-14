#!/system/bin/sh
# 内核侧直接测「读 / 读写观察点」—— 绕开宿主,判据只有一个:
#   靶子实际访问次数 == 内核记录次数,且读写方向对得上。
#
# 用法:diag_access.sh [w|r|rw] [target-mode]
#   默认 `rw both` —— 靶子同时读写,观察点盯 rw,两边计数应各自对上。
#
# 为什么要有这个脚本:宿主那条链路上「靶子日志」和「内核计数」在同一个终端里
# 混着打印,对不上时不好判断是哪一层的问题。这里把内核的节点计数单独拿出来,
# 和靶子的 [w]/[r] 行数直接比。

set -u
TARGET=/data/local/tmp/hwbp_test
LOADER=/data/local/tmp/kpm_loader
LOG=/data/local/tmp/t_access.log

TYPE=${1:-rw}
TGTMODE=${2:-both}

# 观察点类型 -> 靶子该跑什么模式(没显式指定时按观察点类型推)
if [ $# -lt 2 ]; then
    case "$TYPE" in
        w)  TGTMODE=write ;;
        r)  TGTMODE=read ;;
        rw) TGTMODE=both ;;
    esac
fi

rm -f "$LOG"
"$TARGET" --delay 25 --interval 200 --rounds 15 --threads 2 --late 1 \
          --mode "$TGTMODE" >"$LOG" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$LOG" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" | head -1)
echo "########## type=$TYPE target=$TGTMODE pid=$PID addr=$ADDR ##########"

if [ -z "$PID" ] || [ -z "$ADDR" ]; then
    echo "错误: 没从靶子日志里取到 pid/地址"
    cat "$LOG"
    kill "$TPID" 2>/dev/null
    exit 1
fi

echo "--- 逐线程下发(type=$TYPE) ---"
for t in $(ls /proc/$PID/task); do
    echo -n "  tid=$t -> "
    "$LOADER" control hwbp "watch $ADDR $t 4 500 $TYPE" 2>&1 | head -1
done

echo "--- 下发后 list(格式 地址:tid:命中数:类型:句柄)---"
"$LOADER" control hwbp list 2>&1 | tail -1

echo "--- 等靶子写完(15 轮 × 200ms + delay 25s)---"
sleep 34

echo "--- 结束后的 list ---"
"$LOADER" control hwbp list 2>&1 | tail -1

echo "--- 靶子各线程实际 读/写 次数 ---"
grep '^\[w\]' "$LOG" | sed -n 's/.*tid=\([0-9]*\).*/\1/p' | sort | uniq -c | sed 's/^/  写 /'
grep '^\[r\]' "$LOG" | sed -n 's/.*tid=\([0-9]*\).*/\1/p' | sort | uniq -c | sed 's/^/  读 /'

echo "--- 靶子日志里声明的线程 ---"
grep '^\[start\]' "$LOG"

echo "--- 内核侧命中方向统计(前 3 条全参数 + 出错行)---"
dmesg | grep -iE "hwbp: wp trap|hwbp: watch armed|bad type" | tail -12

kill -TERM "$TPID" 2>/dev/null
