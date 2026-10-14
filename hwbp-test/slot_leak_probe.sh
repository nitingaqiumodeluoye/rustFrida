#!/system/bin/sh
# 判定「per-CPU 硬件断点槽位是否被泄漏」—— 因为 stackplz 的 system-wide 模式
# (--brk-pid=-1,默认)实测第 5 次运行起报:
#     failed to create perf ring for CPU 0: can't create perf event:
#     no space left on device
# 而 --brk-pid <pid>(task-bound)仍然可用。所以耗尽的是**每 CPU 4 个**的那个池子。
#
# 这个脚本要回答一个二选一:
#   (A) 每跑一次 stackplz 就漏一个槽位(跑 4 次后必失败)
#   (B) 不是 stackplz 漏的,而是别的动作(比如加载/卸载我们那个已归档的 KPM)
#
# 用法:slot_leak_probe.sh <runs> [--with-kpm]
#   runs       : 跑几次 stackplz
#   --with-kpm : 每次 stackplz 之前先 load + unload 一次 hwbp.kpm
#
# 输出每次的结果:OK(有命中) / ENOSPC / ERR,并在末尾给出结论。
#
# 重要:必须在**刚重启过**的机器上跑,否则已有的泄漏会污染结果。

set -u
cd /data/local/tmp || exit 1

RUNS=${1:-6}
WITH_KPM=0
USE_STACK=0
for a in "${2:-}" "${3:-}"; do
    [ "$a" = "--with-kpm" ] && WITH_KPM=1
    [ "$a" = "--stack" ] && USE_STACK=1
done

# --stack 会把 attr.Sample_type 加上 PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER,
# 并设 Sample_stack_user=8192 / Sample_regs_user=全寄存器掩码。
# 它是一个**独立变量**:早期那些成功的 stackplz 测试都带了 --stack,
# 而“连跑 6 次不漏”的验证没带。所以要分开测。
STACK_ARG=""
[ "$USE_STACK" = "1" ] && STACK_ARG="--stack"

TARGET=/data/local/tmp/hwbp_test
SP=/data/local/tmp/stackplz
LOADER=/data/local/tmp/kpm_loader
TL=/data/local/tmp/probe_t.log
OUT=/data/local/tmp/probe_out.log

echo "########## 槽位泄漏探针: runs=$RUNS with_kpm=$WITH_KPM stack=$USE_STACK ##########"
echo "--- 起靶子(一直活着,每轮都读写)---"
"$TARGET" --delay 3 --interval 250 --rounds 400 --threads 1 --late 0 \
          --mode both >"$TL" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$TL" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$TL" | head -1)
echo "    靶子 pid=$PID addr=$ADDR"

if [ -z "$PID" ] || [ -z "$ADDR" ]; then
    echo "取不到 pid/addr"; kill "$TPID" 2>/dev/null; exit 1
fi

ok=0; enospc=0; other=0
i=1
while [ "$i" -le "$RUNS" ]; do
    printf "  第 %d 次: " "$i"

    if [ "$WITH_KPM" = "1" ]; then
        "$LOADER" load /data/local/tmp/hwbp.kpm >/dev/null 2>&1
        "$LOADER" unload hwbp >/dev/null 2>&1
        printf "[已 load+unload KPM] "
    fi

    rm -f "$OUT"
    timeout -s INT 7 "$SP" --pid "$PID" --brk "$ADDR:rw" $STACK_ARG >"$OUT" 2>&1
    hits=$(grep -c "event_addr" "$OUT" 2>/dev/null || echo 0)

    if [ "$hits" != "0" ]; then
        echo "OK(命中 $hits)"
        ok=$((ok + 1))
    elif grep -q "no space left on device" "$OUT"; then
        echo "ENOSPC(槽位耗尽)"
        enospc=$((enospc + 1))
    else
        echo "其它错误:"
        grep -E "error|panic|no space" "$OUT" | head -2 | sed 's/^/        /'
        other=$((other + 1))
    fi
    i=$((i + 1))
done

echo "------------------------------------------------------"
echo "结果: OK=$ok  ENOSPC=$enospc  其它=$other"
if [ "$enospc" = "0" ]; then
    echo "结论: $RUNS 次全部成功(stack=$USE_STACK)⇒ 这条路径**不泄漏**"
elif [ "$ok" = "0" ]; then
    echo "结论: 一次都没成功 ⇒ 这台机器上槽位本来就不够(不是累积泄漏)"
else
    echo "结论: 前 $ok 次成功、之后耗尽 ⇒ **每次运行泄漏一个 per-CPU 槽位**"
fi

kill -TERM "$TPID" 2>/dev/null
