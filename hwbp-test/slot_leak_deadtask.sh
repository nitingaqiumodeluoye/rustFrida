#!/system/bin/sh
# 最后一个候选:观察点**还 armed 时目标线程就死了** —— 这才是之前 diag 脚本的真实用法。
#
# 为什么单独测:diag_threads.sh / diag_access.sh 都是
#   起靶子 → 逐线程 watch → 等它跑完 → kill -TERM 靶子
# 而**从来没有 unwatch**。于是节点留在链表里、bp_handle 指向的内核事件所依附的
# 线程已经消失。之后靠 clear/unload 才释放。
#
# 内核里 per-task 事件分两段生命周期:
#   1) 任务退出时 perf_event_exit_task() 把事件从上下文里摘掉;
#   2) 但**事件对象本身**要等拥有者释放 —— 我们是内核侧创建者(没有 fd),
#      只有调用 unregister_hw_breakpoint/perf_event_release_kernel 才归还槽位。
# 若第 2 步在「任务已死」的情形下漏掉,槽位就永久占着 ——
# 而且因为整个池子一起算(max(cpu_pinned)+max(tsk_pinned) < HBP_NUM),
# 它会连带堵死 stackplz 的 system-wide open,报 ENOSPC。
#
# 用法:slot_leak_deadtask.sh <rounds>
# 每轮:起靶子 → load KPM → watch → **kill 靶子** → unwatch → unload → stackplz 探针

set -u
cd /data/local/tmp || exit 1

ROUNDS=${1:-6}
TARGET=/data/local/tmp/hwbp_test
SP=/data/local/tmp/stackplz
LOADER=/data/local/tmp/kpm_loader
TL=/data/local/tmp/dt_t.log
OUT=/data/local/tmp/dt_out.log

# 常驻一个「探针靶子」给 stackplz 用(它不能死)
"$TARGET" --delay 2 --interval 250 --rounds 400 --threads 1 --late 0 \
          --mode both >/data/local/tmp/dt_probe.log 2>&1 &
PPID_T=$!
sleep 2
PPORT=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' /data/local/tmp/dt_probe.log | head -1)
PADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' /data/local/tmp/dt_probe.log | head -1)
echo "########## 死线程泄漏探针: rounds=$ROUNDS ##########"
echo "    探针靶子 pid=$PPORT addr=$PADDR"

i=1
while [ "$i" -le "$ROUNDS" ]; do
    printf "  第 %d 轮: " "$i"

    # 1) 起一个一次性靶子
    rm -f "$TL"
    "$TARGET" --delay 2 --interval 250 --rounds 5 --threads 2 --late 0 \
              --mode both >"$TL" 2>&1 &
    TP=$!
    sleep 2
    VPID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$TL" | head -1)
    VADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$TL" | head -1)

    # 2) load + 逐线程 watch(复刻 diag 脚本:不 unwatch 就杀)
    "$LOADER" load /data/local/tmp/hwbp.kpm >/dev/null 2>&1
    armed=0
    for t in $(ls /proc/$VPID/task 2>/dev/null); do
        "$LOADER" control hwbp "watch $VADDR $t 4 500 rw" >/dev/null 2>&1 && armed=$((armed + 1))
    done

    # 3) 观察点还在,靶子就没了 —— 关键的一步
    kill -9 "$TP" 2>/dev/null
    wait "$TP" 2>/dev/null
    printf "[armed=%d 后杀掉靶子] " "$armed"

    # 4) 释放(此时事件依附的线程已消失)
    "$LOADER" control hwbp clear >/dev/null 2>&1
    "$LOADER" unload hwbp >/dev/null 2>&1

    # 5) 探针:system-wide 还能不能开
    rm -f "$OUT"
    timeout -s INT 6 "$SP" --pid "$PPORT" --brk "$PADDR:rw" >"$OUT" 2>&1
    hits=$(grep -c "event_addr" "$OUT" 2>/dev/null || echo 0)
    if [ "$hits" != "0" ]; then
        echo "stackplz OK(命中 $hits)"
    elif grep -q "no space left on device" "$OUT"; then
        echo "stackplz ENOSPC ← 死线程上的观察点没还槽位"
    else
        echo "stackplz 其它错误:"; grep -E "error|panic" "$OUT" | head -1 | sed 's/^/      /'
    fi
    i=$((i + 1))
done

echo "------------------------------------------------------"
echo "全部 OK ⇒ 这条路径也不漏;ENOSPC ⇒ 找到了泄漏源。"
kill -TERM "$PPID_T" 2>/dev/null
