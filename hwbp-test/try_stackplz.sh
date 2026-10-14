#!/system/bin/sh
# 用 fork 构建的 stackplz 测「内存读写监控」—— 同一个靶子,三种断点类型各测一次。
# 判据:
#   1. stackplz 有没有报出事件(用户态 perf_event_open(PERF_TYPE_BREAKPOINT) 通不通)
#   2. 报出的东西里有没有 tid(「谁」)与调用栈
#   3. r / w 能不能把方向分开(靶子日志的 [w]/[r] 行数做真值)
#
# 用法:try_stackplz.sh [r|w|rw] [target-mode]
#   缺省 rw / both(读写混合,便于看方向)
set -u

# stackplz 全程用**相对路径**读写自己的资产与配置:
#   RestoreAssets()  → assets.RestoreAsset(ExecPath, "preload_libs/libstackplz.so")
#   root.go:261      → assets.RestoreAsset(exec_path, "user/config/config_syscall_*.json")
#                     紧接着 ioutil.ReadFile("user/config/...")(相对 CWD!)
# 所以它必须在**自己所在目录**里跑 —— 否则第一步能把文件放到 /data/local/tmp,
# 第二步却去 CWD 找,直接 panic:
#     open user/config/config_syscall_aarch64.json: no such file or directory
# 实测踩过:su 起来的 CWD 是 /。
cd /data/local/tmp || exit 1

TARGET=/data/local/tmp/hwbp_test
SP=/data/local/tmp/stackplz
TL=/data/local/tmp/st_t.log
OUT=/data/local/tmp/st_out.log

TYPE=${1:-rw}
TGTMODE=${2:-both}
if [ $# -lt 2 ]; then
    case "$TYPE" in
        r)  TGTMODE=both ;;
        w)  TGTMODE=both ;;
        rw) TGTMODE=both ;;
    esac
fi

rm -f "$TL" "$OUT"

"$TARGET" --delay 6 --interval 300 --rounds 18 --threads 1 --late 0 \
          --mode "$TGTMODE" >"$TL" 2>&1 &
TPID=$!
sleep 2

PID=$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$TL" | head -1)
ADDR=$(sed -n 's/.*被观察地址 = \(0x[0-9a-fA-F]*\).*/\1/p' "$TL" | head -1)

echo "########## 断点类型=$TYPE  靶子模式=$TGTMODE ##########"
echo "########## 靶子 pid=$PID addr=$ADDR ##########"
if [ -z "$PID" ] || [ -z "$ADDR" ]; then
    echo "取不到 pid/addr"; cat "$TL"; kill "$TPID" 2>/dev/null; exit 1
fi

# 我们的 KPM 观察点若在,会占掉 WRP 槽位(每 AMD64... 每 arm64 CPU 4 个),
# 先把它们清干净,保证这次测的是 stackplz 自己的路径。
/data/local/tmp/kpm_loader control hwbp clear >/dev/null 2>&1

echo "########## stackplz --brk $ADDR:$TYPE --stack ##########"
timeout -s INT 15 "$SP" --pid "$PID" --brk "$ADDR:$TYPE" --stack >"$OUT" 2>&1
RC=$?
echo "########## stackplz 退出码=$RC ##########"

echo "---- 输出总行数: $(wc -l < "$OUT") ----"
echo "---- 前 30 行 ----"
head -30 "$OUT"
echo "---- 含 event_addr 的行数(命中)----"
grep -c "event_addr" "$OUT" 2>/dev/null || echo 0

echo "---- 靶子实际访问(真值)----"
grep -c '^\[w\]' "$TL" | sed 's/^/  写 /'
grep -c '^\[r\]' "$TL" | sed 's/^/  读 /'
grep -E '^\[done\]' "$TL"
grep -E '^\[start\]' "$TL"

kill -TERM "$TPID" 2>/dev/null
