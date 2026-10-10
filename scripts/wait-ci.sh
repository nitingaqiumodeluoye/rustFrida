#!/usr/bin/env bash
# 等 CI 跑完并（可选）下载产物。
#
# 为什么不用一段裸的 `for i in $(seq 1 N); do gh run list ...; sleep N; done`：
# 那种写法一旦 headSha 没匹配上（推送还没产生 run、或 sha 前缀取错）就会
# 无限静默空转，既不输出进度也不超时，看起来和"卡死"没区别。
# 本脚本要求：
#   1. 每次轮询都打印状态（看得见在动）；
#   2. 有硬超时（默认 30 分钟）；
#   3. 等到 run 出现并 completed 后，用 --exit-status 拿准确结论；
#   4. 失败时直接打印关键 error 行，不用再手工翻 log。
#
# 用法：
#   scripts/wait-ci.sh                       # 等最新一次 run
#   scripts/wait-ci.sh --sha 3f57c5d         # 等某个 commit 的 run
#   scripts/wait-ci.sh --download out/ci     # 完成后下载产物到 out/ci
#   scripts/wait-ci.sh --sha 3f57c5d --download out/ci
#   scripts/wait-ci.sh --timeout 3600
#
# 退出码：0 = success；1 = 失败/超时/出产物缺失。

set -uo pipefail

REPO="${RF_REPO:-nitingaqiumodeluoye/rustFrida}"
SHA=""
DOWNLOAD=""
TIMEOUT="${TIMEOUT:-1800}"
INTERVAL="${INTERVAL:-15}"

while [ $# -gt 0 ]; do
    case "$1" in
        --sha)      SHA="${2:-}"; shift 2 ;;
        --download) DOWNLOAD="${2:-}"; shift 2 ;;
        --timeout)  TIMEOUT="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --repo)     REPO="${2:-}"; shift 2 ;;
        -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "未知参数: $1" >&2; exit 1 ;;
    esac
done

command -v gh >/dev/null 2>&1 || { echo "gh 不在 PATH 上" >&2; exit 1; }

# 定位 run：优先按 sha 精确找，找不到就取最新一条。
find_run() {
    local json
    if [ -n "$SHA" ]; then
        json="$(gh run list --repo "$REPO" --limit 20 \
            --json databaseId,headSha,status,conclusion,displayTitle,createdAt 2>/dev/null \
            | tr -d '\n' \
            | sed 's/},{/}\n{/g')"
        printf '%s\n' "$json" | grep -F "\"headSha\":\"$SHA" | head -1
    else
        gh run list --repo "$REPO" --limit 1 \
            --json databaseId,headSha,status,conclusion,displayTitle,createdAt 2>/dev/null \
            | tr -d '\n' | sed 's/^\[//; s/\]$//'
    fi
}

field() { printf '%s' "$1" | grep -oE "\"$2\":(\"[^\"]*\"|[a-z0-9]+)" | head -1 | sed 's/^[^:]*://; s/^"//; s/"$//'; }

echo "仓库: $REPO   超时: ${TIMEOUT}s   轮询: ${INTERVAL}s"
[ -n "$SHA" ] && echo "等待 commit: $SHA" || echo "等待最新一次 run"
echo

START=$SECONDS
RUN_ID=""
LAST_LINE=""

while :; do
    ELAPSED=$((SECONDS - START))

    if [ -z "$RUN_ID" ]; then
        ENTRY="$(find_run)"
        if [ -n "$ENTRY" ]; then
            RUN_ID="$(field "$ENTRY" databaseId)"
            TITLE="$(field "$ENTRY" displayTitle)"
            if [ -n "$RUN_ID" ]; then
                echo "[$ELAPSED s] 找到 run $RUN_ID: $TITLE"
            fi
        else
            echo "[$ELAPSED s] 还没找到对应的 run（push 产生 run 有延迟），继续等…"
        fi
    fi

    if [ -n "$RUN_ID" ]; then
        INFO="$(gh run view "$RUN_ID" --repo "$REPO" \
            --json status,conclusion,displayTitle 2>/dev/null | tr -d '\n')"
        STATUS="$(field "$INFO" status)"
        CONCLUSION="$(field "$INFO" conclusion)"
        LINE="[$ELAPSED s] status=$STATUS${CONCLUSION:+ conclusion=$CONCLUSION}"
        # 状态没变时不重复刷屏，但每 6 次（约 90s）报一次，确保看得出在动
        if [ "$LINE" != "$LAST_LINE" ] || [ $((ELAPSED % (INTERVAL * 6))) -lt "$INTERVAL" ]; then
            echo "$LINE"
            LAST_LINE="$LINE"
        fi

        if [ "$STATUS" = "completed" ]; then
            echo
            if [ "$CONCLUSION" = "success" ]; then
                echo "✅ run $RUN_ID 成功（用时 ${ELAPSED}s）"

                if [ -n "$DOWNLOAD" ]; then
                    echo
                    echo "下载产物 → $DOWNLOAD"
                    rm -rf "$DOWNLOAD"
                    if gh run download "$RUN_ID" --repo "$REPO" -D "$DOWNLOAD"; then
                        echo
                        find "$DOWNLOAD" -type f -exec ls -l {} \;
                        [ -f "$DOWNLOAD/SHA256SUMS.txt" ] && { echo; cat "$DOWNLOAD/SHA256SUMS.txt"; }
                    else
                        echo "❌ 产物下载失败" >&2
                        exit 1
                    fi
                fi
                exit 0
            fi

            echo "❌ run $RUN_ID 失败: conclusion=$CONCLUSION"
            echo
            echo "===== 失败步骤 ====="
            gh run view "$RUN_ID" --repo "$REPO" 2>/dev/null | sed -n '/X\|✗\|failed/Ip' | head -10
            echo
            echo "===== 关键 error 行 ====="
            gh run view "$RUN_ID" --repo "$REPO" --log 2>/dev/null \
                | sed 's/\x1b\[[0-9;]*m//g' \
                | grep -E "^error(\[|:)|##\[error\]|error: could not compile" \
                | head -20
            echo
            echo "完整日志: gh run view $RUN_ID --repo $REPO --log"
            exit 1
        fi
    fi

    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo
        echo "⏱ 超过 ${TIMEOUT}s 仍未结束（run=${RUN_ID:-未找到}）" >&2
        exit 1
    fi

    sleep "$INTERVAL"
done
