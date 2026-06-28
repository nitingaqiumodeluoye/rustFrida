/*
 * hook_engine.c - ARM64 Inline Hook Engine — Core
 *
 * Global state, logging, initialization, find_hook, cleanup.
 * Implementation details are split across:
 *   hook_engine_mem.c    — memory pool, alloc, wxshadow, relocate
 *   hook_engine_inline.c — inline hook install/attach/replace/remove
 *   hook_engine_redir.c  — redirect and native thunks
 *   hook_engine_art.c    — ART method router
 */

#include "hook_engine_internal.h"

#ifdef ANDROID
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#endif

/* Global engine state */
HookEngine g_engine = {0};

/* hook_engine_cleanup 快照的扩展 pool 范围。Rust 侧 safepoint + munmap 共用。 */
ExecPoolRange g_retained_pool_ranges[MAX_EXEC_POOLS];
int g_retained_pool_range_count = 0;

/* Thunk 入口 / 出口由汇编 LDADDAL 直接 inc/dec。
 * 覆盖整个 thunk 路径 (art_router prologue→restore_all BR;
 * inline attach save_ctx→restore→RET; inline replace save_ctx→epilogue RET)。
 * cleanup drain 轮询此计数归 0 后再 munmap，避免栈上残留 thunk LR。 */
volatile uint64_t g_thunk_in_flight = 0;

/* LDADDAL X17, XZR, [X16] — ARMv8.1 LSE atomic add-and-ignore.
 * Encoding: 0xF8F1021F (base 0xF8E00000 | Rs=17<<16 | Rn=16<<5 | Rt=31). */
#define LDADDAL_X17_XZR_X16 0xF8F1021Fu

/* 进入 thunk: atomic_inc(&g_thunk_in_flight)。使用 x16/x17 作 scratch，
 * x16/x17 是 PCS IP0/IP1 caller-scratch，所有 thunk 入口均可自由使用。
 * 每个 thunk 必须在有效 entry 之后、任何可能 BR 离开 thunk 的指令之前调用。 */
void emit_thunk_inflight_inc(Arm64Writer* w) {
    arm64_writer_put_ldr_reg_u64(w, ARM64_REG_X16, (uint64_t)&g_thunk_in_flight);
    arm64_writer_put_mov_reg_imm(w, ARM64_REG_X17, 1);
    uint32_t insn = LDADDAL_X17_XZR_X16;
    arm64_writer_put_bytes(w, (const uint8_t*)&insn, 4);
}

/* 离开 thunk: atomic_dec(&g_thunk_in_flight)。x17 = ~0 = -1 → LDADDAL += -1。
 * 必须在 RET / BR 之前的最后窗口（回调、原始函数调用都已返回后）插入。 */
void emit_thunk_inflight_dec(Arm64Writer* w) {
    emit_thunk_inflight_dec_regs(w, ARM64_REG_X16, ARM64_REG_X17);
}

void emit_thunk_inflight_dec_regs(Arm64Writer* w, Arm64Reg addr_reg, Arm64Reg val_reg) {
    arm64_writer_put_ldr_reg_u64(w, addr_reg, (uint64_t)&g_thunk_in_flight);
    arm64_writer_put_movn_reg_imm(w, val_reg, 0, 0);
    uint32_t insn = 0xF8E0001Fu
        | ((uint32_t)ARM64_REG_NUM(val_reg) << 16)
        | ((uint32_t)ARM64_REG_NUM(addr_reg) << 5);
    arm64_writer_put_bytes(w, (const uint8_t*)&insn, 4);
}

uint64_t hook_thunk_in_flight_count(void) {
    return __atomic_load_n(&g_thunk_in_flight, __ATOMIC_ACQUIRE);
}

/* 同步 munmap 所有 pool. 仅在 drain_thunk_in_flight == 0 时调用 (无 in-flight)。
 * drain 成功 → orchestrator 调此函数释放。drain 失败 → 不调, pool 泄漏到进程退出。 */
void hook_engine_munmap_pools_direct(void) {
    int freed = 0;
    uint64_t bytes = 0;
    for (int i = 0; i < MAX_EXEC_POOLS; i++) {
        if (g_engine.pools[i].base && g_engine.pools[i].size) {
            if (munmap(g_engine.pools[i].base, g_engine.pools[i].size) == 0) {
                freed++;
                bytes += g_engine.pools[i].size;
            }
            g_engine.pools[i].base = NULL;
            g_engine.pools[i].size = 0;
            g_engine.pools[i].used = 0;
        }
    }
    g_engine.pool_count = 0;
    for (int i = 0; i < g_retained_pool_range_count && i < MAX_EXEC_POOLS; i++) {
        if (g_retained_pool_ranges[i].base && g_retained_pool_ranges[i].size) {
            if (munmap((void*)(uintptr_t)g_retained_pool_ranges[i].base,
                       (size_t)g_retained_pool_ranges[i].size) == 0) {
                freed++;
                bytes += g_retained_pool_ranges[i].size;
            }
            g_retained_pool_ranges[i].base = 0;
            g_retained_pool_ranges[i].size = 0;
        }
    }
    g_retained_pool_range_count = 0;
    if (freed > 0) {
        hook_log("munmap_pools_direct: %d pool(s), %llu bytes",
                 freed, (unsigned long long)bytes);
    }
}

int hook_engine_get_pool_ranges(ExecPoolRange* out, int cap) {
    if (!out || cap <= 0) return 0;
    int n = g_retained_pool_range_count;
    if (n > cap) n = cap;
    for (int i = 0; i < n; i++) out[i] = g_retained_pool_ranges[i];
    return n;
}

int hook_engine_get_exec_ranges(ExecPoolRange* out, int cap) {
    if (!out || cap <= 0) return 0;
    int n = 0;
    if (g_engine.exec_mem && g_engine.exec_mem_size && n < cap) {
        out[n].base = (uint64_t)(uintptr_t)g_engine.exec_mem;
        out[n].size = (uint64_t)g_engine.exec_mem_size;
        n++;
    }

    int pool_count = g_engine.pool_count;
    if (pool_count > MAX_EXEC_POOLS) pool_count = MAX_EXEC_POOLS;
    for (int i = 0; i < pool_count && n < cap; i++) {
        if (g_engine.pools[i].base && g_engine.pools[i].size) {
            out[n].base = (uint64_t)(uintptr_t)g_engine.pools[i].base;
            out[n].size = (uint64_t)g_engine.pools[i].size;
            n++;
        }
    }

    int retained_count = g_retained_pool_range_count;
    if (retained_count > MAX_EXEC_POOLS) retained_count = MAX_EXEC_POOLS;
    for (int i = 0; i < retained_count && n < cap; i++) {
        if (g_retained_pool_ranges[i].base && g_retained_pool_ranges[i].size) {
            out[n] = g_retained_pool_ranges[i];
            n++;
        }
    }
    return n;
}

void hook_engine_clear_pool_ranges(void) {
    g_retained_pool_range_count = 0;
}

int hook_is_in_exec_pool(uint64_t pc) {
    if (pc == 0) return 0;

    uint64_t base = (uint64_t)(uintptr_t)g_engine.exec_mem;
    uint64_t size = (uint64_t)g_engine.exec_mem_size;
    if (base != 0 && size != 0 && pc >= base && pc < base + size) {
        return 1;
    }

    int pool_count = g_engine.pool_count;
    if (pool_count > MAX_EXEC_POOLS) pool_count = MAX_EXEC_POOLS;
    for (int i = 0; i < pool_count; i++) {
        base = (uint64_t)(uintptr_t)g_engine.pools[i].base;
        size = (uint64_t)g_engine.pools[i].size;
        if (base != 0 && size != 0 && pc >= base && pc < base + size) {
            return 1;
        }
    }

    int retained_count = g_retained_pool_range_count;
    if (retained_count > MAX_EXEC_POOLS) retained_count = MAX_EXEC_POOLS;
    for (int i = 0; i < retained_count; i++) {
        base = g_retained_pool_ranges[i].base;
        size = g_retained_pool_ranges[i].size;
        if (base != 0 && size != 0 && pc >= base && pc < base + size) {
            return 1;
        }
    }

    return 0;
}

/* --- Diagnostic log infrastructure --- */

HookLogFn g_log_fn = NULL;

void hook_engine_set_log_fn(HookLogFn fn) {
    g_log_fn = fn;
}

static int should_force_stderr_hook_log(void) {
    return 1;
}

static int should_force_trace_file_hook_log(void) {
    return 1;
}

static int should_force_android_hook_log(void) {
    return 1;
}

static void hook_trace_file_write(const char* msg, size_t msg_len) {
    if (!should_force_trace_file_hook_log()) {
        return;
    }

    const char* path = "/data/local/tmp/rf_hook_trace.txt";
    int fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    }
    if (fd < 0) {
        return;
    }

    char prefix[64];
    int prefix_len = snprintf(prefix, sizeof(prefix), "[RF_HOOK pid=%d] ", getpid());
    if (prefix_len > 0) {
        size_t n = (size_t)prefix_len;
        if (n > sizeof(prefix)) n = sizeof(prefix);
        write(fd, prefix, n);
    }
    write(fd, msg, msg_len);
    write(fd, "\n", 1);
    fsync(fd);
    close(fd);
}

static void hook_android_log_write(const char* msg) {
    if (!should_force_android_hook_log()) {
        return;
    }

#ifdef ANDROID
    struct rf_log_time {
        uint32_t tv_sec;
        uint32_t tv_nsec;
    } __attribute__((packed));

    struct rf_log_header {
        uint8_t id;
        uint16_t tid;
        struct rf_log_time realtime;
    } __attribute__((packed));

    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/dev/socket/logdw", sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return;
    }

    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    clock_gettime(CLOCK_REALTIME, &ts);

    long tid = syscall(SYS_gettid);
    if (tid <= 0) {
        tid = (long)getpid();
    }

    struct rf_log_header header;
    header.id = 0; /* LOG_ID_MAIN */
    header.tid = (uint16_t)tid;
    header.realtime.tv_sec = (uint32_t)ts.tv_sec;
    header.realtime.tv_nsec = (uint32_t)ts.tv_nsec;

    char tag_payload[] = {4, 'R', 'F', '_', 'H', 'O', 'O', 'K', '\0'};
    char nul = '\0';
    struct iovec iov[4];
    iov[0].iov_base = &header;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = tag_payload;
    iov[1].iov_len = sizeof(tag_payload);
    iov[2].iov_base = (void*)msg;
    iov[2].iov_len = strnlen(msg, 256);
    iov[3].iov_base = &nul;
    iov[3].iov_len = 1;
    writev(fd, iov, 4);
    close(fd);
#else
    (void)msg;
#endif
}

void hook_log(const char* fmt, ...) {
    int saved_errno = errno;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    size_t len = strnlen(buf, sizeof(buf));

    hook_trace_file_write(buf, len);
    hook_android_log_write(buf);

    if (should_force_stderr_hook_log()) {
        static const char prefix[] = "[RF_HOOK] ";
        write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
        write(STDERR_FILENO, buf, len);
        write(STDERR_FILENO, "\n", 1);
    }

    if (g_log_fn) {
        g_log_fn(buf);
    }
    errno = saved_errno;
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    hook_log("hook_engine_init: enter exec_mem=%p size=%zu initialized=%d",
             exec_mem, size, g_engine.initialized);
    if (g_engine.initialized) {
        hook_log("hook_engine_init: already initialized exec_mem=%p size=%zu used=%zu",
                 g_engine.exec_mem, g_engine.exec_mem_size, g_engine.exec_mem_used);
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        hook_log("hook_engine_init: invalid args exec_mem=%p size=%zu", exec_mem, size);
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.pool_count = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    hook_lock_init(&g_engine.lock);
    g_engine.initialized = 1;
    hook_log("hook_engine_init: success exec_mem=%p size=%zu page=%zu",
             g_engine.exec_mem, g_engine.exec_mem_size, g_engine.exec_mem_page_size);

    return 0;
}

/* Find hook entry by target address */
HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

/* Cleanup all hooks */
void hook_engine_cleanup(void) {
    if (!g_engine.initialized) return;

    hook_lock(&g_engine.lock);

    /* Count hooks on both lists for diagnostics */
    int hooks_count = 0, free_count = 0, stealth_hooks = 0, stealth_free = 0;
    for (HookEntry* e = g_engine.hooks; e; e = e->next) {
        hooks_count++;
        if (e->stealth) stealth_hooks++;
    }
    for (HookEntry* e = g_engine.free_list; e; e = e->next) {
        free_count++;
        if (e->stealth) stealth_free++;
    }
    hook_log("hook_engine_cleanup: hooks=%d (stealth=%d), free_list=%d (stealth=%d)",
             hooks_count, stealth_hooks, free_count, stealth_free);

    /* Restore each live hook individually.
     * stealth==1 (wxshadow): must use prctl release.
     * stealth==2 (recomp): release-only cleanup; PR_RECOMPILE_RELEASE has
     * already stopped execution from reaching the anonymous mirror, so do not
     * write target slots/mirrors here.
     * stealth==0 (normal): restore via mprotect+memcpy. */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->stealth == 1) {
            int rc = wxshadow_release(entry->target);
            if (rc != 0) {
                hook_log("hook_engine_cleanup: wxshadow_release failed for %p", entry->target);
            }
        } else if (entry->stealth == 2) {
            /* Recomp entries are discarded below with the pool. */
        } else {
            int saved_prot[8] = {0};
            size_t saved_count = save_range_prot_pages(entry->target, entry->original_size,
                                                       saved_prot,
                                                       sizeof(saved_prot) / sizeof(saved_prot[0]));
            if (saved_count != 0 &&
                    saved_count <= sizeof(saved_prot) / sizeof(saved_prot[0]) &&
                    mprotect_range_pages(entry->target, entry->original_size,
                                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                memcpy(entry->target, entry->original_bytes, entry->original_size);
                restore_range_prot_pages(entry->target, entry->original_size, saved_prot, saved_count);
                hook_flush_cache(entry->target, entry->original_size);
            } else {
                hook_log("hook_engine_cleanup: mprotect restore failed for %p errno=%d",
                         entry->target, errno);
            }
        }
        entry = entry->next;
    }

    /* HookEntry lifetime note:
     * All HookEntry structs (including trampoline and thunk memory) live in one of
     * two executable pool regions:
     *   1. 初始 pool (exec_mem)  — 由 Rust 侧 ExecMemory 拥有，进程生命周期保留
     *   2. 扩展 pool (pools[])   — 由 create_pool_near_range_sized 经 mmap 创建
     *
     * 扩展 pool 在此 **不 munmap**：snapshot 到 g_retained_pool_ranges，供 Rust 侧
     * 通过 hook_engine_get_pool_ranges 查询。Rust 完成全线程 PC/LR safepoint 验证后
     * 自行 munmap；验证失败则 leak 到进程退出（对标 Frida alloc.js 风格兜底）。 */

    g_retained_pool_range_count = 0;
    for (int i = 0; i < g_engine.pool_count; i++) {
        if (g_engine.pools[i].base && g_engine.pools[i].size
                && g_retained_pool_range_count < MAX_EXEC_POOLS) {
            g_retained_pool_ranges[g_retained_pool_range_count].base =
                (uint64_t)g_engine.pools[i].base;
            g_retained_pool_ranges[g_retained_pool_range_count].size =
                (uint64_t)g_engine.pools[i].size;
            g_retained_pool_range_count++;
        }
        g_engine.pools[i].base = NULL;
        g_engine.pools[i].size = 0;
        g_engine.pools[i].used = 0;
    }
    if (g_retained_pool_range_count > 0) {
        hook_log("hook_engine_cleanup: snapshot %d extension pool range(s) for caller-side munmap",
                 g_retained_pool_range_count);
    }
    g_engine.pool_count = 0;

    /* Reset state — the list pointers are now dangling (pool memory unmapped) */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.initialized = 0;

    hook_unlock(&g_engine.lock);
    hook_lock_destroy(&g_engine.lock);
}
