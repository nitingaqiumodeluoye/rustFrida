/*
 * hwbp_test — rustFrida 硬件观察点(hwbp)的受控靶子。
 *
 * 为什么需要它:「谁写了这块内存」这个功能没法靠被监控者自己证明。必须有一个
 * 行为完全可预期的进程,在**已知地址**上按**已知节奏**读写,才能把观察点的输出
 * 与真实行为逐条对上账 —— 即:app 日志说 tid=X 写了 val=0xN,观察者就该报出
 * 同一个 tid。
 *
 * 用法(设备上):
 *
 *     hwbp_test --delay 15
 *
 * 它先打印被观察地址和 pid,留出 --delay 秒让人装观察者:
 *
 *     rustfrida --pid <pid> --hwbp-watch 0x<addr>
 *
 * 然后才开始读写。
 *
 * 设计要点(每一条都对应一类容易漏掉的验证):
 *
 *   1. 地址必须显式打印。观察点是「先装、后写」的,程序不能自己闷头写 ——
 *      得先让人知道往哪儿装。默认留 15 秒。
 *
 *   2. 线程分两批,覆盖两条不同的装点路径:
 *        - 早期线程在 --delay **之前**就建好,属于「观察者启动时已存在」的一批,
 *          走启动时遍历 /proc/<pid>/task 的路径;
 *        - --late 指定延时**之后**才新建的线程,走「观察点已装上、后来才出现的
 *          线程要补装」的路径(这段是 rustFrida 自己写的,最该测)。
 *      两条都测到,才算把线程管理验完。
 *
 *   3. 每个线程都打印自己的 tid。观察点寄存器是 per-thread 资源,「谁写的」
 *      这个问题的答案就是 tid,所以必须能逐条对上。
 *
 *   4. 所有线程写**同一个地址**,而不是各写各的。这样多个线程争抢同一处内存,
 *      hwbp 报出的 tid 序列才和 app 日志能一一比对;若各自写不同地址,就只需
 *      一个观察点,反而测不出「按线程下发」是否正确。
 *
 *   5. 读写分开开关(--mode)。写观察点命中率低、读观察点命中率高,两者行为差异
 *      很大,需要能单独测。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* 模式 */
#define MODE_WRITE 0
#define MODE_READ 1
#define MODE_BOTH 2

/* 被观察的那 4 字节。volatile 保证每次访问都真的落到内存上,不被优化掉。 */
static volatile uint32_t *g_target;

static volatile int g_start; /* 延时到点后置 1,早期线程才开始干活 */
static volatile int g_stop;  /* SIGINT 置 1 */

static long g_interval_us = 100000; /* 每次操作间隔,缺省 100ms */
static int g_mode = MODE_WRITE;
static long g_rounds; /* 每线程操作次数上限,0 = 不限 */

static volatile unsigned long g_writes;
static volatile unsigned long g_reads;

/* 多线程打印会交错,短行也会被拆开;加锁让日志逐行可读。 */
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_line(const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if (n > (int)sizeof(buf) - 2)
        n = (int)sizeof(buf) - 2;
    buf[n++] = '\n';
    buf[n] = '\0';

    pthread_mutex_lock(&g_log_lock);
    fwrite(buf, 1, (size_t)n, stdout);
    fflush(stdout);
    pthread_mutex_unlock(&g_log_lock);
}

static void sleep_us(long us)
{
    struct timespec ts;
    if (us <= 0)
        return;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (us % 1000000) * 1000L;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        if (g_stop)
            return;
    }
}

static const char *mode_name(int m)
{
    switch (m) {
    case MODE_READ:
        return "read";
    case MODE_BOTH:
        return "both";
    default:
        return "write";
    }
}

static void *worker(void *arg)
{
    long id = (long)arg;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    unsigned long seq = 0;
    unsigned long mine_w = 0, mine_r = 0;

    /*
     * 早期线程在这里等 --delay 走完。用轮询而不是条件变量,是为了让这个程序
     * 只依赖 pthread 最基础的部分 —— 它要能在任何 Android 上跑起来,
     * 毕竟它的作用是给人验证另一个东西。
     */
    while (!g_start && !g_stop)
        sleep_us(2000);

    log_line("[start] tid=%d (worker %ld)", tid, id);

    while (!g_stop) {
        uint32_t v;

        if (g_mode != MODE_READ) {
            /*
             * 值里带上线程号与序号,便于事后核对「这一条是不是这个线程写的」。
             * 取低 12 位序号避免值长得太乱。
             */
            v = (uint32_t)((id << 20) | (uint32_t)(seq & 0xfff) | 1u);
            *g_target = v;
            __sync_fetch_and_add(&g_writes, 1);
            mine_w++;
            log_line("[w] tid=%d seq=%lu val=0x%x", tid, seq, v);
        }

        if (g_mode != MODE_WRITE) {
            v = *g_target;
            __sync_fetch_and_add(&g_reads, 1);
            mine_r++;
            log_line("[r] tid=%d seq=%lu val=0x%x", tid, seq, v);
        }

        seq++;
        if (g_rounds > 0 && seq >= (unsigned long)g_rounds)
            break;

        sleep_us(g_interval_us);
    }

    log_line("[done] tid=%d 写 %lu 次 / 读 %lu 次", tid, mine_w, mine_r);
    return NULL;
}

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *argv0)
{
    printf(
        "用法: %s [选项]\n"
        "\n"
        "  --delay <秒>       打印地址后等多久才开始读写(默认 15),留给观察者装点\n"
        "  --interval <毫秒>  每次读写之间的间隔(默认 100)\n"
        "  --threads <n>      启动时就创建的线程数(默认 3)\n"
        "  --late <n>         延时到点后**新创建**的线程数(默认 0),用来测补装路径\n"
        "  --mode <m>         write | read | both(默认 write)\n"
        "  --rounds <n>       每线程操作多少次后收工(默认 0 = 一直跑)\n"
        "  -h, --help         显示本帮助\n",
        argv0);
}

int main(int argc, char **argv)
{
    long delay = 15, nthreads = 3, nlate = 0;
    pthread_t *tids;
    void *page;
    int i;
    long created = 0;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(a, "--delay") && v) {
            delay = atol(v);
            i++;
        } else if (!strcmp(a, "--interval") && v) {
            g_interval_us = atol(v) * 1000;
            i++;
        } else if (!strcmp(a, "--threads") && v) {
            nthreads = atol(v);
            i++;
        } else if (!strcmp(a, "--late") && v) {
            nlate = atol(v);
            i++;
        } else if (!strcmp(a, "--rounds") && v) {
            g_rounds = atol(v);
            i++;
        } else if (!strcmp(a, "--mode") && v) {
            if (!strcmp(v, "write"))
                g_mode = MODE_WRITE;
            else if (!strcmp(v, "read"))
                g_mode = MODE_READ;
            else if (!strcmp(v, "both"))
                g_mode = MODE_BOTH;
            else {
                fprintf(stderr, "未知模式: %s\n", v);
                return 2;
            }
            i++;
        } else {
            fprintf(stderr, "无法识别的参数: %s\n", a);
            usage(argv[0]);
            return 2;
        }
    }

    if (nthreads < 0)
        nthreads = 0;
    if (nlate < 0)
        nlate = 0;
    if (delay < 0)
        delay = 0;

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    /*
     * MAP_SHARED 匿名页 + 立刻写一遍。两个作用:
     *   - 让页驻留,后续 rtFrida 侧读值不会触发缺页;
     *   - 给读线程一个确定的非零初值(否则读到的全是 0,和「没读到」分不清)。
     * 用 SHARED 是为了和 rustFrida 侧 hwbp.rs 承载命中环的方式一致 ——
     * 如果将来要在同一进程内 fork 观察者,SHARED 页才是父子都看得见的那块。
     */
    page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        fprintf(stderr, "mmap 失败: %s\n", strerror(errno));
        return 1;
    }
    g_target = (volatile uint32_t *)page;
    *g_target = 0xdeadbeefu;

    /* 地址必须按观察宽度对齐 —— 内核 arch_build_bp_info 会强制检查。 */
    if (((uintptr_t)g_target & 3u) != 0) {
        fprintf(stderr, "内部错误: 地址 %p 未按 4 字节对齐\n", (void *)g_target);
        return 1;
    }

    log_line("======================================================");
    log_line("[hwbp-test] pid=%d", (int)getpid());
    log_line("[hwbp-test] 被观察地址 = %p  宽度 4 字节  初值 0xdeadbeef",
             (void *)g_target);
    log_line("[hwbp-test] 模式=%s 线程=%ld 间隔=%ldms 等待=%lds 每线程次数=%ld",
             mode_name(g_mode), nthreads, g_interval_us / 1000, delay, g_rounds);
    log_line("------------------------------------------------------");
    log_line("[hwbp-test] 请在 %ld 秒内启动观察者:", delay);
    log_line("[hwbp-test]   rustfrida --pid %d --hwbp-watch %p",
             (int)getpid(), (void *)g_target);
    log_line("======================================================");

    /*
     * 先把线程建出来再等。这样它们属于「观察者启动时就已经存在」的一批,
     * 走的是启动时遍历 /proc/<pid>/task 下发观察点的路径。
     */
    tids = (pthread_t *)calloc((size_t)(nthreads + nlate) + 1, sizeof(*tids));
    if (!tids) {
        fprintf(stderr, "calloc 失败\n");
        return 1;
    }

    for (i = 0; i < (int)nthreads; i++) {
        if (pthread_create(&tids[created], NULL, worker, (void *)(long)(i + 1)) != 0) {
            fprintf(stderr, "pthread_create 失败: %s\n", strerror(errno));
            break;
        }
        created++;
    }
    log_line("[hwbp-test] 已创建 %ld 个线程(观察者现在就该能装上了)", created);

    /* 等观察者就位 */
    {
        struct timespec ts;
        ts.tv_sec = delay;
        ts.tv_nsec = 0;
        while (!g_stop && nanosleep(&ts, &ts) == -1 && errno == EINTR) {
            /* 被信号打断就继续把剩余时间睡完 */
        }
    }

    if (g_stop) {
        log_line("[hwbp-test] 等待期间收到信号,退出");
        return 0;
    }

    log_line("[hwbp-test] 开始 —— 以下每条 [w]/[r] 都应与观察者的输出一一对应");

    /*
     * 现在才创建的线程走的是「补装」路径:观察点已经装好了,这些 tid 是新的。
     * 这一段是 rustFrida 自己写的 arm_new_threads,最该测。
     */
    for (i = 0; i < (int)nlate; i++) {
        if (pthread_create(&tids[created], NULL, worker,
                           (void *)(long)(100 + i + 1)) != 0) {
            fprintf(stderr, "pthread_create(late) 失败: %s\n", strerror(errno));
            break;
        }
        created++;
    }
    if (nlate > 0)
        log_line("[hwbp-test] 又新创建了 %ld 个线程(测「补装新线程」)", nlate);

    g_start = 1; /* 放行全部线程 */

    /* 等线程结束,或者等 SIGINT */
    while (!g_stop) {
        unsigned long w = g_writes, r = g_reads;
        if (g_rounds > 0 && w + r >= (unsigned long)g_rounds * (unsigned long)created)
            break;
        sleep_us(200000);
    }

    g_stop = 1;
    for (i = 0; i < (int)created; i++)
        pthread_join(tids[i], NULL);

    log_line("======================================================");
    log_line("[hwbp-test] 结束:合计写 %lu 次 / 读 %lu 次", g_writes, g_reads);
    log_line("[hwbp-test] 若观察者报出的 tid 与上面的 [w]/[r] 行一致,说明命中归属正确");
    log_line("======================================================");

    free(tids);
    return 0;
}