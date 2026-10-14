//! hwbp 子命令:监控内存写入,打印写入者。
//!
//! 用法(见 `args.rs` 的 `--hwbp-watch`):
//! ```text
//! rustfrida --pid 1234 --hwbp-watch 0x7f1234000 --hwbp-watch 0x7f1234100:8
//! ```
//!
//! ## 为什么是轮询
//!
//! 内核不推送命中 —— 它只把命中记进每个节点的环形缓冲。所以「一旦触发就打印」
//! 这件事在宿主侧实现为:定期调 `hwbp::hits()` 把环拉回来,和上次的记录做差分,
//! 只打印新增的那些。
//!
//! 这带来两个必须接受的特性:
//!   - **不是实时**:延迟 ≈ 轮询间隔(默认 50ms);
//!   - **可能丢条目**:每节点环只有 32 条,轮询慢于命中率时旧条目会被覆盖。
//!     但「谁写了它」这个问题只需要*任何一条*存活记录就能回答,所以实际影响有限。
//!     真正的兜底是内核侧的 `max_hits` 自动关断 —— 热地址不会无限 trap。
//!
//! ## 观察点是按线程的
//!
//! ARM64 每个线程独立持有 4 个观察点寄存器(全进程共享不了)。所以这里:
//!   1. 启动时遍历 `/proc/<pid>/task` 给每个线程都下发一遍;
//!   2. 轮询时顺带发现新线程并补下发 —— 否则目标进程新建的工作线程会完全
//!      处在观察范围之外,而「谁写了它」恰恰常发生在工作线程里。
//!
//! 每线程 4 个是硬上限,`--hwbp-watch` 超过 4 个时后续的会注册失败并打警告。

#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use crate::hwbp::{self, BpLen, HwbpHit};
use crate::symbolize::Symbolizer;
use crate::{log_info, log_warn};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};

/// Ctrl+C 标记。装一个只设标记的 handler,hwbp 循环每轮检查。
static HWBP_INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn hwbp_signal_handler(_sig: libc::c_int) {
    // 只存标记:async-signal-safe。
    HWBP_INTERRUPTED.store(true, Ordering::Relaxed);
}

/// 一个被监控的地址及其解析后的参数。
#[derive(Debug, Clone, Copy)]
struct WatchSpec {
    addr: u64,
    len: BpLen,
}

/// 解析 `ADDR[:LEN]`。
///
/// 宽度缺省 4(最常见的 int / 指针以下标量);显式写 `:8` 才是 8 字节。
/// 不猜数据大小是刻意的 —— 猜错会让观察窗口盖到邻居,报告出无关的写入者。
fn parse_watch_spec(s: &str) -> Result<WatchSpec, String> {
    let (addr_part, len_part) = match s.split_once(':') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };

    let addr_str = addr_part.trim();
    let hex = addr_str
        .strip_prefix("0x")
        .or_else(|| addr_str.strip_prefix("0X"))
        .unwrap_or(addr_str);
    let addr = u64::from_str_radix(hex, 16)
        .map_err(|e| format!("观察地址 '{addr_str}' 不是合法十六进制: {e}"))?;
    if addr == 0 {
        return Err("观察地址不能为 0".to_string());
    }

    let len = match len_part {
        None => BpLen::Len4,
        Some(l) => match l.trim() {
            "1" => BpLen::Len1,
            "2" => BpLen::Len2,
            "4" => BpLen::Len4,
            "8" => BpLen::Len8,
            other => {
                return Err(format!(
                    "观察宽度 '{other}' 非法(只能是 1/2/4/8;arm64 硬件观察点只有这四档)"
                ))
            }
        },
    };

    if addr & (len.bytes() as u64 - 1) != 0 {
        return Err(format!(
            "地址 0x{addr:x} 未按宽度 {} 对齐 —— arm64 的 arch_build_bp_info() 强制要求,\
             不对齐内核直接拒绝",
            len.bytes()
        ));
    }

    Ok(WatchSpec { addr, len })
}

/// 目标进程当前的线程 id 列表。
fn list_tids(pid: u32) -> Result<Vec<u32>, String> {
    let dir = format!("/proc/{pid}/task");
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("读取 {dir} 失败: {e}"))?;
    let mut tids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    tids.sort_unstable();
    Ok(tids)
}

/// 给单个线程下发一个观察点。
///
/// 返回值只用于统计成功率:同一线程上的第 5 个观察点必然失败(硬件只有 4 个
/// 寄存器),这是预期内的,不该当成错误刷屏。
fn arm_on_thread(spec: &WatchSpec, tid: u32, max_hits: u32) -> Result<(), String> {
    hwbp::watch(spec.addr, tid, spec.len, max_hits)
}

/// 已见过并已下发观察点的 (addr, tid) 集合。
///
/// 用它避免对同一线程重复下发 —— 重复下发虽然后端会做「同址同线程替换」,
/// 但那会重建 perf_event,白白抖动观察点状态。
type ArmedSet = HashSet<(u64, u32)>;

/// 轮询期间发现新线程时补下发。
///
/// 返回新下发的数量。每轮都可能有线程退出/新建,所以调用方要周期性调它。
fn arm_new_threads(pid: u32, specs: &[WatchSpec], max_hits: u32, armed: &mut ArmedSet) -> usize {
    let tids = match list_tids(pid) {
        Ok(t) => t,
        Err(_) => return 0, // 目标可能已退出;主循环会让它自然结束
    };

    let mut newly = 0usize;
    for tid in tids {
        for spec in specs {
            if armed.contains(&(spec.addr, tid)) {
                continue;
            }
            if arm_on_thread(spec, tid, max_hits).is_ok() {
                armed.insert((spec.addr, tid));
                newly += 1;
            }
        }
    }
    newly
}

/// 每个观察点上一轮已打印到第几条命中。
///
/// 内核的 `ring_total` 是**累计**命中数(只增不减,环回绕也照增),所以
/// 「本轮新增 = 当前 total - 上次已处理到的地方」。
#[derive(Debug, Default, Clone)]
struct Cursor {
    /// 上次已经消费到的累计命中数。
    consumed_total: u32,
    /// 该地址是否已报告过「节点不存在」——避免刷屏。
    warned_missing: bool,
}

fn print_hit(sym: &Symbolizer, spec: &WatchSpec, hit: &HwbpHit) {
    // 用 stderr 之外的标准输出:这是工具的主结果,不是日志。
    println!(
        "[write] 0x{:x} len={} pc={} lr={}",
        spec.addr,
        spec.len.bytes(),
        sym.resolve(hit.pc),
        sym.resolve(hit.lr),
    );
    println!(
        "        sp=0x{:x} x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x}",
        hit.sp, hit.x[0], hit.x[1], hit.x[2], hit.x[3]
    );
    // x0 常常就是被写的目标(store 的基址寄存器),单独提一句能省一次心算。
    if hit.x[0] == spec.addr {
        println!("        (x0 即被观察地址)");
    }
}

/// 探活失败时把错误拼成带**分诊**的提示。
///
/// `probe()` 失败有两种完全不同的原因,但表面错误几乎一样(都是 supercall 失败),
/// 光看它分不清:
///   - KernelPatch 这一层就不通(未安装 / 授权未过) —— 还没轮到模块;
///   - 通道正常但 hwbp 模块没加载 —— 只需把模块装上。
///
/// `kpver` 恰好能区分:它不需要 `is_authed`(在内核的 su 白名单里),且完全不碰模块,
/// 所以它能返回就证明前一条链路是通的。分不清时人容易在错的地方反复折腾,
/// 所以这里直接把结论写进错误里。
fn probe_failure_message(probe_err: &str) -> String {
    let hint = "hwbp.kpm 需先由 APatch 加载(与 karinahide 同一路径),\
                确认它的 ready 日志里带版本号";

    match crate::kpm::kpver_string() {
        Ok(v) => format!(
            "hwbp 内核模块不可用,无法监控。\n\
             探测结果: {probe_err}\n\
             分诊: 设备上 KernelPatch 正常(版本 {v}),说明 supercall 通道与授权都没问题,\
             问题就在 hwbp 模块本身 —— 多半是没加载,或构建用的头文件版本与上面的 {v} 不匹配。\n\
             提示: {hint}"
        ),
        Err(kp_err) => format!(
            "hwbp 内核模块不可用,无法监控。\n\
             探测结果: {probe_err}\n\
             分诊: 连 KernelPatch 版本都查不到 —— 这一层还没通,先别怀疑 hwbp.kpm。\n\
             kpver 报错: {kp_err}"
        ),
    }
}

/// 主循环。
///
/// `pid` 是目标进程的 tgid(观察点要按线程下发,用 tgid 枚举 /proc/<pid>/task)。
fn run(pid: u32, specs: Vec<WatchSpec>, max_hits: u32, interval_ms: u64) -> Result<(), String> {
    if specs.is_empty() {
        return Err("没有指定观察点".to_string());
    }

    // 先探活:模块没加载时后续每条命令都会失败,早报比刷一屏错误好。
    match hwbp::probe() {
        Ok(status) => log_info!("hwbp 模块就绪: {status}"),
        Err(e) => return Err(probe_failure_message(&e)),
    }

    // Ctrl+C 时停循环并卸掉观察点。
    let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = hwbp_signal_handler as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &action, &mut old_action);
    }

    let sym = Symbolizer::new(pid).map_err(|e| format!("解析目标进程 maps 失败: {e}"))?;

    let mut armed: ArmedSet = HashSet::new();
    let armed_now = arm_new_threads(pid, &specs, max_hits, &mut armed);
    let tid_count = list_tids(pid).map(|t| t.len()).unwrap_or(0);

    for spec in &specs {
        log_info!(
            "watch 0x{:x} len={} max_hits={} → 已下发 {}/{} 个线程",
            spec.addr,
            spec.len.bytes(),
            max_hits,
            armed_now,
            tid_count
        );
    }
    if armed.len() < specs.len() * tid_count {
        log_warn!(
            "部分线程未下发成功(已下发 {} 个)。每线程只有 4 个观察点寄存器,\
             观察点超过 4 个时后面的必然失败 —— 这是硬件上限,不是 bug",
            armed.len()
        );
    }
    log_info!("开始监控,命中会即时打印;Ctrl+C 停止并卸载观察点");

    let mut cursors: HashMap<u64, Cursor> = HashMap::new();
    let mut total_printed = 0u64;

    while !HWBP_INTERRUPTED.load(Ordering::Relaxed) {
        // 目标进程没了就收工
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            log_warn!("目标进程 {pid} 已退出");
            break;
        }

        // 补新线程:目标工作线程往往在建观察点之后才创建,漏了它们就白监控了。
        arm_new_threads(pid, &specs, max_hits, &mut armed);

        for spec in &specs {
            let cursor = cursors.entry(spec.addr).or_default();
            match hwbp::hits(spec.addr, 0, 0) {
                Ok(h) => {
                    cursor.warned_missing = false;
                    // ring_total 是累计值;差值即上次以来新增的条数。
                    let new = h.total.wrapping_sub(cursor.consumed_total);
                    cursor.consumed_total = h.total;
                    if new == 0 {
                        continue;
                    }

                    let entries = hwbp::effective_hits(&h);
                    // 环只有 32 条:新增超过环容量说明中间的被覆盖了,如实说明,
                    // 否则会把「只看到最后 32 条」误读成「只发生了 32 次」。
                    let shown = (new as usize).min(entries.len());
                    if new as usize > entries.len() {
                        println!(
                            "[!] 0x{:x} 新增 {new} 次命中,但环形缓冲只保留 {} 条 —— \
                             中间 {} 条已被覆盖(如需完整记录请减小 --hwbp-interval)",
                            spec.addr,
                            entries.len(),
                            new as usize - entries.len()
                        );
                    }

                    for hit in entries.iter().skip(entries.len() - shown) {
                        print_hit(&sym, spec, hit);
                        total_printed += 1;
                    }

                    if h.is_armed == 0 {
                        println!(
                            "[*] 0x{:x} 已达上限 {} 次命中,内核侧自动关闭(不再产生新记录)",
                            spec.addr, h.max_hits
                        );
                    }
                }
                Err(e) => {
                    // 节点不存在通常是「还没下发成功」或「观察点已到量卸载」。
                    // 只报一次,避免 50ms 一条刷屏。
                    if !cursor.warned_missing {
                        cursor.warned_missing = true;
                        log_warn!("0x{:x} 查询失败: {e}", spec.addr);
                    }
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(interval_ms.max(1)));
    }

    // 卸载:把内核里这个地址上的所有节点清掉,避免留下自动关断后仍在链表里的
    // 僵尸节点占着位置(下次 watch 同址会替换,但不同地址会累积)。
    for spec in &specs {
        if let Err(e) = hwbp::unwatch(spec.addr, 0) {
            log_warn!("卸载 0x{:x} 的观察点失败: {e}", spec.addr);
        }
    }

    unsafe {
        libc::sigaction(libc::SIGINT, &old_action, std::ptr::null_mut());
    }

    log_info!(
        "已停止。共打印 {} 条命中,已卸载 {} 个观察点",
        total_printed,
        specs.len()
    );
    Ok(())
}

/// CLI 入口:解析 `--hwbp-watch` 列表并跑。
pub(crate) fn run_from_args(
    pid: u32,
    watches: &[String],
    max_hits: u32,
    interval_ms: u64,
) -> Result<(), String> {
    let mut specs = Vec::with_capacity(watches.len());
    for w in watches {
        specs.push(parse_watch_spec(w)?);
    }
    run(pid, specs, max_hits, interval_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addr_with_default_len() {
        let s = parse_watch_spec("0x7f1234000").unwrap();
        assert_eq!(s.addr, 0x7f1234000);
        assert_eq!(s.len, BpLen::Len4);
    }

    #[test]
    fn parses_addr_with_explicit_len() {
        let s = parse_watch_spec("7f1234000:8").unwrap();
        assert_eq!(s.addr, 0x7f1234000);
        assert_eq!(s.len, BpLen::Len8);
    }

    #[test]
    fn rejects_misaligned_addr() {
        // 4 字节宽度要求地址 4 对齐
        let e = parse_watch_spec("0x7f1234002:4").unwrap_err();
        assert!(e.contains("对齐"), "{e}");
    }

    #[test]
    fn rejects_bad_len_and_bad_hex() {
        assert!(parse_watch_spec("0x1000:3").unwrap_err().contains("非法"));
        assert!(parse_watch_spec("zzz").is_err());
        assert!(parse_watch_spec("0x0").is_err());
    }
}