//! 地址符号解析:把命中里的裸 pc/lr 翻译成「模块+偏移」。
//!
//! 排查时裸地址基本没用 —— 拿到 `0x7a3c001890` 还得自己对照 maps 才知道是哪个
//! 模块的哪条指令。解析成 `libtarget.so+0x1890` 才直接可读。
//!
//! 数据源是目标进程的 `/proc/<pid>/maps`:可执行段(`r-xp`)的首地址即该模块的
//! 加载基址,`地址 - 基址` 就是模块内偏移。这里刻意不做 ELF 符号表解析 ——
//! 那需要读目标进程的磁盘文件、处理 stripped 的 .dynsym,而 Frida 系的工具
//! (以及 `addr2line`/IDA)都吃「模块+偏移」这种输入,偏移本身已经足够定位。

#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use crate::process::{parse_proc_maps, MapEntry};

/// 一个可执行映射段,用来把地址折算成模块偏移。
#[derive(Debug, Clone)]
pub(crate) struct ExecSegment {
    pub(crate) start: u64,
    pub(crate) end: u64,
    /// 模块加载基址 = 该段地址 - 段在文件中的偏移。
    /// 直接用段首地址当基址是错的:同一模块的 `.text` 段通常不在文件偏移 0 处。
    pub(crate) base: u64,
    /// 模块路径(去掉 `(deleted)` 之类后缀后的可读名字)
    pub(crate) module: String,
}

/// 目标进程的可执行段快照。
///
/// 一次解析、多次查询:轮询打印命中时每个 pc/lr 都要解析,每 50ms 重读一遍
/// `/proc/<pid>/maps` 是浪费。调用方在开始轮询前建一次即可。
pub(crate) struct Symbolizer {
    segs: Vec<ExecSegment>,
}

impl Symbolizer {
    /// 读取 `/proc/<pid>/maps`,挑出可执行段。
    pub(crate) fn new(pid: u32) -> Result<Self, String> {
        let entries = parse_proc_maps(pid)?;
        Ok(Self::from_entries(&entries))
    }

    fn from_entries(entries: &[MapEntry]) -> Self {
        let mut segs: Vec<ExecSegment> = entries
            .iter()
            .filter(|e| e.is_executable() && !e.path.is_empty())
            .map(|e| ExecSegment {
                start: e.start,
                end: e.end,
                // 基址 = 段起始 VA - 该段对应的文件偏移。
                // 例:.text 在文件偏移 0x1000 处、映射到 0x7a3c001000,
                // 则 base = 0x7a3c001000 - 0x1000 = 0x7a3c000000。
                base: e.start.saturating_sub(e.offset),
                module: shorten_module_name(&e.path),
            })
            .collect();

        // 同一模块会有多个可执行段(如 .text 与 .plt),按段首排序后二分即可。
        segs.sort_by_key(|s| s.start);
        Self { segs }
    }

    /// 把一个地址格式化成 `模块+0x偏移`;不在任何可执行段内时退回裸地址。
    pub(crate) fn resolve(&self, addr: u64) -> String {
        if addr == 0 {
            return "0x0".to_string();
        }
        // 段按 start 排序,找最后一个 start <= addr 的段。
        let idx = self.segs.partition_point(|s| s.start <= addr);
        if idx == 0 {
            return format!("0x{addr:x}");
        }
        let seg = &self.segs[idx - 1];
        if addr < seg.end {
            format!("{}+0x{:x}", seg.module, addr - seg.base)
        } else {
            format!("0x{addr:x}")
        }
    }

    /// 地址落在哪个模块(不折算偏移)。找不到时返回 None。
    #[allow(dead_code)] // 后续 JS API 的 hwbp.watch 会用它做模块校验
    pub(crate) fn module_of(&self, addr: u64) -> Option<&str> {
        let idx = self.segs.partition_point(|s| s.start <= addr);
        if idx == 0 {
            return None;
        }
        let seg = &self.segs[idx - 1];
        if addr < seg.end {
            Some(&seg.module)
        } else {
            None
        }
    }
}

/// 把 maps 里的路径压成短名:`/data/app/.../lib/arm64/libtarget.so` → `libtarget.so`。
///
/// 保留 `(deleted)` 这类标记是有意的 —— 匿名/已删除映射在排查时是关键信息
/// (往往是 JIT 出来的代码或脱壳产物),不能悄悄丢掉。
fn shorten_module_name(path: &str) -> String {
    let deleted = path.contains("(deleted)");
    let core = path.trim_end_matches(" (deleted)").trim();
    let name = core.rsplit('/').next().unwrap_or(core);
    let name = if name.is_empty() { core } else { name };
    if deleted {
        format!("{name}(deleted)")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(start: u64, end: u64, offset: u64, path: &str) -> MapEntry {
        MapEntry {
            start,
            end,
            perms: "r-xp".to_string(),
            offset,
            path: path.to_string(),
        }
    }

    #[test]
    fn resolves_within_module_and_falls_back_outside() {
        // .text 在文件偏移 0x1000,映射到 0x7a3c001000 -> base 0x7a3c000000
        let s = Symbolizer::from_entries(&[
            seg(0x7a3c001000, 0x7a3c005000, 0x1000, "/data/app/lib/arm64/libtarget.so"),
            seg(0x7a3d000000, 0x7a3d002000, 0x0, "/system/lib64/libc.so"),
        ]);

        assert_eq!(s.resolve(0x7a3c001890), "libtarget.so+0x1890");
        assert_eq!(s.resolve(0x7a3d001234), "libc.so+0x1234");
        // 段外(既不在 .text 也不在其它可执行段)
        assert_eq!(s.resolve(0x11223344), "0x11223344");
        assert_eq!(s.resolve(0), "0x0");
        assert_eq!(s.module_of(0x7a3c001890), Some("libtarget.so"));
        assert_eq!(s.module_of(0x11223344), None);
    }

    #[test]
    fn records_base_from_file_offset_not_segment_start() {
        // 关键回归:基址必须扣掉文件偏移,否则偏移会整体偏 .text 的位置
        let s = Symbolizer::from_entries(&[seg(
            0x7a3c010000,
            0x7a3c018000,
            0x10000,
            "/data/app/libtarget.so",
        )]);
        // base = 0x7a3c010000 - 0x10000 = 0x7a3c000000
        assert_eq!(s.resolve(0x7a3c010000), "libtarget.so+0x10000");
    }

    #[test]
    fn keeps_deleted_marker() {
        let s = Symbolizer::from_entries(&[seg(0x1000, 0x2000, 0, "/memfd:jit-cache (deleted)")]);
        assert_eq!(s.resolve(0x1500), "jit-cache(deleted)+0x1500");
    }

    #[test]
    fn ignores_non_executable_and_anonymous() {
        let mut ro = seg(0x5000, 0x6000, 0, "/data/app/libfoo.so");
        ro.perms = "rw-p".to_string();
        let anon = seg(0x7000, 0x8000, 0, "");
        let s = Symbolizer::from_entries(&[ro, anon]);
        assert_eq!(s.resolve(0x5500), "0x5500");
        assert_eq!(s.resolve(0x7500), "0x7500");
    }
}