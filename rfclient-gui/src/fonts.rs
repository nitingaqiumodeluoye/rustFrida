//! CJK 字体加载。
//!
//! # 为什么必须做这件事
//!
//! eframe 的 `default_fonts` 只带 Latin 字形（Ubuntu-Light / Hack / NotoEmoji），
//! **不含任何汉字**。界面里全是中文，不额外装字体的话所有中文都会渲染成
//! tofu（空心方块）。
//!
//! # 为什么是「找系统字体」而不是「内嵌一份字体」
//!
//! 内嵌一份完整 CJK 字体是 10~20 MB，装进 exe 会让体积翻几倍；而做子集
//! 又不可行 —— 日志面板要显示 agent 回传的**任意**中文（脚本里的
//! `console.log("检测到 xxx")`），字符集在编译期根本不知道。
//! 所以按平台探测系统里已有的字体，Windows/macOS 都自带，Linux 通常也装了
//! Noto CJK。
//!
//! # 为什么要校验魔数
//!
//! epaint 对无法解析的字体数据是 **panic**（`epaint/src/text/fonts.rs` 里
//! `FontFace::new(...).unwrap_or_else(|err| panic!("Error parsing {name:?} TTF/OTF"))`）。
//! 也就是说把垃圾字节交给 `set_fonts` 会让整个程序启动即崩。
//! 因此在交给 egui 之前先检查 sfnt 魔数，宁可退化成 tofu 也不能崩。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eframe::egui;

/// 用这个环境变量可以指定字体文件，覆盖自动探测。
pub const ENV_OVERRIDE: &str = "RFCLIENT_GUI_FONT";

/// 用来验证字体是否真的覆盖中文的探针。
///
/// 取「中文」二字而不是单个字：只测一个字的话，一个只含少量汉字的
/// 装饰字体也能骗过检查。
const CJK_PROBE: &str = "中文日志";

/// 字体注册名（进 `FontDefinitions::font_data` 的 key）。
const FONT_KEY: &str = "cjk";

/// 一个已载入内存的候选字体。
#[derive(Debug)]
pub struct LoadedFont {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

impl LoadedFont {
    /// 人类可读的体积，用于日志。
    pub fn size_mib(&self) -> f32 {
        self.bytes.len() as f32 / (1024.0 * 1024.0)
    }
}

/// sfnt 容器的四种开头：TrueType、`true`、字体集合（ttc）、CFF/OpenType。
fn looks_like_sfnt(data: &[u8]) -> bool {
    match data.get(..4) {
        Some([0x00, 0x01, 0x00, 0x00]) => true,
        Some(b"true") | Some(b"ttcf") | Some(b"OTTO") => true,
        _ => false,
    }
}

/// 各平台的候选字体，按「界面观感」排序而不是按文件名：
///
/// - Windows：优先微软雅黑（现代 Windows 的界面中文字体，笔画均匀，
///   小字号下比黑体清晰），其次等线、黑体、宋体，最后繁体的正黑体。
/// - Linux：Noto Sans CJK（绝大多数发行版的可选依赖）、文泉驿。
/// - macOS：苹方，其次 Hiragino。
fn candidates() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |path: &str| out.push(PathBuf::from(path));

    if cfg!(target_os = "windows") {
        let fonts = std::env::var("SystemRoot")
            .map(|root| format!("{}\\Fonts", root))
            .unwrap_or_else(|_| "C:\\Windows\\Fonts".to_string());
        for name in [
            "msyh.ttc",     // 微软雅黑
            "Deng.ttf",     // 等线
            "simhei.ttf",   // 黑体
            "msyh.ttf",     // 少数精简安装里是 ttf 形式
            "simsun.ttc",   // 宋体
            "msjh.ttc",     // 微软正黑（繁体）
        ] {
            add(&format!("{}\\{}", fonts, name));
        }
        // 有些环境把字体装到了用户目录（绿色版/精简版系统）。
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            for name in ["msyh.ttc", "Deng.ttf", "simhei.ttf"] {
                add(&format!("{}\\Microsoft\\Windows\\Fonts\\{}", local, name));
            }
        }
    } else if cfg!(target_os = "macos") {
        add("/System/Library/Fonts/PingFang.ttc");
        add("/System/Library/Fonts/Hiragino Sans GB.ttc");
        add("/Library/Fonts/Arial Unicode.ttf");
    } else {
        for name in [
            "noto/NotoSansCJK-Regular.ttc",
            "noto/NotoSansCJKsc-Regular.otf",
            "opentype/noto/NotoSansCJK-Regular.ttc",
            "truetype/noto/NotoSansCJK-Regular.ttc",
            "wqy-zenhei/wqy-zenhei.ttc",
            "wqy-microhei/wqy-microhei.ttc",
        ] {
            add(&format!("/usr/share/fonts/{}", name));
        }
        add("/usr/share/fonts/truetype/arphic/uming.ttc");
    }
    out
}

/// 读一个候选文件并做魔数校验。返回 `None` 的原因会通过 `why` 回传，
/// 让上层能给出「文件不存在」还是「文件不是字体」这种可操作的提示。
fn try_load(path: &Path, why: &mut Vec<String>) -> Option<LoadedFont> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            // 文件不存在是最常见的情况（比如没装雅黑的精简系统），
            // 不必每次都刷日志，只在全部失败时汇总。
            if e.kind() != std::io::ErrorKind::NotFound {
                why.push(format!("{}: 读取失败 {}", path.display(), e));
            }
            return None;
        }
    };
    if !looks_like_sfnt(&bytes) {
        why.push(format!(
            "{}: 不是 TTF/OTF/TTC（开头 {:02x?}）",
            path.display(),
            bytes.get(..4).unwrap_or(&[])
        ));
        return None;
    }
    Some(LoadedFont {
        path: path.to_path_buf(),
        bytes,
    })
}

/// 按优先级找到第一个可用的 CJK 字体。
///
/// `RFCLIENT_GUI_FONT` 指定的文件优先，且**只认它** —— 用户显式指定时
/// 静默换成别的字体反而更难排查。
pub fn load_cjk() -> Result<LoadedFont, String> {
    let mut why: Vec<String> = Vec::new();

    if let Some(custom) = std::env::var_os(ENV_OVERRIDE) {
        let path = PathBuf::from(&custom);
        return try_load(&path, &mut why).ok_or_else(|| {
            format!(
                "{}={} 无法作为字体载入：{}",
                ENV_OVERRIDE,
                path.display(),
                if why.is_empty() {
                    "文件不存在".to_string()
                } else {
                    why.join("；")
                }
            )
        });
    }

    for path in candidates() {
        if let Some(font) = try_load(&path, &mut why) {
            return Ok(font);
        }
    }

    let mut msg = String::from("未找到可用的系统中文字体，中文会显示为方块。");
    if !why.is_empty() {
        msg.push_str(" 已排除的候选：");
        msg.push_str(&why.join("；"));
    }
    msg.push_str(&format!(
        " 可设置环境变量 {} 指向任意中文字体文件（.ttf/.ttc/.otf）后重启。",
        ENV_OVERRIDE
    ));
    Err(msg)
}

/// 把字体注册为 **proportional 与 monospace 两个族的兜底字体**。
///
/// 用「追加到族末尾」（而不是插到最前面）是刻意的：拉丁字母继续用 egui 自带的
/// Ubuntu-Light / Hack，只有它们没有的字形（汉字、部分符号）才回落到系统 CJK 字体。
/// 雅黑/Noto 的拉丁字形偏宽，换掉会让整体排版变松。
pub fn install(ctx: &egui::Context, font: &LoadedFont) -> Result<(), String> {
    if !looks_like_sfnt(&font.bytes) {
        // 双保险：install 也可能被别处调用，别让 panic 路径有一丝机会。
        return Err("字体数据不是合法的 TTF/OTF/TTC".to_string());
    }

    let mut definitions = egui::FontDefinitions::default();
    definitions.font_data.insert(
        FONT_KEY.to_owned(),
        Arc::new(egui::FontData::from_owned(font.bytes.clone())),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        definitions
            .families
            .entry(family)
            .or_default()
            .push(FONT_KEY.to_owned());
    }
    ctx.set_fonts(definitions);
    Ok(())
}

/// 检查当前字体是否真的能显示中文。
///
/// 必须在**首帧渲染时**调用：`Context::fonts` 在第一次 `run()` 之前会 panic，
/// 所以不能在 `App::new` 里做这个检查。
pub fn covers_cjk(ctx: &egui::Context) -> bool {
    ctx.fonts_mut(|fonts| {
        fonts.has_glyphs(&egui::FontId::proportional(14.0), CJK_PROBE)
            && fonts.has_glyphs(&egui::FontId::monospace(14.0), CJK_PROBE)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 魔数校验认得四种容器() {
        assert!(looks_like_sfnt(&[0x00, 0x01, 0x00, 0x00]));
        assert!(looks_like_sfnt(b"true....."));
        assert!(looks_like_sfnt(b"ttcf....."));
        assert!(looks_like_sfnt(b"OTTO....."));
    }

    #[test]
    fn 魔数校验拒绝垃圾数据() {
        // 这几类都是「拿错文件」的典型：HTML 错误页、空文件、被截断的数据。
        assert!(!looks_like_sfnt(b"<!DOCTYPE html>"));
        assert!(!looks_like_sfnt(b""));
        assert!(!looks_like_sfnt(&[0x00, 0x01]));
        assert!(!looks_like_sfnt("中文".as_bytes()));
    }

    #[test]
    fn 候选表非空且都是绝对路径() {
        let list = candidates();
        assert!(!list.is_empty());
        for path in &list {
            assert!(path.is_absolute(), "候选路径必须是绝对路径: {}", path.display());
        }
    }

    #[test]
    fn 载入的字体必须真的覆盖中文() {
        // 这是唯一能证明「不再显示方块」的检查：文件存在、魔数正确，
        // 都不代表这个字体里真有汉字（例如误把语言包、图标字体当候选）。
        //
        // 用 headless 的 egui::Context 跑一帧即可：has_glyphs 只查字符映射表，
        // 不需要窗口、也不需要 GPU 光栅化，所以 CI 里也能跑。
        let Ok(font) = load_cjk() else {
            // 环境里没装任何中文字体：跳过（同样让 load_cjk 的返回路径被覆盖到）。
            //
            // 必须**把跳过说出来**：静默跳过会让人以为「CI 验过字体了」，
            // 实际什么都没验 —— 那比没有测试更坏。CI 里用 --nocapture 跑就能看到这行。
            println!(
                "[字体测试] 跳过：本机没有可用的中文字体候选（环境问题，非代码问题）。可用 {} 指定。",
                ENV_OVERRIDE
            );
            return;
        };
        println!(
            "[字体测试] 使用 {}（{:.1} MiB）",
            font.path.display(),
            font.size_mib()
        );

        let ctx = egui::Context::default();
        install(&ctx, &font).expect("注册字体不该失败");

        // egui 0.36 的入口是 run_ui(RawInput, |ui| ...)（老的 run(|ctx| ...) 已改名）。
        let mut covered = false;
        let output = ctx.run_ui(egui::RawInput::default(), |ui| {
            covered = covers_cjk(ui.ctx());
        });
        // FullOutput 带着字体图集的纹理增量，直接 drop 会 panic
        //（egui 要求调用方显式处置）。测试里没有渲染器，故声明为「不应用」。
        output.drop_without_applying_deltas();
        println!(
            "[字体测试] proportional 与 monospace 的 has_glyphs(\"{}\") = {}",
            CJK_PROBE, covered
        );
        assert!(
            covered,
            "字体 {} 能载入，但不含中文字形（界面仍会是方块）",
            font.path.display()
        );
    }

    #[test]
    fn 本机若装了候选字体则必须能通过魔数校验() {
        // 只在 Windows 上断言「找一个」：Linux CI runner 未必装 Noto CJK，
        // 断言存在会变成环境相关的脆弱测试。这里只验证「找到的那些确实像字体」。
        let mut why = Vec::new();
        for path in candidates() {
            if let Some(font) = try_load(&path, &mut why) {
                assert!(looks_like_sfnt(&font.bytes));
                assert!(font.size_mib() > 0.1, "字体文件太小，可能是占位文件");
                println!(
                    "[字体测试] 首选候选 {}（{:.1} MiB）",
                    font.path.display(),
                    font.size_mib()
                );
                return;
            }
        }
        // 一个都没有也算通过（环境问题），但要能给出原因而不是静默。
        let msg = load_cjk().unwrap_err();
        assert!(msg.contains("未找到") || msg.contains("无法作为字体"));
    }
}
