# WalkStack `StackMap not found for 0` — 根因 + 伪 OAT 头根治方案

作者: agent, 2026-04-21（v2，方向改为伪 header）.

## 1. drain 卡死根因

`drain_thunk_in_flight()` (quickjs-hook/src/jsapi/java/mod.rs:975) 无限轮询
`IN_FLIGHT_JAVA_HOOK_CALLBACKS` (registry.rs:73) 归零。计数点只在 Rust
`java_hook_callback`(`callback/hook.rs:88`) 进出。失败模式:

1. **JS_ENGINE 锁串行 + 阻塞 callback 死锁**: T1 在 `java_hook_callback`,
   counter=1, 持 `JS_ENGINE` 锁; 其 JS 在 callOriginal 触发的 Java code 里
   阻塞 (`Object.wait` / Looper / IO)。T2 进 `java_hook_callback`, counter=2,
   在 `acquire_js_engine_for_callback` (`callback_util.rs:55`) 无限等
   `JS_ENGINE.lock()`。T1 永不释放 → counter 永不归零。
2. **JNI 双向死锁**: callback 取了一个 Java monitor, 该 monitor 持有者是
   另一个被 hook 方法的线程, 它也在 callback 里等 JS_ENGINE。环形等待。
3. **callback 内部 callOriginal 间接阻塞**: 已切断的 Layer 1/2/3 让新调用
   走原方法, 但 in-flight callback 已经在执行原方法/JNI, 同样能阻塞。

**结论: drain 不是"等几下就归零"——它依赖外部 Java 线程的 ABA 行为, 在
存在阻塞 / wait 调用链时是无限的。**因此 cleanup 不能依赖 drain==0 来
保证安全 munmap, 必须从 thunk frame **天然合法** 解决。

## 2. AOSP Android 16 (API 36) 源码确认

来源: `git tag android-16.0.0_r1` `art/runtime/oat/` 系列。

### 2.1 OatQuickMethodHeader 布局
```cpp
class PACKED(4) OatQuickMethodHeader {  // 4-byte 对齐, 总 4 字节
  uint32_t code_info_offset_;            // CodeInfo 在 code_ 前几字节
  uint8_t  code_[0];                     // 实际代码紧接其后
};
static OatQuickMethodHeader* FromEntryPoint(const void* ep) {
  return FromCodePointer(EntryPointToCodePointer(ep));  // = ep - 4
}
ALWAYS_INLINE bool IsOptimized() const {                // 仅 nterp 数据为 false
  return code_ != NterpImpl.data() && code_ != NterpWithClinitImpl.data();
}
```

### 2.2 ToDexPc 关键早退
```cpp
uint32_t OatQuickMethodHeader::ToDexPc(ArtMethod** frame, uintptr_t pc, bool abort_on_failure) {
  ArtMethod* method = *frame;
  if (method->IsNative()) return dex::kDexNoIndex;     // ★ 早退, 不查 StackMap, 不 abort
  ...
}
```

### 2.3 StackVisitor::GetDexPc abort 路径 (stack.cc:140)
非 native 路径里 `IsOptimized() && !stack_map.IsValid()` → `LOG(FATAL) "StackMap not found for ..."`。

### 2.4 ArtMethod::GetOatQuickMethodHeader(pc) 关键分支
```cpp
if (!class_linker->IsQuickGenericJniStub(ep) &&
    !IsQuickResolutionStub(ep) && !IsQuickToInterpreterBridge(ep) &&
    !OatQuickMethodHeader::IsStub(ep).value_or(true)) {
  // ★ ep 不在 libart 内 (我们的 thunk pool 满足) → 走这条:
  OatQuickMethodHeader* h = OatQuickMethodHeader::FromEntryPoint(ep);
  if (h->Contains(pc)) return h;       // ★ 我们伪造 header 让这里通过
}
// 否则继续走 JIT cache / OAT file lookup → 失败则 LOG(FATAL).
```

`Contains(pc)`: `code_start <= pc <= code_start + GetCodeSize()`。
`GetCodeSize() = CodeInfo::DecodeCodeSize(code_ - code_info_offset_)`。

### 2.5 CodeInfo 最小编码 (`stack_map.h:576`)
7 个 interleaved 4-bit varint: `[flags, code_size, packed_frame_size,
core_spill_mask, fp_spill_mask, number_of_dex_registers, bit_table_flags]`。
varint 0..11 直接, 12..15 表示后面再读 `(v-11)*8` bits。
`bit_table_flags=0` → 8 个 BitTable 全部省略 (`stack_map.cc:40`)。

**最小编码 (8 字节)**: nibble 序列 `[0, 15, 0, 0, 0, 0, 0]` (28 bits) + 32-bit
`code_size_` (位 28..59) + 4 bits 0 pad = 60 bits = 8B. 字节 (LSB-first):
```
byte0 = 0xF0   // flags=0 | code_size_marker=15
byte1 = 0x00   // packed_frame_size=0 | core_spill_mask=0
byte2 = 0x00   // fp_spill_mask=0 | number_of_dex_registers=0
byte3 = (code_size & 0xF) << 4   // bit_table_flags=0 | code_size bits 0..3
byte4 = (code_size >> 4)  & 0xFF
byte5 = (code_size >> 12) & 0xFF
byte6 = (code_size >> 20) & 0xFF
byte7 = (code_size >> 28) & 0x0F
```

## 3. 伪 OAT header 设计

### 3.1 thunk 内存布局
```
+-------------------+ thunk_mem (entry->thunk)
| 8B fake CodeInfo  |  ← code_info_offset_=8 指向这里
+-------------------+ thunk_mem + 8
| 4B OatQuickMethod |  ← code_info_offset_ = 8
| Header            |
+-------------------+ thunk_mem + 12 ← entry_point_from_quick_compiled_code_
| thunk body        |   patch_target 跳到这里
| (router prologue, |   被 hook 方法 caller BL 进入这里
|  scan, found path,|
|  not_found path)  |
+-------------------+ thunk_mem + 12 + body_size
```

### 3.2 GetOatQuickMethodHeader 命中路径
- `existing_entry_point = thunk + 12`
- `IsStub(thunk+12).value_or(true) = false` (不在 libart)
- `FromEntryPoint(thunk+12) = thunk+12 - 4 = thunk+8` = 我们的伪 header
- `header->Contains(any_pc_in_body) = (thunk+12) ≤ pc ≤ (thunk+12) + body_size` ✓

### 3.3 抹除 `*SP=original` 窗口
仅有伪 header 不够: `GetDexPc` 还是会调 `IsOptimized() && GetStackMap →
InvalidRow → abort`。我们再在 thunk found-path **BLR art_router_stack_check
之前** 把 SP+0 改写为 `replacement` (native). WalkStack 读 `*cur_quick_frame
= *SP = replacement` → `IsNative()=true` → `ToDexPc` 早退 → 无 abort。

剩余窗口: `prologue` 入口 (SUB SP + STP/STR 一连串非 BLR 指令) ~ 第一条
BLR 之前。这段没有 ART implicit suspend check, **同线程 GC 不可能在此打断**;
跨线程 GC peer-walk 的概率极低 (10 ns 量级)。如必要后续可在 prologue 第一
条指令就把 replacement 写到 SP+0 (Layer 3 静态已知 replacement, 直接立即数
LDR 即可), 但 POC 先不做。

### 3.4 跨版本兼容
- Android 14/15/16 OatQuickMethodHeader 三个版本字段相同 (单 `code_info_offset_`),
  伪 header 都成立。
- CodeInfo 编码自 Android 11 起稳定 (BitTable + interleaved varint)。
- API < 31 没有 inline-of-WalkStack 路径, 影响小。POC 主要验证 API 36。

### 3.5 与现有 OAT inline patch / SIGSEGV guard 关系
- 伪 header 让 `GetOatQuickMethodHeader` 自然返回合法 header → 现有 3 处
  inline patch + `hook_replace(GetOatQuickMethodHeader)` + NULL+0x18 SIGSEGV
  guard **理论可全部删除**。POC 暂保留作为兜底, 后续验证后再裁掉。

## 4. POC 改动点清单 (commit `<待commit>`)

文件: `quickjs-hook/src/hook_engine_art.c`
- **新增** `FAKE_OAT_PREFIX_SIZE` (12), `FAKE_OAT_CODEINFO_BYTES` (8)。
- **新增** `encode_fake_codeinfo_code_size()`: 编码 8 字节 CodeInfo, 含
  `code_size_` 字段。
- **新增** `backfill_fake_oat_header()`: 在 thunk_mem[0..12] 写 CodeInfo+header。
- 修改 `generate_art_router_thunk()`: 跳过前 12 字节, 在 body_mem 写 router
  逻辑, 完成后 `backfill_fake_oat_header(thunk_mem, body_size)`, 返回总
  字节数 (含前缀)。
- 修改 `hook_install_art_router()`: `patch_target` 用 `entry->thunk + 12`
  作为跳转目标, 让 ART 看到 entry_point = body 起点。
- 修改 `hook_create_art_router_stub()`: 同样布局, 返回 body 起点供调用方
  写入 `entry_point_`。
- 修改 `emit_art_router_found_path()`:
  * 把 `STR replacement, [SP+0]` (原本在 BLR 之后) **提前到 BLR 之前**,
    保证 walkstack 读到的方法是 native。
  * 在 `art_router_stack_check` 返回 0 (递归) 时, 先恢复 SP+0 = original,
    再 B 到 lbl_not_found, 防止 restore_all 把 x0 错置成 replacement。

文件: 无其他改动。`hook_engine_oat_patch.c` 暂留作兜底,
`agent/src/quickjs_loader.rs` cleanup 流程不变 (drain + munmap 都照常),
但 cleanup 卡死时不再决定生死 — thunk frame 自身合法。

## 5. 编译/部署

构建统一走 CI（`doc/build.md`）：

```bash
REPO=nitingaqiumodeluoye/rustFrida
git push origin master
gh run watch <run-id> --repo "$REPO" --exit-status
gh run download <run-id> --repo "$REPO" -D out/ci-<run-id>

adb -s 10.0.0.44:5556 push out/ci-<run-id>/rustfrida /data/local/tmp/
# 在 Pixel 6 (API 36) 上:
./rustfrida --name com.example -l test_hashmap_put_hook.js
# 触发 HashMap.put 大量调用 + Throwable.fillInStackTrace
# 预期: 不再 LOG(FATAL) "StackMap not found for 0 in HashMap.put"
```

## 6. 下一步

1. 设备验证 fake header 命中 + cleanup 稳定。
2. 确认稳定后删除 `hook_engine_oat_patch.c` (3 处 inline patch +
   `hook_replace(GetOatQuickMethodHeader)` + SIGSEGV guard 三层兜底)。
3. 残留窗口 (prologue 前几条指令): Layer 3 改成静态 replacement 立即数 +
   `STR replacement, [SP+0]` 作为 thunk 第一条指令, 完全消除窗口。
4. Layer 1 共享 stub: replacement 不是静态已知, 仍依赖 scan 后才能写 SP+0;
   同时考虑伪 header 是否够用 (取决于 shared stub 上是否触发 pc=0 abort)。
