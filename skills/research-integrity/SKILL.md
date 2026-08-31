---
name: research-integrity
description: "Research-integrity workflow for DeepSeek Harness sessions: pre-register claims before data contact, run deterministic re-execution, adjudicate against pre-registered boundaries, record provenance, and keep the guardrail on. Invoke when the task involves experiments, measurements, data analysis, benchmark claims, or any conclusion that will be written down."
---

# Research Integrity（科研诚信运行时工作法）

> 本 skill 是[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)在 DeepSeek Harness 中的运行时形态。方法论全文在上述仓库；本文件只讲**在 dsh 会话里如何用五个插件把它落地**。

## 0. 何时启用

任务满足任一条即启用：
- 要跑实验、测量、评测（benchmark），并得出一个结论
- 要写报告 / README / 论文草稿中的任何定量声明
- 要复现或验证别人（或自己上一轮会话）的结果
- 涉及高危 shell / 文件操作，需要防模型自毁证据或泄密

## 1. 一条主轴

**结论的价值 = 可被反驳的程度 × 接受反驳的方式。**

落到 dsh 会话就是四个动作，顺序不可换：

```
prereg_register（数据接触前写死边界）
  → bitwin_run（确定性复现，BIT 级一致才有效）
  → adjudicate（对照预注册边界裁决，禁止事后挪线）
  → provenance_record（结论登记溯源，可再生成）
```

全程 `dsh-integrity-guardrail` 保持 enforce 模式，防止任何工具（包括你自己）改写 `.integrity/` 下的注册表与审计日志。

## 2. 会话内操作序列

### Phase 0 — 接触数据之前
```
prereg_register({
  claim: "方法A的主指标显著高于基线",
  boundary: 0.05,          // 判定线
  direction: "above",
  tolerance: 0.005,        // 灰区半宽
  decisionRules: "同一配置双跑 BIT 一致后才可裁决；否则结果无效"
})
```
拿到 `PR-001` 与哈希。此后**禁止**修改这条记录——改了 `prereg_verify` 会报 `firstMismatch`。

### Phase 1 — 实施与确定性检查
```
bitwin_run({ command: "node experiment.js", cwd: workspace })
```
- `bit_identical` → 有资格进入裁决
- `divergent` → 先修确定性（种子、环境、时序），**结果无效**，不要解释差异的含义

### Phase 2 — 裁决
```
adjudicate({ preregId: "PR-001", measured: 0.073 })
```
- `boundaryProvenance: "preregistered"` 才是确认性结论
- `post-hoc` → 边界是事后给的，结论自动降级为探索性
- `inconclusive`（落在容差带）→ 诚实报告灰区，禁止挑边
- `falsified` → 走**条件完备化**：找出哪个隐含条件不成立，补为显式前提，重新预注册。禁止把理论改小到只剩对的数据。

### Phase 3 — 登记与溯源
```
provenance_record({
  artifact: "results/metrics.json",
  inputs: ["data/raw.csv"],
  pipeline: "node scripts/compute.js"
})
```
之后任何人改动产物文件，`provenance_verify` 会报 `drifted`；`rerun` 一致则报 `reproducible`。

## 3. 快速自检清单（每轮输出结论前过一遍）

1. 边界是数据接触前注册的吗？（`prereg_verify` 全绿？）
2. 数字是双跑 BIT 一致的吗？（不是 → 无效）
3. 判读用的是预注册规则吗？（计划外发现 → 标注"探索性"，分节书写）
4. 产物有溯源记录吗？（改动可检测、再生成可验证？）
5. 护栏开着吗？（`guardrail_status` 的 mode 是否 `enforce`）

任何一条不过 → 该结论停留在 L2 以下，不得写成确认性声明。

## 4. 反模式（出现即纠正）

| 反模式 | 会话内症状 | 插件级纠正 |
|---|---|---|
| 事后阈值 | "先看看结果再定显著线" | adjudicate 报 `post-hoc` 并降级 |
| 解释差异 | 双跑不一致仍读数 | bitwin 报 `divergent` 即无效 |
| 挪线 | 偷改 prereg 记录 | 哈希链 `firstMismatch` |
| 无中生有 | 结论数字没有再生管线 | provenance 拒绝无管线记录 |
| 毁证据 | 工具试图写 `.integrity/` | guardrail 直接 deny + 审计 |
| 泄密 | 读取 `.env` / `id_rsa` | guardrail deny |

## 5. 证据阶梯（写声明时对号入座）

L0 口头假设 → L1 预注册 → L2 管线可再生成 → L3 裁决通过 → L4 形式化（本套件不覆盖，Lean 4 侧完成）→ L5 蒸馏收录。

本套件把 L1–L3 变成模型可直接调用的运行时能力；L4 在 DSH 运行时之外完成；L5 由各项目的蒸馏文档承担。
