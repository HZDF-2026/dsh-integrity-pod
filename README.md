# dsh-integrity-pod

**DeepSeek Harness 科研诚信与安全插件套件** —— 把[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)的七支柱落地为模型可直接调用的运行时工具与安全护栏。

[![CI](https://github.com/HZDF-2026/dsh-integrity-pod/actions/workflows/ci.yml/badge.svg)](https://github.com/HZDF-2026/dsh-integrity-pod/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## 为什么做这个

DeepSeek Harness（[deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)）在 2026-08 进入开发者预览（`0.1.1-rc.2`），是国内增长最快的 Agent 运行时方向之一。它把工具、模型适配器、Agent Loop 全部做成 Cordis 插件，扩展性极强——但生态刚起步，**科研诚信与运行时安全两类模块基本空白**：

- 模型可以事后挪阈值、把探索性结果包装成确认性结论，无检测手段；
- 工具调用没有面向 Agent 场景的高危操作护栏（`rm -rf /`、`curl | sh`、凭据文件读取在默认权限模型下畅通）；
- 实验结果无法 BIT 级复现验证，"复现"停留在口头。

本套件用五个零构建 ESM 插件 + 一个 skill 填这些洞。**只含方法论，零理论内容。**

## 套件内容

| 插件包 | 方法论支柱 | 模型可见工具 | 一句话 |
|---|---|---|---|
| [dsh-integrity-prereg](plugins/dsh-integrity-prereg) | ① 预注册 | `prereg_register` / `prereg_list` / `prereg_verify` | 数据接触前写死判定边界，追加式哈希链，事后篡改可检测 |
| [dsh-integrity-bitwin](plugins/dsh-integrity-bitwin) | ③ 确定性复现 | `bitwin_run` | 同一命令双跑比对（stdout/stderr/exit/文件树哈希），非 BIT 一致即无效 |
| [dsh-integrity-adjudicate](plugins/dsh-integrity-adjudicate) | ④ 裁决实验 | `adjudicate` | 对照预注册边界三分判读（supported / falsified / inconclusive），边界来源可追溯 |
| [dsh-integrity-provenance](plugins/dsh-integrity-provenance) | ② 管线与溯源 | `provenance_record` / `provenance_verify` | 产物↔输入↔管线登记，改动检测（drifted）与再生成验证（reproducible） |
| [dsh-integrity-guardrail](plugins/dsh-integrity-guardrail) | ⑥ 审计循环 + 安全 | `guardrail_status`（+ 两个钩子） | `tools/pre-execute` 拦高危调用，`tools/result` 写哈希链审计日志，保护 `.integrity/` 存储 |

另附 [skills/research-integrity](skills/research-integrity)（方法论会话工作法 skill，教模型在 dsh 会话内按四个动作的固定顺序使用上述工具）。

未落地支柱：⑤ 形式化验证（Lean 4，在 DSH 运行时之外）；⑦ 知识蒸馏（由 [DISTILLATION.md](DISTILLATION.md) 承担）。

## 安装

要求 Node.js ≥ 22。

```sh
git clone https://github.com/HZDF-2026/dsh-integrity-pod.git
cd dsh-integrity-pod

# 逐个加入 profile（本地路径安装）
npx @deepseek-ai/dsh@0.1.1-rc.2 plugin --profile web add ./plugins/dsh-integrity-prereg
npx @deepseek-ai/dsh@0.1.1-rc.2 plugin --profile web add ./plugins/dsh-integrity-guardrail
# …其余三个同理

# 验证装载
npx @deepseek-ai/dsh@0.1.1-rc.2 --profile web --dump-config
```

五个插件相互独立，可单独安装；组合使用时 guardrail 建议始终在场（它同时是其余四个的反作弊护栏）。

## 快速上手（模型会话内）

```
用户：帮我评测两个方法，主指标越高越好，显著线 0.05

模型（自动调用）：
  prereg_register({ claim: "方法A主指标>0.05", boundary: 0.05, direction: "above" })
  bitwin_run({ command: "node bench.js" })        → bit_identical 才继续
  adjudicate({ preregId: "PR-001", measured: 0.073 }) → supported（边界=预注册）
  provenance_record({ artifact: "results.json", inputs: [...], pipeline: "node bench.js" })
```

配套 skill（`skills/research-integrity`）把这个顺序固化为会话纪律：**注册 → 双跑 → 裁决 → 登记**，四步顺序不可换。

## 验证

```sh
npm install
npm run verify   # 80 项包结构检查（五插件元数据一致性）
npm test         # 39 个行为测试（真实 defineTool + 模拟 Cordis ctx）
```

验收标准先于测试写定于 [PREREGISTRATION.md](PREREGISTRATION.md)（A1–A7），裁决记录见 [AUDIT_LOG.md](AUDIT_LOG.md)。

## 仓库布局

```
plugins/          五个插件包（package.json + cordis.patch.yml + index.js + README）
skills/           research-integrity 会话工作法 skill
tests/            node:test 行为测试 + 模拟 Cordis harness
scripts/          verify-packages.mjs 包结构自检
PREREGISTRATION.md 验收判定边界（数据接触前冻结）
AUDIT_LOG.md      改进轮审计记录
DISTILLATION.md   单文件知识总入口
```

## 已知限制（诚实声明）

- 证据层级 **L1**：编译装载 + 行为测试（真实 `defineTool` + 模拟 Cordis ctx）；未在带 API Key 的真实 `dsh web` 会话中跑通模型调用，发布后补 L2 证据。
- DSH 处于开发者预览期，破坏性变更是已知风险；`@deepseek-ai/dsh-tools` 精确锁死 `0.1.1-rc.2`（npm `latest` 是已废弃的 `0.0.1-rc.1`）。
- 护栏的拒绝模式是高置信度启发式，不承诺穷尽；敏感部署请叠加 DSH 自带沙箱/审批。
- 防篡改等级为"可检测"（哈希链），非密码学签名。

## License

[Apache-2.0](LICENSE)
