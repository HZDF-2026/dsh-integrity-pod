# 预注册 — dsh-integrity-pod v0.1.0

> 本文件先于任何插件实现代码与测试代码编写（科研增强方法论·支柱一：预注册）。
> 注册时间：2026-09-01（UTC）；注册人：HZDF-2026。
> 判定依据以本文件进入 git 的首个提交哈希为准（见 AUDIT_LOG.md），禁止事后移动边界。

## 目标

为 DeepSeek Harness（[deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness)，开发者预览版 0.1.1-rc.2）交付五个零构建 ESM 插件包，把[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)的支柱落地为模型可直接调用的运行时能力与安全护栏。零理论内容，仅方法论。

## 交付物（预注册范围）

| 插件包 | 方法论支柱 | 模型可见工具 |
|---|---|---|
| dsh-integrity-prereg | ① 预注册 | prereg_register / prereg_list / prereg_verify |
| dsh-integrity-bitwin | ③ 确定性复现 | bitwin_run |
| dsh-integrity-adjudicate | ④ 裁决实验 | adjudicate |
| dsh-integrity-provenance | ② 管线与数据溯源 | provenance_record / provenance_verify |
| dsh-integrity-guardrail | ⑥ 审计循环 + 安全 | guardrail_status（另挂 tools/pre-execute 与 tools/result 钩子）|

未落地的支柱：⑤ 形式化验证（Lean 4，不在 DSH 运行时内）、⑦ 知识蒸馏（以本仓库 DISTILLATION.md 承担）。

## 验收判定边界（先于测试运行写定）

- **A1 装载**：五个插件 `apply(ctx)` 在模拟 Cordis 上下文下全部无异常完成注册（工具 + 钩子）。
- **A2 链式预注册**：连续注册 3 条后 `prereg_verify` 报 `verified=true`；篡改第 2 行后报 `verified=false` 且 `firstMismatch` 指向第 2 条记录。
- **A3 确定性复现**：`bitwin_run` 对确定性命令（`node -e "console.log(42)"`）判 `bit_identical`；对随机命令（`Math.random()` 输出）判 `divergent`；写随机内容文件的命令在 `file_hash` 维度分歧。
- **A4 裁决**：boundary 取自注册表时 `boundaryProvenance=preregistered`；显式传入未注册边界时 =`post-hoc`；`measured` 越过容差带判 `supported`/`falsified`，落在容差带内判 `inconclusive`；注册表被篡改时 `preregChainVerified=false`。
- **A5 溯源**：记录后原文件未动判 `intact`；改动后判 `drifted`；`rerun` 再生成且哈希一致判 `reproducible`；输入文件缺失时拒绝记录。
- **A6 护栏**（默认 enforce 模式）：`rm -rf /`、`curl…| sh`、读取 `.env`/`id_rsa`、非诚信工具写 `.integrity/` 存储全部被 `deny`；良性命令放行；`mode=audit` 时不 deny；`tools/result` 审计日志追加且哈希链可验证；非法正则配置导致插件装载失败（fail-loud）。
- **A7 总闸**：`node --test tests/` 全部通过（exit 0）。

## 决策规则

- A1–A7 全部通过 → 判定 v0.1.0 达到发布条件，允许建仓与推送。
- 任一不通过 → 停止发布，修复后在 AUDIT_LOG.md 记录偏差与根因，重新裁决。

## 已知限制（预注册即声明）

- 证据层级为 L1（编译装载 + 行为测试）：未在真实 `dsh web` 会话中接入模型调用（无 DEEPSEEK_API_KEY）。真实 profile 安装路径（`dsh plugin add`）以文档与官方教程为准，发布后补充 L2 证据。
- `@deepseek-ai/dsh-tools` 精确锁定 `next` 线 `0.1.1-rc.2`（npm `latest` 是废弃的 0.0.1-rc.1）；DSH 处于开发者预览期，破坏性变更是已知风险，由版本精确锁定缓解。
- 测试基于真实 `defineTool`（来自 npm 包）+ 模拟 Cordis `ctx`，不启动完整 dsh 运行时。
- 护栏的默认拒绝模式为高置信度启发式，不承诺穷尽；`allowPatterns` 提供逃生通道。
