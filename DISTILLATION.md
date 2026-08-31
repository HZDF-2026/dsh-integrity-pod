# DISTILLATION — dsh-integrity-pod v0.1.0

> 单文件总入口：恢复本项目工作时**先读本文件**，不读散落档案（方法论支柱⑦）。
> 状态：v0.1.0 已通过预注册验收（A1–A7），2026-09-01。改进轮历史见 [AUDIT_LOG.md](AUDIT_LOG.md)。

## 1. 本项目是什么（一句话）

为 DeepSeek Harness（开发者预览 `0.1.1-rc.2`）交付五个零构建 ESM 插件 + 一个 skill，把[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)七支柱中的 ①②③④⑥ 落地为模型可调用的运行时能力；⑤⑦ 留在运行时之外（Lean 4 / 本文件）。零理论内容。

## 2. 五插件与工具语义（已确立，勿重复推导）

| 插件 | 工具 | 关键语义 |
|---|---|---|
| prereg | `prereg_register` / `prereg_list` / `prereg_verify` | JSONL 追加式，每行含 `prevHash` 哈希链；篡改第 n 行 → verify 报 `firstMismatch` 指向该行 |
| bitwin | `bitwin_run` | 净化环境（去时间戳类 env）双跑；比对维度 stdout/stderr/exit code/duration/cwd 文件树 SHA256；全同 → `bit_identical`，任一异 → `divergent`（附首分歧维度） |
| adjudicate | `adjudicate` | 边界取自 prereg 注册表 → `boundaryProvenance: "preregistered"`；临时传入 → `post-hoc`；\|measured−boundary\| ≤ tolerance → `inconclusive`；否则按 direction 判 `supported`/`falsified`；注册表被篡改 → `preregChainVerified: false` |
| provenance | `provenance_record` / `provenance_verify` | 记录 artifact+inputs+pipeline；原文件未动 → `intact`，改动 → `drifted`，rerun 哈希一致 → `reproducible`；输入缺失 → 拒绝记录 |
| guardrail | `guardrail_status` + `tools/pre-execute` + `tools/result` 钩子 | 默认 `enforce`；13 类拒绝模式（rm-root/mkfs/pipe-to-shell/凭据文件/git-force-main/Windows 递归删/integrity-store-write…）；allow 优先于 deny；audit 模式只记 `would-deny`；审计日志自身是哈希链；非法正则 → 装载失败（fail-loud） |

**判定语义共享约定**：`direction: "above"` 表示 measured > boundary 为 supported；tolerance 灰区永不挑边。

## 3. 工程结构（已定型）

```
plugins/<pkg>/  = package.json（dsh.bundle.patch 字段）+ cordis.patch.yml + index.js + README.md
                 零构建 ESM，main=index.js，files 三件套，dsh-tools 精确锁 0.1.1-rc.2
tests/          = node:test + 自制模拟 Cordis ctx（tests/harness.js：register/on/effect + preExecute 瀑布）
skills/         = research-integrity SKILL.md（会话工作法：注册→双跑→裁决→登记，顺序不可换）
scripts/        = verify-packages.mjs（80 项元数据检查；repoRoot 用 URL('..') 解析，勿再包 dirname——见 AUDIT_LOG R1）
```

插件 `export const name = '<去 dsh- 前缀>'`、`export function apply(ctx)`，工具用真实 `defineTool`（来自 `@deepseek-ai/dsh-tools`）定义。

## 4. 验收与证据（L1 级）

- 预注册：[PREREGISTRATION.md](PREREGISTRATION.md)（A1–A7 判定边界先于测试写定；锚定 = 包含它的首个 git 提交哈希，记录于 AUDIT_LOG.md）
- 测试：39/39 通过（`node --test "tests/*.test.js"`，Node 22.16）
- 包校验：80/80 通过（`npm run verify`）
- 证据层级 L1：真实 defineTool + 模拟 Cordis ctx；**未做**：带 API Key 的真实 `dsh web` 会话验证、`dsh plugin add` 真实安装路径（发布后补 L2）

## 5. 关键经验（R1 及环境坑）

1. `fileURLToPath(new URL('..', import.meta.url))` 已带尾分隔符，再套 `path.dirname` 会多弹一层 → verify-packages 曾因此全报 "package.json missing"（R1）。
2. Windows PowerShell 无 `&&`；git 不在 PATH，用 `C:\Program Files\Git\cmd\git.exe`。
3. `node --test tests/` 在 Windows 下目录参数不可靠，用 glob `"tests/*.test.js"`。
4. `@deepseek-ai/dsh-tools` 的 npm `latest` 是废弃的 `0.0.1-rc.1`，必须显式锁 `0.1.1-rc.2`（next 线）。
5. DSH 处于开发者预览期，`tools/result` 事件负载形态可能变——guardrail 已做多形态防御性解析。

## 6. 复现地图

```
命令                         → 产物
npm install                  → node_modules（dsh-tools 0.1.1-rc.2）
npm test                     → 39 测试结果（TAP 输出）
npm run verify               → 80 项包检查
tests/*.test.js              → 各自断言 A2–A6 行为
guardrail 运行时             → .integrity/tool-audit.jsonl（哈希链，gitignore）
prereg 运行时                → .integrity/prereg.jsonl
```

## 7. 下一步（按优先级）

1. L2 证据：真实 `dsh web` + API Key 会话中走通 注册→双跑→裁决→登记 全链（预注册：会话内四步调用全部成功且 guardrail 审计日志完整）。
2. 发布 npm（五包单独 publish，`dsh plugin add <name>` 路径验证）。
3. 跟踪 DSH 上游破坏性变更：锁版本策略 + 升级轮次记录进 AUDIT_LOG。

## 8. 边界与红线

- 只做方法论，不进任何理论内容（对外披露纪律）。
- 护栏是"高置信度启发式 + 可检测防篡改"，**不得**在文档中宣称"不可绕过 / 密码学安全"。
- 预注册边界一经提交冻结，任何后续改动都必须走 AUDIT_LOG 记录偏差，禁止静默移动。
