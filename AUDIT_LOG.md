# AUDIT_LOG — dsh-integrity-pod

改进轮审计记录（方法论支柱⑥：每个错误/每轮裁决留下可复核证据）。**只追加，不改写历史条目。**

## 改进轮 R0 — v0.1.0 验收裁决（2026-09-01）

**预注册锚点**：PREREGISTRATION.md 进入版本库的首个提交哈希 = `347f80cdf93d85cf87ba1850b8cb00492bf8aa93`（2026-09-01，root commit；判定依据以此为准，禁止事后移动边界）。

对照 [PREREGISTRATION.md](PREREGISTRATION.md) A1–A7 判定边界：

| 判据 | 结果 | 证据 |
|---|---|---|
| A1 装载 | PASS | 39 个测试中 5 个装载/注册类断言全过（五插件 `apply(ctx)` 无异常，工具 + 钩子注册完整） |
| A2 链式预注册 | PASS | 3 条注册后 verify `verified=true`；篡改第 2 行 → `verified=false`、`firstMismatch.id="PR-002"`、reason="hash mismatch" |
| A3 确定性复现 | PASS | `node -e "console.log(42)"` → `bit_identical`；`Math.random()` → `divergent`；写随机文件 → `file_hash` 维度分歧 |
| A4 裁决 | PASS | 注册表边界 → `preregistered`；临时边界 → `post-hoc`；越界 → `supported`/`falsified`；带内 → `inconclusive`；注册表篡改 → `preregChainVerified=false` |
| A5 溯源 | PASS | intact / drifted / reproducible / 输入缺失拒绝，四态全部按预注册判读 |
| A6 护栏 | PASS | rm-root、pipe-to-shell、env-file、integrity-store-write 均 deny；良性命令放行；audit 模式不 deny；审计日志追加且链可验证；非法正则 fail-loud |
| A7 总闸 | PASS | `node --test "tests/*.test.js"` → **tests 39 / pass 39 / fail 0**（exit 0） |

**裁决**：A1–A7 全过 → v0.1.0 达到发布条件，允许建仓与推送（预注册决策规则第 1 条）。

**环境**：Node v22.16.0（Windows）；`@deepseek-ai/dsh-tools@0.1.1-rc.2`（npm next 线，latest 是废弃的 0.0.1-rc.1）。

## 偏差与修复记录

### R1 — verify-packages 路径解析错误（发现于 A7 复核，2026-09-01）

- **现象**：`node scripts/verify-packages.mjs` 报 5 项 "package.json missing"，实际文件存在。
- **根因**：`path.dirname(fileURLToPath(new URL('..', import.meta.url)))` —— `fileURLToPath` 返回**带尾分隔符**的 `...\dsh-integrity-pod\`，再套一层 `dirname` 会多弹一级到 `h:\work`，导致所有插件包路径整体错位。
- **修复**：去掉外层 `dirname`，`const repoRoot = fileURLToPath(new URL('..', import.meta.url))`。
- **修复后验证**：`package checks: 80 run, 0 failed`（exit 0）。
- **教训固化**：此坑已写入 DISTILLATION.md 第 5 节第 1 条；校验脚本对"文件存在性失败"类报错应先自证脚本自身的路径解析（fail-loud 的前提是 loud 的对象正确）。
- **偏差声明**：A7 门禁在初次复核时实际为 verify 失败 + test 通过；按预注册决策规则第 2 条，未放行发布，先修复再重新裁决（即本条目 + 上表复跑结果）。测试（A1–A6 行为断言）不受影响——缺陷在校验脚本，不在被校验物。

## 环境与工具坑（不构成改进轮，仅记录）

- Windows PowerShell 无 `&&` 语句分隔符；用 `;` + `$LASTEXITCODE`。
- `git` 不在 PATH：`C:\Program Files\Git\cmd\git.exe`。
- `node --test tests/`（目录参数）在 Windows 下不可靠；用 glob `node --test "tests/*.test.js"`。
- 后台任务通知可能出现陈旧 job（输出日志已不存在）——以进程表与实际产物为准。
