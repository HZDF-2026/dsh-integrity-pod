# dsh-integrity-prereg

DeepSeek Harness 插件：**预注册**——在接触数据之前，把可证伪的命题、判定边界与决策规则写入追加式、哈希链化的注册表，事后改动可被检测。

对应[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)支柱①。

## 安装

```sh
# 本地路径安装（开发）
npx @deepseek-ai/dsh plugin --profile web add ./plugins/dsh-integrity-prereg
# npm 安装（发布后）
dsh plugin add dsh-integrity-prereg
# 验证装载
npx @deepseek-ai/dsh --profile web --dump-config
```

## 工具

| 工具 | 作用 |
|---|---|
| `prereg_register` | 追加一条预注册记录：claim + boundary + direction + tolerance + decisionRules，返回 id 与哈希 |
| `prereg_list` | 列出注册表内容摘要 |
| `prereg_verify` | 重算整条哈希链，报告篡改位置 |

存储默认在 cwd 下 `.integrity/prereg.jsonl`（JSONL，每行一条，`prevHash` 链接前一条）。

## 判定语义（与 dsh-integrity-adjudicate 共享）

- `direction: "above"`：measured > boundary（超出容差带）→ supported
- `tolerance`：|measured − boundary| ≤ tolerance → inconclusive（灰区）
- 边界未预注册而临时给出 → adjudicate 报 `boundaryProvenance: "post-hoc"`

## 已知限制

- 防篡改是"可检测"级别（哈希链），不是"不可篡改"级别（无签名、无外部时间戳）。
- 运行时文件可被其他工具改写；配合 `dsh-integrity-guardrail` 的 `.integrity/` 写保护可提高门槛。
