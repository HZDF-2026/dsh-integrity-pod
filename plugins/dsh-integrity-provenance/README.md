# dsh-integrity-provenance

DeepSeek Harness 插件：**数据溯源**——把产物（artifact）绑定到输入、管线与 git 提交的哈希链记录，支持"原地校验"与"再生校验"两种验证。

对应[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)支柱②（管线与数据溯源）。

## 安装

```sh
npx @deepseek-ai/dsh plugin --profile web add ./plugins/dsh-integrity-provenance
```

## 工具

| 工具 | 作用 |
|---|---|
| `provenance_record` | 记录：artifact SHA256 + 每个 input 的 SHA256 + pipeline 描述 + git commit + 仓库是否 dirty |
| `provenance_verify` | 验证：不带 `rerun` → 原地比对（intact / drifted / missing）；带 `rerun` → 先执行再生命令再比对（reproducible / divergent） |

存储默认 `.integrity/provenance.jsonl`（JSONL 哈希链，与 prereg 同构）。

## 裁决语义

| 场景 | 结果 |
|---|---|
| 记录后文件未动 | `intact` |
| 记录后文件被改 | `drifted` |
| 文件消失 | `missing` |
| `rerun` 再生成且哈希与记录一致 | `reproducible`（管线可从原料再生该产物） |
| `rerun` 后哈希不一致 | `divergent` |

`repoDirty: true` 表示记录时工作区有未提交改动——溯源证据弱化，报告引用时应声明。

## 已知限制

- git 信息取自 process cwd，不支持 per-artifact 仓库定位。
- `rerun` 命令在净化环境下执行（与 bitwin 相同的确定性环境），但不比对中间产物，只比对最终 artifact 哈希。
