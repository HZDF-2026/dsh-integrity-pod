# dsh-integrity-adjudicate

DeepSeek Harness 插件：**裁决实验**——用测量值对照预注册边界给出 `supported` / `falsified` / `inconclusive` 裁决，并暴露边界来源（`preregistered` vs `post-hoc`）与注册表链完整性。

对应[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)支柱④（裁决实验）。

## 安装

```sh
npx @deepseek-ai/dsh plugin --profile web add ./plugins/dsh-integrity-adjudicate
```

## 工具

| 工具 | 作用 |
|---|---|
| `adjudicate` | 输入 measured +（preregId 或 boundary），输出裁决与证据来源标注 |

## 裁决语义

设 `margin = measured − boundary`，`tolerance` 为绝对容差带：

| 条件 | 裁决 |
|---|---|
| \|margin\| ≤ tolerance | `inconclusive`（灰区，即"测了但测不实"） |
| direction=above 且 margin > 0（越带） | `supported` |
| direction=above 且 margin < 0（越带） | `falsified` |
| direction=below 镜像同理 | `supported` / `falsified` |

诚实性标注：

- `boundaryProvenance: "preregistered"`：边界取自 `prereg_register` 写入的哈希链注册表
- `boundaryProvenance: "post-hoc"`：边界为临时给出——**结果可用但被标记**，报告引用时必须声明
- `preregChainVerified: false`：注册表被篡改，裁决本身失去依据

## 与 prereg 的共享约定

两个插件共享 `.integrity/prereg.jsonl` 的记录格式与哈希链字段序（id, registeredAt, claim, boundary, direction, tolerance, decisionRules, prevHash）。修改任一侧的字段序都会使跨包链校验失效——这是有意的紧耦合契约。

## 已知限制

- 仅支持单边界数值裁决；多通道复合裁决（如 bootstrap CI 区间判定）需调用方自行分解为多次单边界裁决。
- `preregChainVerified` 只在通过 preregId 取边界时计算。
