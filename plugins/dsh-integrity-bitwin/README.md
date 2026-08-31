# dsh-integrity-bitwin

DeepSeek Harness 插件：**确定性复现**——把同一条管线命令在净化后的确定性环境中跑两遍，比较 stdout/stderr 哈希、退出码与工作区文件哈希，给出 `bit_identical` / `divergent` 裁决并定位分歧通道。

对应[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)支柱③（确定性复现 / BIT 级一致性）。

## 安装

```sh
npx @deepseek-ai/dsh plugin --profile web add ./plugins/dsh-integrity-bitwin
# 或发布后
dsh plugin add dsh-integrity-bitwin
```

## 工具

| 工具 | 作用 |
|---|---|
| `bitwin_run` | 双跑命令并比对：exit_code / stdout / stderr / file_hash / file_added / file_removed 六类分歧 |

## 确定性环境（两轮相同）

- 固定：`TZ=UTC`、`LC_ALL=C`、`SOURCE_DATE_EPOCH=946684800`、`PYTHONHASHSEED=0`
- 剥离：`TZ`、`LANG`、`LC_*`、`TERM`、`COLUMNS`、`LINES`、`SESSIONNAME`
- 文件哈希范围：cwd 下全部常规文件（跳过 `.git` / `node_modules` / `.integrity`，单文件 ≤ 8MB，总量 ≤ 2000 个）

`durationMs` 仅报告不参与裁决（时长不是内容通道）。

## 典型用法

```
bitwin_run(command="python train.py --config base.yaml", cwd="experiments/run42")
```

裁决为 `divergent` 时优先怀疑：未固定的随机种子、时间/日期依赖、locale、并发写入、追加式日志（第二轮包含第一轮内容）。

## 已知限制

- 通过 `shell: true` 执行，超时强杀的是 shell 进程，进程树孙进程可能残留（Windows 上尤其如此）。
- 环境净化是白名单式固定项，不能穷尽所有非确定性来源（主机名、网络、GPU、并行调度等仍需命令自身控制）。
- 大工作区受 2000 文件 / 8MB 上限约束，超出部分静默跳过（结果中的 `fileCount`/`checkedFiles` 可用于发现截断）。
