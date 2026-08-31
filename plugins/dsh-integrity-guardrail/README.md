# dsh-integrity-guardrail

DeepSeek Harness 安全插件：**护栏 + 审计循环**——在 `tools/pre-execute` 权限瀑布上拒绝高危工具调用，在 `tools/result` 上追加哈希链审计日志。

对应[科研增强方法论](https://github.com/HZDF-2026/research-enhancement-methodology)支柱⑥（审计循环），同时是该生态当前最缺的安全模块。

## 安装

```sh
npx @deepseek-ai/dsh plugin --profile web add ./plugins/dsh-integrity-guardrail
```

## 机制

| 扩展点 | 行为 |
|---|---|
| `tools/pre-execute` | 匹配拒绝模式 → `{ kind: 'deny', reason }`；否则 `next()` 放行 |
| `tools/result` | 每次工具结果追加一条哈希链审计记录（`kind: "tool_result"`） |
| 工具 `guardrail_status` | 查看当前模式、模式清单与审计统计 |

被拒绝的调用同样进审计日志（`kind: "deny"`；audit 模式记 `would-deny` 但放行）。

## 默认拒绝模式（id）

| id | 拦截 |
|---|---|
| `rm-root` | `rm` 指向 `/`、`~`、`.`、`*`、`$HOME` |
| `mkfs` / `dd-raw-disk` / `chmod-root` | 磁盘级破坏 |
| `pipe-to-shell` | `curl/wget … \| sh`（供应链投毒经典形态） |
| `sudo` | 提权 |
| `win-rd-s` / `win-del-s` / `win-format` / `win-remove-item-drive` | Windows 递归删除/格式化 |
| `shutdown` | 关机重启 |
| `env-file` / `ssh-cred-file` | 凭据文件读取（`.env`、`id_rsa`、`.npmrc`、`.aws/credentials` 等，防模型外泄凭据） |
| `git-force-main` | force push 到 main/master |
| `etc-passwd-write` | 改写 `/etc/passwd` 系列 |
| `integrity-store-write` | 非诚信工具写入 `.integrity/`（防止模型篡改预注册/溯源记录——本套件的反作弊闭环） |

模式匹配对象是工具参数的全部字符串值与其 JSON 序列化，因此对 bash 类工具与文件类工具同样生效。

## 配置（cordis.patch.yml 的行内 config）

```yaml
- insert:
    - id: integrity-guardrail
      name: dsh-integrity-guardrail
      config:
        mode: enforce                 # enforce | audit
        extraDenyPatterns: []         # 追加的正则源字符串
        allowPatterns: []             # 逃生通道（优先于拒绝判断）
        protectIntegrityStores: true
        integrityStoreDir: .integrity
        auditLog: true
        auditPath: .integrity/tool-audit.jsonl
```

非法正则或非法 mode 会让插件装载失败（fail-loud，不静默降级）。

## 已知限制

- 拒绝模式是高置信度启发式，不承诺穷尽所有攻击面；敏感部署应叠加 DSH 自带的沙箱/审批插件。
- `tools/result` 事件负载形态在开发者预览期可能变化，处理器做了多形态防御性解析。
- 审计日志防篡改等级为"可检测"（哈希链），非密码学签名。
