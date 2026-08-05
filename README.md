# Go 漏洞复现与判断 Workflow

这个仓库用于把 Go 漏洞检测工具生成的项目级 JSON 报告，转化为可追溯、可复核的人工判断报告。

核心流程：

```text
report.json
  -> 项目全局信息 project.md
  -> 每条告警的源码证据 code.txt
  -> 每条告警的 Docker 证据 runtime.log
  -> 项目级判断报告 report.md
```

扫描器的 `reasoning`、`evidence`、严重度和置信度都是待验证线索。只有真实源码路径与受控运行结果形成证据闭环，才能给出确认结论。

## 证据包

```text
cases/<project>/<scan-id>/
  report.json
  intake.md
  project.md
  findings/
    F001/
      code.txt
      runtime.log
  report.md
```

判断阶段使用三类文件：

| 文件 | 作用 |
| --- | --- |
| `project.md` | 项目、commit、Go、Docker、扫描范围、入口和信任边界。 |
| `code.txt` | 一条 finding 的真实调用方、输入、校验/缓解、危险操作和影响代码。 |
| `runtime.log` | Docker 中的精确命令、原始 stdout/stderr、退出码和观察结果。 |

最终 `report.md` 汇总全部选中告警，不替代三类原始证据。

## 快速开始

1. 将原始 JSON 放入案例目录并重命名为 `report.json`，不要修改内容。
2. 使用 [`templates/intake.md`](templates/intake.md) 校验 JSON、记录 SHA-256，并选择告警。
3. 使用 [`templates/project-context.md`](templates/project-context.md) 生成项目级 `project.md`。
4. 为每条告警复制 [`templates/code-evidence.txt`](templates/code-evidence.txt) 为 `code.txt`，从目标 commit 截取真实代码。
5. 按 [`templates/reproduction-report.md`](templates/reproduction-report.md) 设计 Docker 实验，并保存原始 `runtime.log`。
6. 三类证据一致后，使用 [`templates/judgement-record.md`](templates/judgement-record.md) 生成项目级 `report.md`。
7. 通过 Pull Request 让合作者复核证据和结论。

## 判断结果

| 结论 | 含义 |
| --- | --- |
| `confirmed` | 真实路径、可达性/可控性和运行行为形成闭环。 |
| `conditional` | 行为已复现，但依赖明确的非默认前提。 |
| `false-positive` | 源码或运行反证明扫描器主张错误，或稳定缓解层阻断影响。 |
| `not-reproduced` | 有效实验没有观察到行为，但尚不能证明误报。 |
| `insufficient-evidence` | 三类证据缺失、错配、无效或影响未闭环。 |

没有复现不等于误报。误报需要证明扫描器主张为什么不成立。

## 文档入口

| 路径 | 内容 |
| --- | --- |
| [`docs/workflow.md`](docs/workflow.md) | 完整八阶段工作流。 |
| [`docs/evidence-standard.md`](docs/evidence-standard.md) | JSON 字段、证据等级、判断矩阵和一致性规则。 |
| [`docs/collaboration.md`](docs/collaboration.md) | GitHub 协作、复核与敏感材料规范。 |
| [`examples/example-case.md`](examples/example-case.md) | 脱敏的端到端示例。 |

## 共同原则

- JSON 告警是候选，不是结论。
- 读取真实源码，不能只引用扫描器摘录。
- `code.txt` 同时保留支持证据和缓解/反证。
- `runtime.log` 保留原始输出，`report.md` 只引用关键片段。
- 只在本地 checkout、Docker、测试或隔离沙箱中验证。
- 不测试第三方线上服务，不提交凭据、私有源码或未脱敏敏感数据。
- 重要判断至少由一名合作者独立复核。
