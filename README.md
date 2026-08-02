# 复现和判断 Workflow

这是一个用于和合作者共享的“复现和判断”工作流仓库。它适合用来处理论文、实验、产品问题、数据现象、线上故障、用户反馈或任何需要先复现、再判断的问题。

核心目标是让团队在同一套标准下工作：

- 先把问题描述清楚，再开始复现。
- 复现过程保留证据，而不是只保留结论。
- 判断结论区分事实、推断和建议。
- 每个任务都能被合作者接手、复核和追踪。

## 目录

| 路径 | 用途 |
| --- | --- |
| `docs/workflow.md` | 完整工作流说明。 |
| `docs/collaboration.md` | GitHub 协作方式。 |
| `templates/intake.md` | 新任务录入模板。 |
| `templates/reproduction-report.md` | 复现报告模板。 |
| `templates/judgement-record.md` | 判断结论模板。 |
| `examples/example-case.md` | 示例案例。 |

## 快速开始

1. 用 `templates/intake.md` 创建一个新任务。
2. 按 `docs/workflow.md` 完成复现准备、复现执行和证据整理。
3. 用 `templates/reproduction-report.md` 记录复现结果。
4. 用 `templates/judgement-record.md` 给出判断结论。
5. 通过 Pull Request 邀请合作者复核。

## 推荐任务状态

| 状态 | 含义 |
| --- | --- |
| `intake` | 已录入，等待澄清。 |
| `ready-to-reproduce` | 信息足够，可以开始复现。 |
| `reproducing` | 正在复现。 |
| `reproduced` | 已成功复现。 |
| `not-reproduced` | 未能复现，但已记录条件和尝试。 |
| `judging` | 正在判断原因、影响和处理方案。 |
| `resolved` | 已形成结论并完成复核。 |

## 协作原则

- 所有结论必须能追溯到证据。
- 不把“没有复现”直接等同于“问题不存在”。
- 对不确定内容明确标注不确定性。
- 重要判断至少由一名合作者复核。
- 涉及敏感数据时，只提交脱敏样例、摘要或可公开的复现脚本。
