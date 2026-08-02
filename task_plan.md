# 共享复现和判断 Workflow 计划

## 目标

把当前“复现和判断”工作流整理成一个可协作、可复用、可追踪的 GitHub 私人仓库。

## 阶段

| 阶段 | 状态 | 说明 |
| --- | --- | --- |
| 1. 明确仓库结构 | complete | 采用 README + docs + templates + examples 的轻量结构。 |
| 2. 编写工作流文档 | complete | 输出完整流程、角色、状态、模板和示例。 |
| 3. 初始化版本库 | complete | 创建 Git 历史并提交初版。 |
| 4. 推送私人仓库 | complete | 使用 GitHub 私有仓库共享给合作者。 |
| 5. 收尾说明 | complete | 给出仓库地址和后续协作方式。 |

## 文件结构

| 文件 | 用途 |
| --- | --- |
| `README.md` | 仓库入口，说明用途、目录、快速开始。 |
| `docs/workflow.md` | 完整复现和判断流程。 |
| `docs/collaboration.md` | 与合作者协作、分支、评审和权限建议。 |
| `templates/intake.md` | 新任务录入模板。 |
| `templates/reproduction-report.md` | 复现记录模板。 |
| `templates/judgement-record.md` | 判断结论模板。 |
| `examples/example-case.md` | 一个端到端示例。 |
| `.gitignore` | 避免上传系统文件、临时文件和敏感信息。 |

## 遇到的错误

| 错误 | 尝试次数 | 处理 |
| --- | --- | --- |
| 当前目录不是 Git 仓库 | 1 | 准备初始化仓库。 |
| 当前目录为空 | 1 | 从工作流文档骨架开始创建内容。 |
| 历史记忆搜索失败 | 1 | 按目录名和用户目标产出可迭代初稿。 |
