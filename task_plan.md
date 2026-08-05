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
| 6. 分析三类源材料 | complete | 已读取复现工作流、判断 `AGENTS.md` 和真实 JSON 样例。 |
| 7. 设计证据包与合并流程 | complete | 确定项目级上下文、告警级代码与日志证据、项目级最终报告。 |
| 8. 编写工作流和模板 | complete | 已改写 README、流程、证据标准、协作规范、模板和脱敏示例。 |
| 9. 校验、提交并推送 | in_progress | 使用真实 JSON 校验字段假设，审核后同步到私人仓库。 |

## 文件结构

| 文件 | 用途 |
| --- | --- |
| `README.md` | 仓库入口，说明用途、目录、快速开始。 |
| `docs/workflow.md` | 完整复现和判断流程。 |
| `docs/evidence-standard.md` | JSON 字段映射、证据包约定、证据等级和判断矩阵。 |
| `docs/collaboration.md` | 与合作者协作、分支、评审和权限建议。 |
| `templates/intake.md` | 新任务录入模板。 |
| `templates/project-context.md` | 项目级全局上下文模板。 |
| `templates/code-evidence.txt` | 单条告警的纯文本源码证据模板。 |
| `templates/reproduction-report.md` | 复现记录模板。 |
| `templates/judgement-record.md` | 判断结论模板。 |
| `examples/example-case.md` | 一个端到端示例。 |
| `.gitignore` | 避免上传系统文件、临时文件和敏感信息。 |

## 当前适配重点

- 输入：Go 漏洞检测工具针对单个 Go 项目生成的 JSON 报告。
- 处理：解析告警、定位源码与调用链、构造复现、判断真阳性/误报/待确认。
- 输出：可追溯的复现证据、判断依据和结构化结果。
- 已确认：一个 JSON 对应一个项目并包含多条告警；最终生成项目级 `report.md`。
- 判断输入：项目级 `project.md`、每条告警的 `code.txt`、每条告警的 `runtime.log`。
- 原始 JSON 用于候选生成和追溯，不直接作为真阳性证据。

## 遇到的错误

| 错误 | 尝试次数 | 处理 |
| --- | --- | --- |
| 当前目录不是 Git 仓库 | 1 | 准备初始化仓库。 |
| 当前目录为空 | 1 | 从工作流文档骨架开始创建内容。 |
| 历史记忆搜索失败 | 1 | 按目录名和用户目标产出可迭代初稿。 |
