# Progress

## 2026-08-02

- 确认工作区为空且尚未初始化 Git 仓库。
- 确认 GitHub CLI 已登录账号 `GG-Feng`。
- 创建任务计划、发现记录和进度日志。
- 创建 README、完整工作流文档、GitHub 协作说明、任务录入模板、复现报告模板、判断记录模板和示例案例。
- 检查文档结构与行数，确认仓库内容已具备初版共享条件。
- 初始化 Git 仓库，创建初始提交 `docs: add reproduction judgement workflow`。
- 创建并推送 GitHub 私有仓库：`https://github.com/GG-Feng/reproduction-judgement-workflow`。
- 确认远端仓库为 private，默认分支为 `main`，本地工作区无未提交内容。

## 2026-08-05

- 用户补充真实业务背景：工具用于检测 Go 项目漏洞，每次输出项目级 JSON 报告，团队依据报告开展复现和判断。
- 检查仓库内容，确认当前版本仍是通用工作流，且仓库内没有 JSON 样例或字段定义。
- 将计划扩展为 Go 漏洞 JSON 适配、真实样例校验和新版推送三个阶段。
- 阅读现有 README、主流程、三个模板和示例，完成从通用问题工作流到 Go 漏洞告警工作流的改造范围分析。
- 暂停正式文档改写与推送，等待脱敏 JSON 样例或字段说明，避免在共享规范中虚构工具字段。
- 用户提供完整复现工作流，并指出判断工作流位于本地 `go项目BUG-issue发布/AGENTS.md`。
- 读取复现工作流并定位判断规则文件，确认最终产物应从 GitHub Issue 改为本地 `report.md`。
- 收到并校验真实扫描 JSON 样例，完成顶层结构、项目元数据、告警字段和严重度分布分析。
- 确认报告为“单项目、多告警”结构，并明确检测器推理只能作为复现线索，不能直接作为最终判断证据。
- 读取 `go项目BUG-issue发布/AGENTS.md`，提炼判断证据门槛、安全边界、影响闭环和不夸大原则。
- 检查样例中的项目领域、函数评分和全部 8 条 high 告警，确认扫描器元数据只用于排序，最终结论必须依赖真实源码与运行证据。
- 抽查原判断仓库的协作规范、项目概览和单项概览，确认旧流程只保存日志摘要，没有保存原始 `.log` 证据。
- 确定新的四文件证据包和项目/告警两级目录，并创建详细实施计划 `docs/superpowers/plans/2026-08-05-go-vulnerability-evidence-workflow.md`。
- 根据用户建议，将源码证据从 `code.md` 调整为纯文本 `code.txt`，并定义固定元数据头部和三段代码分隔格式。
- 创建 `docs/evidence-standard.md`，完成 JSON 字段映射、四文件证据包、证据等级和判断矩阵。
- 重写 `docs/workflow.md`，形成 JSON 接收、项目上下文、源码核验、Docker 复现、三文件检查、判断、报告和复核八阶段流程。
- 新增 `project.md`、`code.txt` 模板，并把原有录入、复现和判断模板改造成 JSON intake、`runtime.log` 采集和最终 `report.md` 模板。
- 运行关键词、阶段顺序和模板覆盖检查，第一轮结果通过。
- 重写 README 和 GitHub 协作规范，明确案例目录、角色、PR 检查和敏感材料边界。
- 将原通用产品示例替换为虚构 Go 路径告警示例，演示 `project.md + code.txt + runtime.log -> report.md` 的误报证据闭环。
- 检查旧通用场景词和旧 `code.md` 引用；正式工作流文件已统一使用 `code.txt`。
- 发现并修复 `.gitignore` 与证据包冲突：普通 `.log` 仍忽略，案例目录下的 `runtime.log` 允许提交。
- 完成真实 JSON 结构、告警数量、必需 finding 字段、Markdown 标题、README 链接、旧扩展名和差异空白检查。
- 创建提交 `b7f81ab`：`docs: combine Go vulnerability reproduction and judgement workflow`。
- 将合并后的工作流推送到 `origin/main`，远端私人仓库已更新。
