# Findings

## 当前上下文

- 工作目录：`/Users/oliverwu/Documents/复现和判断-workflow`
- 当前目录初始为空，不是 Git 仓库。
- 本机已安装 Git 和 GitHub CLI。
- GitHub CLI 已登录账号：`GG-Feng`。
- 用户目标：先把整个 workflow 写出来，然后推送到用户自己的私人仓库。

## 决策

- 使用轻量文档仓库结构，不引入复杂工程框架。
- 仓库名优先使用 ASCII：`reproduction-judgement-workflow`，便于 GitHub 链接、命令行和跨平台协作。
- 默认创建私人仓库，避免未确认前公开工作流内容。

## 2026-08-05：Go 漏洞检测工具上下文

- 工作流的真实输入不是普通问题单，而是漏洞检测工具为每个 Go 项目生成的 JSON 报告。
- 后续流程需要围绕 JSON 告警展开：字段解析、项目与版本确认、漏洞点定位、可达性分析、复现、证据整理、结论判定和结果输出。
- 当前仓库没有任何 JSON、JSONL 或 JSON Schema 文件，暂时无法确定字段映射和单个报告包含一条还是多条告警。
- 为避免把虚构字段写入共享规范，需要一份脱敏后的真实 JSON 样例或正式字段说明。

## 现有文档适配分析

- `README.md` 目前把论文、产品、数据等都列为适用范围，应收窄为 Go 项目漏洞检测报告的复现与人工判定。
- `templates/intake.md` 的人工问题录入模型不再合适，应替换为“JSON 报告接收与告警拆分”，并保留原始报告路径或哈希以便追溯。
- `templates/reproduction-report.md` 需要增加 Go 版本、模块版本、目标包/函数、触发输入、调用路径、利用前置条件和最小复现代码等安全复现字段。
- `templates/judgement-record.md` 的结论类型应改为真阳性、误报、待确认、重复项或不适用，并记录可达性、可控性、实际影响和证据强度。
- 通用示例必须替换成一条来自 JSON 告警的 Go 漏洞案例；准确字段映射需要真实样例。

## 2026-08-05：两套源工作流

- 复现源文件：`/Users/oliverwu/Desktop/workflow/复现workflow.md`，标题为“Go 项目漏洞 Docker 复现工作流”。
- 判断源文件已定位：`/Users/oliverwu/Documents/New project/go项目BUG-issue发布/AGENTS.md`。
- 复现工作流已包含可复用的四阶段结构：Docker 环境搭建、定位 JSON 漏洞报告、手动复现高危告警、生成 Markdown 报告。
- 复现侧强调不能只相信扫描报告，必须读取真实源码并检查缓解层；证据优先级以 Docker 内行为级 `go test` 为主，复杂情形允许代码路径分析。
- 复现产物当前已经接近用户的新目标：单个 Markdown 报告，可选同目录 `.log`；需要进一步把复现事实和判断结论拆成清晰的证据链。
- 用户指定判断阶段的三个核心输入：项目全局 Markdown、漏洞代码片段、Docker 复现运行时截取的 `.log` 文件。

## 2026-08-05：真实 JSON 样例结构

- 样例文件：`report(1).json`，大小约 180 KB；JSON 语法有效。
- 顶层字段：`scan_info`、`project_domains`、`summary`、`findings`、`function_scores`。
- `scan_info` 包含 `project_id`、`target`、`timestamp`、`model`、函数数量、已分析函数数量、模板命中数和耗时。
- 样例对应项目 `multica`，报告共有 101 条告警：8 high、66 medium、27 low。
- 每条 `finding` 的稳定字段为：`template_id`、`pattern_name`、`confidence`、`severity`、`missing_step_category`、`reasoning`、`evidence`、`function`。
- `cwe_alignment` 在 83/101 条告警中存在，因此工作流必须允许 CWE 缺失，不能把它设为必填字段。
- `function` 当前是类似 `server/internal/daemon/daemon.go:runTask` 的源码文件与函数定位，不包含精确行号。
- `reasoning` 和 `evidence` 是检测器生成的待验证主张；它们用于指导复现，但不能替代项目源码、漏洞代码片段和 Docker 行为日志。
- 一个 JSON 对应一个项目并包含多条告警，因此处理单元应分两级：项目级上下文只整理一次，告警级复现与判断逐条执行。

## 判断工作流提炼

- `AGENTS.md` 的可保留核心是证据门槛、安全边界、影响闭环和不夸大原则；GitHub Issue 草稿与 Obsidian 发布记录不属于新的 `report.md` 产物，应从主流程移除。
- 允许的验证范围是本地 checkout、Docker、单元测试、集成测试、沙箱或用户提供的日志；不得把本地代码访问授权扩展为测试第三方线上系统。
- 只有运行证据证明行为时才能写“已复现”；只有源码可能性时应写“潜在/证据不足”；真实路径被缓解代码阻断时应写“已缓解/误报”。
- 源码检查通常不足以形成确认结论。每个最终 claim 都必须由运行日志或等价行为证据支撑；只验证了一部分时必须缩小结论范围。
- 外部前提、不可达调用方、非默认配置、mock-only 路径或未证明的受影响路径，都应降低结论等级并明确列为证据缺口。
- JSON 中的 `project_domains` 和 `function_scores` 可辅助安排阅读优先级，但属于扫描器启发式元数据，不能进入最终证据链的“已证实事实”部分。
- 样例 8 条 high 告警中多条依赖“输入是否外部可控”“调用方是否限制路径”“错误后沙箱是否确实失效”等前提，正好说明判断报告必须单独记录可达性、可控性、缓解层和运行结果。

## 证据包设计决策

- 目录采用 `cases/<project>/<scan-id>/`，原始 `report.json`、项目级 `project.md` 和最终 `report.md` 放在案例根目录；每条告警的 `code.txt`、`runtime.log` 放在 `findings/<finding-id>/`。
- JSON 没有稳定告警 ID；展示 ID 使用数组顺序生成 `F001`、`F002`，同时保存 `template_id + pattern_name + function` 身份元组，避免只靠序号追踪。
- `project.md` 汇总一次仓库、commit、module、Go、Docker、扫描覆盖率、外部依赖和信任边界，避免每条告警重复项目背景。
- `code.txt` 必须同时截取报告命中点、真实调用方/输入来源、危险操作、下游影响和缓解代码，不能只截取支持扫描器结论的一小段；纯文本扩展名让它和 Markdown 背景、运行日志快速区分。
- `runtime.log` 保留原始命令、时间、stdout/stderr、退出码、期望与实际标记；判断报告只引用日志，不改写原始日志。
- `report.md` 为项目级最终产物，先给告警汇总，再按 finding 逐条记录代码证据、运行证据、支持/反证、结论、影响和限制。
- 原判断仓库没有实际保存 `.log` 文件，只在概览中写“本地日志支持”；新流程要求日志作为一等证据文件进入案例目录。
- 原 `.gitignore` 使用 `*.log` 忽略所有日志；已保留该默认规则并增加 `!cases/**/runtime.log`，只允许案例证据日志进入版本控制。
