# Go 漏洞复现与判断 Workflow

## 1. 目标与边界

本工作流用于处理 Go 漏洞检测工具生成的项目级 JSON 报告。它把扫描器告警转化为可复核的本地证据，并输出项目级 `report.md`。

工作流只允许在以下环境验证：

- 用户有合法访问权的本地源码 checkout。
- Docker、单元测试、集成测试或隔离沙箱。
- 用户已经提供的日志和证据。


## 2. 输入与输出

### 2.1 原始输入

- 漏洞检测工具生成的 `report.json`。
- 与报告目标一致的 Go 项目源码。
- 可在本地或 Docker 中运行的构建、测试或服务环境。

### 2.2 判断输入

最终判断只使用以下三类人工核验材料：

1. `project.md`：项目全局信息、版本、构建方式、扫描范围和信任边界。
2. `code.txt`：单条告警对应的真实代码片段、调用链、输入来源、危险操作和缓解层。
3. `runtime.log`：Docker 受控复现的原始命令、stdout/stderr、退出码和观察结果。

`report.json` 中的 `reasoning`、`evidence`、`project_domains` 和 `function_scores` 只用于生成候选和安排优先级，不能直接作为真阳性证据。

### 2.3 最终输出

- 项目级 `report.md`，汇总所有被选中告警的判断。
- 每条告警的 `code.txt` 和 `runtime.log` 证据索引。
- 必要时记录 `confirmed`、`conditional`、`false-positive`、`not-reproduced` 或 `insufficient-evidence`。

## 3. 案例目录

```text
cases/<project>/<scan-id>/
  report.json
  intake.md
  project.md
  findings/
    F001/
      code.txt
      runtime.log
    F002/
      code.txt
      runtime.log
  report.md
```

源 JSON 没有稳定的 finding ID。案例中按 `findings` 数组顺序生成 `F001`、`F002`，同时在所有证据文件中记录：

```text
template_id + pattern_name + function
```

序号用于阅读，身份元组用于避免告警错配。

## 4. 总体流程

```text
JSON 接收与校验
  -> 项目全局信息整理
  -> 告警筛选与编号
  -> 真实源码和调用链核验
  -> Docker 复现设计与执行
  -> 三文件完整性检查
  -> 逐条判断
  -> 项目级 report.md
  -> 合作者复核与归档
```

## 5. 阶段一：JSON 接收与校验

### 5.1 保留原始报告

将原始文件复制到案例目录并保持只读语义。不要直接修改扫描器输出。记录文件 SHA-256：

```bash
shasum -a 256 report.json
```

### 5.2 校验结构

先确认 JSON 语法有效：

```bash
jq empty report.json
```

最低必需结构：

```text
scan_info: object
summary: object
findings: array
project_domains: array
function_scores: array
```

检查汇总数量是否和数组长度一致：

```bash
jq -e '.summary.total_findings == (.findings | length)' report.json
```

不一致时停止分发告警，在 `intake.md` 记录异常，并以原始数组为待调查数据，不自行修正报告。

### 5.3 记录扫描范围

从 `scan_info` 记录：

- `project_id`、`target`、`timestamp`、`model`。
- `total_functions` 与 `analyzed_functions`。
- `total_templates_matched` 与 `total_duration`。

必须把 `analyzed_functions / total_functions` 写入最终报告。扫描范围不足意味着“没有告警”不能推导为“项目没有漏洞”。

### 5.4 选择告警

默认先处理 `severity == "high"`，也可以由项目负责人指定其他严重度。严重度和置信度只决定处理顺序，不决定最终结论。

每条选中告警在 `intake.md` 中记录：

- Finding ID。
- `template_id`。
- `pattern_name`。
- `severity` 与 `confidence`。
- `missing_step_category`。
- 可选的 `cwe_alignment`；字段缺失或为 `null` 时写“扫描器未提供”。
- `function`。
- 扫描器主张摘要。

## 6. 阶段二：生成 `project.md`

`project.md` 是同一项目全部告警共享的全局上下文，只整理一次。

### 6.1 源码身份

必须记录：

- 仓库 URL 或内部仓库标识。
- 当前 commit 完整哈希与分支或 tag。
- Go module path 和 `go.mod` 声明的 Go 版本。
- 报告 `scan_info.target` 与实际 checkout 路径的对应关系。

如果报告扫描版本和复现版本不同，先记录差异，再确认告警代码是否仍存在。不能用新版本运行结果替代旧版本结论而不作说明。

### 6.2 运行模型

按项目选择：

| 项目类型 | Docker 方式 |
| --- | --- |
| CLI 或可独立运行服务 | 构建二进制并运行真实入口 |
| 库、框架或宿主依赖强 | Go dev 容器中执行 `go build` / `go test` |
| Go + 数据库等多服务 | Docker Compose 启动最小依赖集合 |

记录基础镜像、容器名、架构、环境变量名称、依赖服务和网络限制。凭据只记录“已配置/未配置”，不得写入真实值。

### 6.3 项目级信任边界

至少回答：

- 哪些输入来自远程用户、配置、仓库内容、环境变量或受信任服务端。
- 哪些调用只在管理员、本地 CLI、测试或 mock 路径出现。
- 默认配置是否能到达被报告函数。
- 是否存在统一鉴权、输入校验、路径约束、资源上限或沙箱层。

这些信息决定后续告警的可达性和可控性判断。

## 7. 阶段三：为每条告警生成 `code.txt`

### 7.1 把扫描器输出写成待验证主张

先原样记录 `pattern_name`、`reasoning`、`evidence` 和 `function`，并明确标记为“扫描器主张”。不要先把它改写成事实。

### 7.2 定位真实代码

在 `project.md` 记录的 commit 上完成以下检查：

1. 找到 `function` 指向的文件和函数。
2. 确认代码是否与 JSON 的 `evidence` 一致。
3. 向上追踪真实调用方和输入来源。
4. 向下追踪危险操作和可观察影响。
5. 搜索鉴权、校验、规范化、边界检查、资源限制、错误处理和标准库保护。
6. 检查默认配置、构建标签和平台差异。

### 7.3 代码片段要求

`code.txt` 不能只截取支持扫描器结论的一行。至少包括：

- 输入进入函数的位置。
- 关键转换或验证。
- 被报告的危险操作。
- 实际产生影响或返回错误的位置。
- 可能阻断问题的调用方或缓解代码。

每个片段必须写仓库相对路径、起止行号和 commit。代码过长时分成“输入”“校验/缓解”“危险操作”三个片段。

`code.txt` 使用纯文本固定头部，不写 Markdown 标题：

```text
finding_id: F001
identity_tuple: tpl_000 | example_pattern | internal/example.go:Run
project_commit: 0123456789abcdef
source_file: internal/example.go
line_range: 10-48

===== INPUT AND CALLER =====
<原始代码>

===== VALIDATION OR MITIGATION =====
<原始代码；没有时明确写 NONE FOUND>

===== SINK AND EFFECT =====
<原始代码>
```

只允许加入定位标签和必要的行号；代码正文保持与目标 commit 一致。分析文字放入最终 `report.md`，避免和原始代码证据混在一起。

### 7.4 源码阶段结论

源码核验只能给出：

| 结果 | 含义 |
| --- | --- |
| `supports-hypothesis` | 真实路径支持扫描器主张，仍需运行验证。 |
| `contradicts-hypothesis` | 真实代码或缓解层直接反驳主张，仍建议用负向测试确认。 |
| `source-inconclusive` | 无法证明可达性、可控性或实际影响。 |

源码阶段不直接写 `confirmed`。

## 8. 阶段四：Docker 复现并生成 `runtime.log`

### 8.1 设计受控实验

复现前写清楚：

- 要验证的单一 claim。
- 前置条件和配置。
- 输入如何进入真实代码路径。
- 预期安全行为。
- 若告警成立，应出现的最小可观察行为。
- 若缓解有效，应出现的拒绝、错误或无副作用行为。

一个实验只验证一个主要 claim。组合问题必须拆分，除非它们共享同一根因且同一日志可以完整证明。

### 8.2 选择复现策略

优先级如下：

1. 调用真实公开入口或真实服务请求。
2. 在目标包内编写 `go test`，调用真实函数和真实依赖边界。
3. 使用 `httptest`、临时目录、测试数据库或伪造本地二进制替代外部系统。
4. 只有无法隔离的重型路径才采用代码路径分析，并将结论保持为 `insufficient-evidence`，除非已有等价运行证据。

测试不得访问第三方线上系统，不得使用真实生产凭据，不得造成不可逆数据修改。

### 8.3 日志必须保留的内容

`runtime.log` 是原始证据文件，至少包含：

```text
finding_id
identity_tuple
project_commit
container_image_or_id
started_at
exact_command
expected_observation
stdout_and_stderr
exit_code
observed_marker
cleanup_result
finished_at
```

完整 stdout/stderr 应保留。可以在 `report.md` 中引用关键几行，但不得用手工摘要替代原始日志。

### 8.4 复现结果

| 结果 | 说明 |
| --- | --- |
| 行为成立 | 日志证明输入到达真实路径并产生被报告行为。 |
| 行为被阻断 | 日志证明校验、权限、标准库或缓解层阻断行为。 |
| 未观察到 | 实验没有观察到行为，但原因未闭环。 |
| 实验无效 | 构建失败、路径未到达、环境错误或日志不完整。 |

“未观察到”不自动等于误报；只有证明主张错误或被稳定缓解时才能判 `false-positive`。

## 9. 阶段五：三文件完整性检查

进入判断前，逐条检查：

- `project.md`、`code.txt`、`runtime.log` 都存在。
- 三个文件使用同一 project、scan ID、finding ID 和 commit。
- `code.txt` 的身份元组与 `report.json` 一致。
- 日志命令确实运行了 `code.txt` 中的真实路径或等价行为。
- 日志含退出码、预期结果和实际结果。
- 代码片段包含支持证据和可能的反证/缓解层。

任一关键检查失败时，结论只能是 `insufficient-evidence` 或退回补充材料。

## 10. 阶段六：逐条判断

### 10.1 判断维度

每条告警都回答：

| 维度 | 问题 |
| --- | --- |
| 代码存在性 | 报告描述的代码在目标 commit 上是否存在？ |
| 可达性 | 默认或已声明配置下，真实入口能否到达该函数？ |
| 可控性 | 关键输入能否由攻击面或非受信任主体控制？ |
| 缓解层 | 调用方、被调方、标准库或运行环境是否阻断影响？ |
| 运行行为 | Docker 日志是否证明被报告行为？ |
| 实际影响 | 是否观察到安全边界突破、敏感操作、崩溃或资源影响？ |
| 适用范围 | 影响是否只在非默认配置、特殊平台或特定版本成立？ |

### 10.2 判断结果

| 结论 | 必要条件 |
| --- | --- |
| `confirmed` | 真实代码路径、可达性/可控性和 Docker 行为证据形成闭环；结论只覆盖已证明影响。 |
| `conditional` | 行为已复现，但依赖明确的非默认配置、权限、平台或外部前提；报告必须列出条件。 |
| `false-positive` | 真实源码或运行证据证明扫描器主张错误，或稳定缓解层阻断了被报告影响。 |
| `not-reproduced` | 实验有效但未观察到行为，且尚不能证明主张错误或稳定缓解。 |
| `insufficient-evidence` | 缺少三文件之一、调用路径未闭环、日志无效、版本不一致或影响未证明。 |

严重度需要重新评估。扫描器 `severity` 和 `confidence` 原样保留为“工具输出”，人工判断的影响和置信度单独填写。

## 11. 阶段七：生成项目级 `report.md`

使用 `templates/judgement-record.md`，至少包含：

1. 项目、scan ID、JSON SHA-256、commit、Go 和 Docker 环境。
2. 扫描覆盖率和工具告警统计。
3. 被选中告警的判断汇总表。
4. 每条告警的扫描器主张、代码证据、运行证据、反证、结论、影响和限制。
5. `project.md`、各 `code.txt`、各 `runtime.log` 的相对链接。
6. 未完成实验和证据缺口。
7. 判断者与复核者签字信息。

`report.md` 不自动生成公开 Issue 文本，也不把敏感验证细节复制到公开渠道。

## 12. 阶段八：复核与归档

复核者重点检查：

- 是否把扫描器推理误写成已证实事实。
- 每个结论是否同时对应正确的代码和日志。
- 标题和影响描述是否超过日志证明范围。
- 误报结论是否有正向反证，而不只是“我没有复现”。
- 条件性问题是否完整列出前置条件。
- 敏感路径、凭据、私有源码和个人信息是否已脱敏。

复核通过后，将案例状态设为 `resolved`。发现新证据时新增修订记录，不直接覆盖旧结论。

## 13. 停止条件

出现以下情况时停止形成强结论：

- JSON 结构损坏或告警数量不一致。
- 找不到报告对应的源码版本。
- 只能运行 mock-only/helper 路径，无法证明真实调用方。
- Docker 日志缺少命令、退出码或实际输出。
- 测试依赖第三方线上系统或真实生产凭据。
- 只证明了组合 claim 的一部分。

停止后保留已有证据，并把结果写为 `insufficient-evidence`，同时列出下一项最小补证实验。
