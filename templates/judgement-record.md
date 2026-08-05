# Go 漏洞复现与判断报告

> 保存为案例根目录的 `report.md`。本报告只汇总判断，不替代 `project.md`、`code.txt` 或 `runtime.log` 原始证据。

## 1. 报告信息

| 项 | 值 |
| --- | --- |
| 项目 |  |
| 仓库 |  |
| scan ID |  |
| JSON SHA-256 |  |
| project commit |  |
| Go 版本 |  |
| Docker 镜像 / 容器 |  |
| 判断日期 |  |
| 判断者 |  |
| 复核者 |  |
| 当前状态 | judging / needs-evidence / resolved |

## 2. 扫描概览与限制

| 项 | 值 |
| --- | --- |
| 工具告警总数 |  |
| high / medium / low |  |
| 已分析函数 / 总函数 |  |
| 本轮判断数量 |  |
| confirmed | 0 |
| conditional | 0 |
| false-positive | 0 |
| not-reproduced | 0 |
| insufficient-evidence | 0 |

- 工具模型和时间：
- 本轮选择规则：
- 扫描覆盖限制：
- 复现环境限制：

## 3. 判断汇总

| ID | 身份元组 | 工具严重度 | 人工结论 | 人工影响 | 证据等级 | 置信度 |
| --- | --- | --- | --- | --- | --- | --- |
| F001 | `template_id | pattern_name | function` | high | insufficient-evidence | 未证明 | E1 | 低 |

## 4. Finding F001

> 为每条选中告警复制本节，并同步替换 Finding ID、身份元组和三个证据路径。

### 4.1 扫描器主张

- `template_id`：
- `pattern_name`：
- `function`：
- 工具严重度 / 置信度：
- `missing_step_category`：
- `cwe_alignment`：扫描器未提供 / 列表
- `reasoning` 摘要：
- `evidence` 摘要：

本节内容是扫描器主张，不是已证实事实。

### 4.2 三类判断输入

| 证据 | 路径 | SHA-256 | 一致性 |
| --- | --- | --- | --- |
| 项目全局信息 | [`project.md`](project.md) |  | 通过 / 不通过 |
| 源码片段 | [`findings/F001/code.txt`](findings/F001/code.txt) |  | 通过 / 不通过 |
| Docker 日志 | [`findings/F001/runtime.log`](findings/F001/runtime.log) |  | 通过 / 不通过 |

### 4.3 代码证据判断

- 报告代码是否存在：是 / 否
- 真实入口与调用链：
- 输入来源：
- 输入可控性：已证明 / 受限 / 未证明
- 危险操作：
- 可观察影响：
- 鉴权、校验或缓解：
- 默认配置可达性：已证明 / 非默认 / 未证明
- 源码阶段结论：supports-hypothesis / contradicts-hypothesis / source-inconclusive

### 4.4 Docker 运行证据

- 实验是否有效：是 / 否
- 精确命令：
- 退出码：
- 预期观察：
- 实际观察：
- 关键日志行：
- 是否命中真实路径：
- 是否证明行为：
- 是否证明影响：

### 4.5 支持证据与反证

| 类型 | 证据 | 来源 |
| --- | --- | --- |
| 支持 |  | `code.txt` / `runtime.log` |
| 反证或缓解 |  | `code.txt` / `runtime.log` |

### 4.6 最终判断

- 结论：confirmed / conditional / false-positive / not-reproduced / insufficient-evidence
- 结论理由：
- 已证明影响：
- 未证明或不得声称的影响：
- 前置条件：
- 人工严重度：低 / 中 / 高 / 不适用 / 未判断
- 人工置信度：低 / 中 / 高
- 证据等级：E0 / E1 / E2 / E3 / E4
- 下一步最小补证实验：无 / 具体实验

## 5. 项目级结论

- 已确认问题：
- 条件性问题：
- 已证明误报：
- 未复现：
- 证据不足：
- 项目级共同缓解或限制：

## 6. 证据索引

- 原始报告：[`report.json`](report.json)
- JSON 接收记录：[`intake.md`](intake.md)
- 项目全局信息：[`project.md`](project.md)
- Finding F001 源码：[`findings/F001/code.txt`](findings/F001/code.txt)
- Finding F001 日志：[`findings/F001/runtime.log`](findings/F001/runtime.log)

## 7. 证据缺口

| Finding | 缺失证据 | 对当前结论的影响 | 负责人 |
| --- | --- | --- | --- |
| F001 |  |  |  |

## 8. 复核

- [ ] 没有把 JSON 推理写成已证实事实。
- [ ] Finding ID、身份元组和 commit 在三类证据中一致。
- [ ] 每个 confirmed/conditional 结论有有效 Docker 日志。
- [ ] 每个 false-positive 结论有正向反证，不只是未复现。
- [ ] 影响描述没有超过日志证明范围。
- [ ] 凭据、个人路径、私有源码和敏感细节已脱敏。

- 复核结论：通过 / 需补证 / 不通过
- 复核说明：
- 复核日期：
