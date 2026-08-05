# JSON 报告接收记录

## 1. 文件身份

| 项 | 值 |
| --- | --- |
| 案例目录 | `cases/project/scan-id/` |
| 原始文件名 | `report.json` |
| SHA-256 |  |
| 文件大小 |  |
| 接收日期 |  |
| 接收人 |  |
| JSON 语法校验 | 通过 / 不通过 |
| 汇总数量校验 | 通过 / 不通过 |

## 2. `scan_info`

| 字段 | 值 |
| --- | --- |
| `project_id` |  |
| `target` |  |
| `timestamp` |  |
| `model` |  |
| `total_functions` |  |
| `analyzed_functions` |  |
| 扫描覆盖提示 | `analyzed_functions / total_functions` |
| `total_templates_matched` |  |
| `total_duration` |  |

## 3. 告警统计

| 项 | 值 |
| --- | --- |
| `summary.total_findings` |  |
| `findings` 数组长度 |  |
| high |  |
| medium |  |
| low |  |

## 4. 本轮选择规则

- 处理范围：high / 指定类别 / 指定 finding
- 选择原因：
- 暂不处理的范围：
- 已知扫描限制：

## 5. 选中告警

> Finding ID 按 JSON 数组顺序生成。身份元组必须完整记录。

| ID | 数组下标 | `template_id` | `pattern_name` | `function` | 工具严重度 | 工具置信度 | 状态 |
| --- | ---: | --- | --- | --- | --- | ---: | --- |
| F001 | 0 |  |  |  |  |  | selected |

## 6. 接收异常

- 缺失字段：
- 数量不一致：
- 无法解析内容：
- 路径或版本疑点：
- 处理决定：继续 / 停止并补充报告
