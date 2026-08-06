# reports/

集中存放本项目的验证/审计报告。每份报告一个子目录，按主题命名。

| 报告 | 状态 | 说明 |
|---|---|---|
| [vuln_detect_validation/](vuln_detect_validation/) | 完成（2026-06-15） | [detect_vulns.py](../../detect_vulns.py) 在 4 个 verify_samples 上的端到端验证 |

## 新增报告的约定

- 目录名格式：`<主题>_validation` / `<主题>_audit` / `<主题>_<日期>`，全小写下划线分隔
- 内部结构参考 `vuln_detect_validation/`：README.md 主报告、SUMMARY.md 速查、`reports/` 数据、`logs/` 日志、`scripts/` 驱动
- 路径使用相对引用（`../../xxx`）指回项目根的文件
