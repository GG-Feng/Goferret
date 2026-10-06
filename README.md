# Goferret

Goferret 是面向 Go 项目的漏洞检测与复现验证工具，包含 `detector/` 检测器和 `workflow-v2/` 复现工作流。

当前使用 **workflow-v2**：检测器产出候选告警，复现工作流提取证据、设计并冻结双臂测试，在 Docker 中重放，然后按规则判定并生成报告。

```text
Go 项目 → detector/ → report.json
                           ↓
workflow-v2/: select → evidence → design → run → judge → report
```

## 入口

- [检测器安装与扫描](detector/README.md)
- [workflow-v2 配置与使用](workflow-v2/README.md)
- [工作流设计说明与限制](workflow-v2/设计说明.md)
- [配置示例](workflow-v2/config.example.json)

## 使用顺序

1. 按检测器说明安装依赖、构建 AST 分析器并配置 `detector/.env`。
2. 扫描已获授权的项目，保存原始 `report.json` 和对应版本源码。
3. 按 workflow-v2 说明填写配置，准备 Docker 镜像和离线模块缓存。
4. 执行六步流程，用 `check-stable` 重放冻结测试并比较结果。
5. 人工核对测试前提、信任边界和实测值后，再使用生成的报告。

检测输出是候选证据。workflow-v2 的结论为“已复现 / 不成立 / 未能复现”，适用范围受测试设计和运行前提约束。

旧版 `docs/`、`templates/`、`examples/` 已由 workflow-v2 替代，可通过 Git 历史恢复。`detector/reports/` 中的既有报告是历史记录，不代表 workflow-v2 的本次验证结果。
