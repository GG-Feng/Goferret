# Docker 复现记录

> 本模板用于设计并执行一条 finding 的受控实验。执行结束后，把原始输出保存为同目录 `runtime.log`；最终判断不把本文件当作运行证据。

## 1. 实验身份

| 项 | 值 |
| --- | --- |
| Finding ID | F001 |
| 身份元组 | `template_id | pattern_name | function` |
| scan ID |  |
| project commit |  |
| 复现者 |  |
| 日期 |  |

## 2. 单一验证目标

- 要验证的 claim：
- 预期安全行为：
- 若告警成立，应观察到：
- 若缓解有效，应观察到：

## 3. 前置条件

- Docker 镜像或容器：
- 构建/启动状态：
- 配置条件：默认 / 非默认，具体为：
- 外部依赖：
- 测试数据：合成 / 脱敏，说明：
- 是否访问第三方线上系统：否
- 是否使用真实生产凭据：否

## 4. 真实代码路径

- 入口：
- 调用链：
- 关键输入：
- 目标函数：
- 可观察副作用或返回：
- 与 `code.txt` 的对应位置：

## 5. 执行命令

```bash
# 写入将在容器或受控本地环境执行的精确命令。
```

## 6. `runtime.log` 采集格式

实际 `.log` 文件至少包含：

```text
finding_id=F001
scan_id=20260000_000000
identity_tuple=tpl_000 | example_pattern | internal/example.go:Run
project_commit=0123456789abcdef0123456789abcdef01234567
container_image_or_id=example-image-id
started_at=2026-01-01T00:00:00+08:00
exact_command=go test ./internal/example -run TestFindingF001 -v
expected_observation=request rejected and no file created

===== STDOUT AND STDERR =====
原始输出从这里开始，不能只写摘要。

===== RESULT METADATA =====
exit_code=0
observed_marker=validation rejected input
cleanup_result=temporary files removed
finished_at=2026-01-01T00:00:05+08:00
```

采集后记录 `runtime.log` 的 SHA-256：

```bash
shasum -a 256 runtime.log
```

## 7. 实验有效性检查

- [ ] 命中了真实入口或等价真实代码路径。
- [ ] 使用了 `project.md` 和 `code.txt` 对应的同一 commit。
- [ ] 日志包含完整 stdout/stderr 和退出码。
- [ ] 预期结果与实际结果都能从日志确认。
- [ ] 没有访问第三方线上系统。
- [ ] 临时文件、容器状态和测试数据已清理。

任一关键项未通过时，将运行证据标记为“实验无效”，不要用它支持确认或误报结论。
