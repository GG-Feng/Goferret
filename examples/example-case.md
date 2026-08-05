# 脱敏示例：路径告警被调用方校验阻断

> 本示例为虚构代码和日志，只展示文件如何配合，不对应真实项目或未公开漏洞。

## 1. JSON 候选

扫描器输出一条 high 告警：

| 字段 | 值 |
| --- | --- |
| Finding ID | F001 |
| `template_id` | `tpl_060` |
| `pattern_name` | `workspace_path_traversal` |
| `function` | `internal/workspace/path.go:BuildDir` |
| `missing_step_category` | `path_validation` |
| 扫描器主张 | `filepath.Join` 使用了外部 workspace ID，可能逃逸根目录。 |

这个表只建立待验证主张。

## 2. `project.md`

项目全局信息记录：

- 仓库：`example/demo-go-service`
- commit：`1111111111111111111111111111111111111111`
- module：`example.com/demo-go-service`
- Go：`1.26`
- Docker：`golang:1.26` dev 容器
- 真实入口：HTTP handler 先解析 workspace ID，再调用 `BuildDir`。
- 信任边界：HTTP 参数不受信任；进入 workspace service 前必须通过格式校验。

## 3. `code.txt`

```text
finding_id: F001
scan_id: demo-scan-001
identity_tuple: tpl_060 | workspace_path_traversal | internal/workspace/path.go:BuildDir
project_commit: 1111111111111111111111111111111111111111
source_file: internal/workspace/path.go
line_range: 12-48

===== SCANNER CLAIM LOCATION =====
42  func BuildDir(root, workspaceID string) string {
43      return filepath.Join(root, workspaceID)
44  }

===== INPUT AND REAL CALLER =====
12  func handleWorkspace(w http.ResponseWriter, r *http.Request) {
13      workspaceID := r.PathValue("workspace")
14      if !validWorkspaceID(workspaceID) {
15          http.Error(w, "invalid workspace", http.StatusBadRequest)
16          return
17      }
18      dir := workspace.BuildDir(workspaceRoot, workspaceID)

===== VALIDATION OR MITIGATION =====
30  func validWorkspaceID(value string) bool {
31      return workspaceIDPattern.MatchString(value)
32  }

===== SINK AND OBSERVABLE EFFECT =====
18      dir := workspace.BuildDir(workspaceRoot, workspaceID)
19      serveWorkspace(w, r, dir)
```

代码证据显示扫描器命中了真实 sink，但真实调用方在进入 sink 前执行白名单校验。源码阶段结论是 `contradicts-hypothesis`，仍需负向运行测试。

## 4. `runtime.log`

```text
finding_id=F001
scan_id=demo-scan-001
identity_tuple=tpl_060 | workspace_path_traversal | internal/workspace/path.go:BuildDir
project_commit=1111111111111111111111111111111111111111
container_image_or_id=golang:1.26
started_at=2026-08-05T15:00:00+08:00
exact_command=go test ./internal/workspace -run TestHandlerRejectsInvalidWorkspaceID -v
expected_observation=request rejected before BuildDir and no outside path accessed

===== STDOUT AND STDERR =====
=== RUN   TestHandlerRejectsInvalidWorkspaceID
    handler_test.go:51: status=400
    handler_test.go:52: build_dir_calls=0
    handler_test.go:53: outside_path_accessed=false
--- PASS: TestHandlerRejectsInvalidWorkspaceID (0.00s)
PASS
ok      example.com/demo-go-service/internal/workspace  0.004s

===== RESULT METADATA =====
exit_code=0
observed_marker=status=400; build_dir_calls=0; outside_path_accessed=false
cleanup_result=temporary directory removed
finished_at=2026-08-05T15:00:01+08:00
```

日志证明真实 HTTP 入口拒绝无效 ID，并且没有调用被报告函数。

## 5. `report.md` 判断

| 维度 | 结果 |
| --- | --- |
| 代码存在 | 是 |
| 真实入口 | 已确认 |
| 输入可控 | HTTP 参数可控，但先经过校验 |
| 缓解层 | 调用方白名单校验 |
| Docker 行为 | 无效 ID 返回 400，sink 调用次数为 0 |
| 实际影响 | 未发生 |
| 证据等级 | E3 |

最终结论：`false-positive`。

理由不是“没有复现”，而是 `code.txt` 和 `runtime.log` 共同证明真实调用方稳定阻断了扫描器描述的路径。结论仅覆盖该真实 HTTP 入口；如果项目还有其他未校验调用方，需要作为新的 finding 单独核验。
