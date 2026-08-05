# GitHub 协作规范

## 1. 协作目标

合作者围绕同一份 JSON 和同一组证据文件工作，任何人都能回答：告警来自哪里、验证了什么、日志证明了什么、为什么得到当前结论。

本仓库生成内部 `report.md`，不自动生成或发布公开 GitHub Issue，也不代表已经完成漏洞披露决策。

## 2. 角色

| 角色 | 责任 |
| --- | --- |
| 接收者 | 校验 `report.json`、记录 SHA-256、生成 finding ID。 |
| 项目整理者 | 固定源码版本并完成 `project.md`。 |
| 复现者 | 生成 `code.txt`、执行 Docker 实验、保存 `runtime.log`。 |
| 判断者 | 使用三类证据生成 `report.md`。 |
| 复核者 | 检查证据一致性、结论范围和敏感信息。 |

同一个人可以承担多个角色，但 `confirmed`、`conditional` 和 `false-positive` 结论应由另一名合作者复核。

## 3. 分支与 Pull Request

建议每个扫描案例使用一个分支：

```text
case/<project>-<scan-id>
```

Pull Request 只处理一个项目和一个 scan ID。PR 描述至少写明：

- JSON SHA-256 和 scan ID。
- 目标仓库与 commit。
- 本轮选中的 finding ID。
- 新增的 `project.md`、`code.txt`、`runtime.log` 和 `report.md`。
- 各判断结果数量。
- 仍缺少的证据和未完成实验。

## 4. 提交粒度

推荐按证据阶段提交：

```text
docs: add <project> scan intake and context
test: add <project> Docker reproduction evidence
docs: add <project> vulnerability judgements
```

不要修改或格式化原始 `report.json` 和 `runtime.log`。需要脱敏时保留受限原件，提交明确标注为脱敏副本的文件，并在 `report.md` 记录原件索引。

## 5. Review Checklist

- [ ] `summary.total_findings` 与 `findings` 数组长度一致。
- [ ] JSON SHA-256、scan ID 和 finding ID 已记录。
- [ ] `project.md`、`code.txt`、`runtime.log` 使用同一 commit。
- [ ] `code.txt` 含真实调用方、输入、缓解层和危险操作，不是孤立 sink。
- [ ] `runtime.log` 含精确命令、原始输出、退出码和预期/实际标记。
- [ ] `confirmed` 和 `conditional` 有有效运行证据。
- [ ] `false-positive` 有正向反证，不只是未复现。
- [ ] 结论没有超过实际日志证明范围。
- [ ] 扫描覆盖限制已写入 `report.md`。
- [ ] 没有提交凭据、个人目录、私有源码或容易被直接滥用的敏感细节。

## 6. 冲突处理

当源码和日志结论冲突时：

1. 检查 commit、构建标签、平台和配置是否一致。
2. 检查日志是否真正命中 `code.txt` 中的路径。
3. 检查测试是否只调用了 helper 或 mock-only 路径。
4. 在问题闭环前使用 `insufficient-evidence`，保留双方证据。

不要为了让结论一致而删除反证或覆盖原始日志。

## 7. 敏感材料

以下内容默认不提交 GitHub，即使仓库是 private：

- 访问令牌、Cookie、私钥、数据库密码和云凭据。
- 未经批准共享的第三方私有代码。
- 生产数据、个人数据和内部主机地址。
- 可直接用于影响第三方线上系统的完整操作细节。

允许提交脱敏代码片段、合成输入、受控 Docker 日志和证据哈希。无法脱敏时，在 `report.md` 写受限存储索引，由有权限的复核者查看原件。

## 8. 邀请合作者

在 GitHub 私人仓库中打开：

```text
Settings -> Collaborators and teams -> Add people
```

授予完成任务所需的最低权限。工作流规则的修改通过 Pull Request 复核，不直接覆盖 `main`。
