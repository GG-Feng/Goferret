# .claude/CLAUDE.md — 项目操作规则

> 本文件由 Claude Code 在每次会话启动时自动读取。
> 根 `CLAUDE.md` 描述"项目是什么 / 流水线怎么跑"，本文件约束"**怎么改**"。

## 1. 代码变更规则

### 默认禁止
- **直接修改**以下文件必须先有变更说明：
  - `*.py`（所有 Python 脚本）
  - `ast_analyzer/main.go`、`ast_analyzer/go.mod`
  - `*.md` LLM prompt 文件（`classification.md`、`behavior_chain.md`、`detect_domain.md`、`detect_analyze.md`、`gen_testcase.md`）
  - `.env`（含任何 API key 修改）
  - `CLAUDE.md`、本文件 `.claude/CLAUDE.md`

### 例外（不需要变更说明）
- 新增数据/产物目录下的文件：`vuln/`、`repos/`、`vuln_data/`、`prepared_inputs/`、`classifications/`、`enriched_inputs/`、`behavior_chains/`、`projects/`、`reports/`——这些是脚本再生成的产物
- `verify_samples/` 下的真值样本——是输入数据
- `.gitignore`、`requirements.txt` 这类纯配置/依赖清单

### 变更说明必须包含
1. 改了什么（diff 摘要或具体行号）
2. 为什么改
3. 影响哪些 stage / 哪些产物
4. 如修改了 prompt：影响哪个 stage 的 LLM 行为 + 是否需要重跑已有产物

变更说明放在 [CHANGELOG.md](../CHANGELOG.md) 新条目，或在对话/PR 里写明。

## 2. 数据完整性

- 删除空目录前必须确认无残留数据
- `enriched_inputs/`、`behavior_chains/`、`vuln_db.json` 这类已生成产物**默认不改**——若发现数据问题，先确认是脚本 bug 还是输入问题，再决定重跑哪个 stage
- `detect_vulns.py` 产生的 `projects/<timestamp>/` 是单次扫描产物，可清

## 3. 报告与文档

- 验证/审计报告统一放 [../reports/](../reports/) 下，目录名格式：`<主题>_validation` / `<主题>_audit` / `<主题>_<日期>`
- 内部结构参考 `reports/vuln_detect_validation/`
- 新增报告必须更新 [../reports/README.md](../reports/README.md) 索引

## 4. 环境与依赖

- 不要把 API key 直接写进任何 Python 脚本或 commit——统一放 [.env](../.env)
- 不要把 `.env`、`vuln_db.json`、`enriched_inputs/`、`behavior_chains/`、`repos/`、`vuln_data/` 这类大文件/敏感文件 commit 进去（参见 [.gitignore](../.gitignore)）
- Python 依赖变更同步更新 [../requirements.txt](../requirements.txt)
- Go 工具链变更同步更新 [../ast_analyzer/go.mod](../ast_analyzer/go.mod)

## 5. 跑流水线前自检

启动任何 stage 之前先确认：
1. Python 依赖装好（`pip install -r requirements.txt`）
2. `.env` 配好 LLM key（`ZHIPUAI_API_KEY` / `ARK_API_KEY` 至少一个）
3. Go 工具链就位（`go version` 应 ≥ [ast_analyzer/go.mod](../ast_analyzer/go.mod) 中声明的版本）
4. 上游 stage 的输入目录有数据（避免重跑已完成的 stage）
