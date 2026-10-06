# Goferret 检测器

面向 Go 项目的研究型漏洞检测与验证流水线。项目把本地 AST/污点分析、行为链知识库、LLM 语义事实提取、确定性判定、CVSS v3.1 与证据加权置信度组合为一条可审计的检测流程。

> 当前版本属于研究原型。扫描结果是候选证据，不能代替源码复核、受控复现或正式安全审计。只应扫描你拥有或已获授权的目标。

## 核心能力

- 扫描本地 Go 项目，或按 Git URL/分支/标签拉取后扫描。
- 使用 Go AST 分析输入源、危险汇、净化操作、跨函数参数传播和授权一致性。
- 让 LLM 只提取带行号的语义事实，由本地规则决定是否形成 finding。
- 本地确定性计算 CVSS v3.1 和证据加权置信度。
- 生成结构化 `report.json`，并可进一步生成单元测试与 PoC 验证脚本。
- 提供从 Go 漏洞数据抓取、补丁解析、行为链提取到知识库构建的完整数据流水线。

完整检测阶段与设计约束见 [DETECTION_PIPELINE.md](DETECTION_PIPELINE.md) 和 [docs/DESIGN_v3.md](docs/DESIGN_v3.md)。

## 运行环境

- Python 3.9 或更高版本
- Go 1.23 或更高版本
- Git
- 一个兼容项目配置的 LLM API

## 快速开始

### 1. 安装依赖

```bash
git clone https://github.com/GG-Feng/Goferret.git
cd Goferret/detector

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

构建 Go AST 分析器：

```bash
cd ast_analyzer
go build -o ast_analyzer .
cd ..
```

### 2. 配置 LLM

```bash
cp .env.example .env
```

编辑 `.env`，选择一个 `LLM_PROVIDER`，并只填写对应供应商的 API Key、Base URL 和模型名。`.env` 已被 Git 忽略，不要把真实密钥写入源码、提交历史或 issue。

### 3. 构建基础知识库

仓库包含 13 条通用行为链，但不提交本地生成的完整漏洞数据库。可以先用通用行为链构建一个基础 `vuln_db.json`：

```bash
python3 build_vuln_db.py \
  --input-dir behavior_chains_generic \
  --output vuln_db.json
```

如需完整研究知识库，请先按数据流水线生成 `behavior_chains/`，再以它作为输入重新构建数据库。`behavior_chains/` 与 `vuln_db.json` 都是本地生成物，默认不会上传。

### 4. 扫描项目

扫描本地目录：

```bash
python3 detect_vulns.py \
  --target /path/to/go-project \
  --workers 4 \
  --flow-gate
```

扫描远程仓库的指定版本：

```bash
python3 detect_vulns.py \
  --git-url https://github.com/owner/repository \
  --git-ref v1.0.0 \
  --workers 4 \
  --flow-gate
```

实验用的无知识库模式：

```bash
python3 detect_vulns.py \
  --target /path/to/go-project \
  --no-kb \
  --workers 4
```

默认结果写入 `projects/<timestamp>/report.json`。LLM 调用会产生费用；首次运行建议限制目标规模，并检查 `report.json` 中的 `scan_info.llm_usage`。

## 验证

无需网络和 API Key 的本地自测：

```bash
python3 cvss.py --selftest
python3 confidence.py --selftest
python3 decide.py --selftest
python3 param_taint.py --selftest
python3 validator_contract.py --selftest
python3 authz_consistency.py --selftest
python3 chain_align.py --selftest

cd ast_analyzer
go test ./...
```

## 目录说明

| 路径 | 用途 |
| --- | --- |
| `detect_vulns.py` | 主检测入口 |
| `ast_analyzer/` | Go AST、数据流和跨函数分析器 |
| `decide.py` | 基于事实与 span 的本地判定 |
| `cvss.py` | CVSS v3.1 确定性评分 |
| `confidence.py` | 证据加权置信度评分 |
| `behavior_chains_generic/` | 随仓库发布的通用行为链 |
| `gen_testcases.py` | 根据 finding 生成测试用例与 PoC |
| `tests/fixtures/` | 回归测试用 Go 样例 |
| `DETECTION_PIPELINE.md` | 检测流程说明 |
| `CLAUDE.md` | 数据生产流水线和工程约束 |

数据抓取与知识库构建的阶段顺序记录在 [CLAUDE.md](CLAUDE.md)；这些阶段会产生大量本地数据，相关目录已在 `.gitignore` 中明确排除。

## 安全与数据说明

- 仓库不应包含 `.env`、API Key、GitHub Token、扫描目标源码或运行报告。
- `projects/`、`workdir/`、漏洞数据集与中间 JSON 默认只保留在本地。
- 如果密钥曾进入 Git 历史，仅从最新提交删除是不够的；应立即撤销密钥并清理整个历史。
- finding 需要结合源代码审查和受控运行证据确认；未复现不等同于误报。

## 许可证

当前仓库尚未添加开源许可证。在选择许可证前，默认保留全部权利。
