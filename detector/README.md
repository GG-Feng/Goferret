# Goferret 检测器

面向 Go 项目的研究型漏洞检测与验证流水线。项目把本地 AST/污点分析、行为链知识库、LLM 语义事实提取、确定性判定、CVSS v3.1 与证据加权置信度组合为一条可审计的检测流程。

> 当前版本属于研究原型。扫描结果是候选证据，不能代替源码复核、受控复现或正式安全审计。只应扫描你拥有或已获授权的目标。

## 核心能力

- 扫描本地 Go 项目，或按 Git URL/分支/标签拉取后扫描。
- 使用 Go AST 分析输入源、危险汇、净化操作、跨函数参数传播和授权一致性。
- 默认模式让 LLM 提取带行号的语义事实，由本地规则决定是否形成 finding；增强模式另加全仓语义发现与独立证据核验。
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

## 增强检测模式

借鉴 OCR 的上下文工具与独立核验机制，在现有规则之外增加全仓分层语义发现：

```bash
python3 detect_vulns.py --target /path/to/go-project --detection-mode enhanced
```

增强模式可用 `--enhanced-max-model-calls N` 限制新增的全仓发现与候选核验请求数；默认 `0` 不限制。此上限不包含先运行的原有结构化检测通道。达到上限时，未检查的源码单元标为 `pending`，未完成核验的候选保留为 `unknown`，报告 `enhanced.status` 为 `partial`，并在 `enhanced.limits` 记录已用请求数。调用数上限不是 token 或费用硬上限。

默认仍为 `legacy`。增强模式会检查全部生产 Go 文件中的函数、闭包和声明；`--flow-gate`、`--max-functions` 与 `--align-max-funcs` 仅约束原有通道，不限制新增发现通道。文件按 AST 边界及大小拆分，模型可按需查询源码、调用关系和污点路径。每个发现单元及每个候选各最多六轮请求，每轮最多三个只读查询；没有候选数量截断，因此大仓库调用成本可能明显增加。

每个源码单元至多先推进一个新调查组的一轮核验；完成发现后，各组代表候选轮流调查，再处理组内其他候选。分组依据是函数、危险位置和类别，只用于分配额度，组员各自保留独立结论。有限额度可能使后续单元保持 `pending`，报告分别记录发现与核验调用数，并在 `enhanced.investigation_groups` 保留分组成员。调用关系查询提供调用点、实参来源和候选目标的参数/返回值事实；字段查询可按显式类型身份寻找协议字段的构造、读取与写入，并返回局部变量的可能赋值来源。名称分派、隐式类型及分支可达性仍需核查。

增强模式保留检查和清洗操作作为保护假设，通过独立核验形成 `supported`、`refuted`、`unknown`。`supported` 是源码证据支持，**不是动态复现**；失败、歧义或调查轮数耗尽均保留为不确定。报告使用 `goforret.enhanced/v1`：

- `findings`：supported 与 unknown，均不受旧 confidence 阈值过滤。
- `enhanced.triage_queue`：把两类结果列为可复核的检测候选；`needs_review` 对应 unknown，保留位置、源码引用、未决问题和核验原因。CLI 也逐项显示。它不是已复现漏洞清单。
- `enhanced.candidates`：包含 refuted 的全部核验结果；`raw_candidates` 保留各来源原始候选。
- `enhanced.tasks`、`source_errors`、`invalid_candidates`：发现覆盖、失败和输出协议问题；`status=partial` 表示过程不完整，`complete` 也不表示代码安全。
- 每项保存源码引用、核验结论和查询轨迹。语义通道没有可靠数值评分时 CVSS/confidence 为 null；结构化通道旧评分仅作排序参考，不替代 validation_status。

测试生成器默认仅处理增强报告中的 supported；使用 `--include-unknown` 可包含待核实项。生成文件以 finding ID 命名，避免同模式相互覆盖。

增强模式首次使用会按 Go 源码内容构建临时分析器，需要 Go 1.23+。不会使用可能过期的仓库内二进制。主检测流程会加载漏洞库并检索行为链；新增语义发现通道本身不读取漏洞库或补丁。

离线回归（使用安装了 requirements.txt 的 Python 环境）：

```bash
python3 -m unittest discover -s tests -p 'test_enhanced*.py' -v
```

这些测试使用真实 Go 分析器与确定性模型替身，验证候选保留、上下文查询和证据协议，不证明真实模型的精确率或召回率。机制与限制见 [增强检测说明](docs/ENHANCED_DETECTION.md)。
