# Go 漏洞检测分析逻辑

本文档详细描述 `detect_vulns.py` 的检测分析逻辑：从一份 Go 源码到 `report.json` 的完整数据流、每个阶段的作用、以及贯穿全程的设计原则。适合需要理解、修改或调试检测管线的读者。

## 1. 概览

检测管线对一个 Go 项目做**静态 + LLM 语义**的漏洞分析，输出带证据、CVSS 评分和置信度的 findings。

核心思想一句话概括：

> **LLM 只做语义事实提取，一切判断（是否存在漏洞、严重程度、置信度）都由本地确定性规则决定。**

这条原则贯穿全程，带来两个直接好处：

- **可复现**：相同的事实输入 → 相同的报告（判断逻辑零随机性）。
- **稳定**：LLM 只输出「高 logit 差」的事实 token（行号、枚举类别），而非容易漂移的判断 token；配合 `temperature=0.1`，两次运行的结果在 distinct findings 层面能做到零漂移（实测 DeepSeek ×2 = 18/18 一致）。

## 2. 架构总览

```
Go 源码
   │
   ▼
[Stage 1] AST 扫描（本地 Go 分析器 ast_analyzer）
   │  多包合并、三张模式表匹配（source/sink/sanitizer + import 门控）
   │  输出: imports / call_chains / data_flow_indicators / stdlib_signals / functions
   ▼
[Stage 2] 域分类（1 次 LLM，可 --domains 手动跳过）
   │  输出: active_domains（10 个功能域的子集）
   ▼
[Stage 3] 模式检索（本地，查 vuln_db.json）
   │  输出: 候选漏洞模板（按 API overlap 评分）
   ▼
[Stage 4] 函数排序（本地评分）
   │  输出: scored_functions（带 data_flow / call_chain）
   ▼
[Stage 5] 语义提取（N 次 LLM，flow gate 过滤）
   │  输出: 每函数的事实（purpose / semantic_inputs / semantic_sinks / observed_checks）
   ▼
[本地决策] decide.py —— 合并事实 → span 规则 → findings
   ▼
[本地评分] cvss.py（CVSS 3.1）+ confidence.py（证据加权置信度）
   ▼
[过滤 + 报告] confidence 阈值过滤 → report.json
```

## 3. 分阶段详解

### 3.1 Stage 1 — AST 扫描（本地）

调用 Go 二进制 `ast_analyzer`（`ast_analyzer/main.go`），对源码目录做静态分析。

- **多包合并**：`parser.ParseDir` 只覆盖根包，`_find_go_subdirs`（深度 ≤4，剪枝 `vendor`/`testdata`/`.git`，排序保证可复现）找出所有子包目录，`_merge_subdir_results` 合并结果——否则 gin 这类多包仓库会漏掉 `binding/`、`render/`、`internal/` 等。
- **三张模式表**（子串匹配 AST 节点的文本形式）：
  - **source 表**：读外部输入 → 标记为 `http_request`/`read`/`json_decode`/`scan`/`http_body` 等 14 种 source 类型。
  - **sink 表**：危险/敏感操作 → 标记为 `command_execution`/`sql_query`/`file_write`/`string_format`/`write` 等。
  - **sanitizer 表**：约 41 个安全检查 API → 映射到 `missing_step_category`（如 `filepath.Clean`→`path_validation`、`jwt.Parse`→`identity_verification`）。`bounds_check`/`error_handling`/`protocol_validation` 无可靠 API 信号，刻意缺省。
- **import 门控**：source/sink 表是 `flowPattern` 结构，带可选 `gateImports` 字段。receiver-name 模式（如 `c.Query(`）只在 import 了对应框架的文件里匹配——module-root 前缀匹配，`github.com/labstack/echo` 同时覆盖 `echo/v4`。这避免了 `*sql.DB` 名叫 `c` 时 `c.Query(` 被误判成 `http_request` 源。

输出按函数组织：每个有 source/sink 的函数生成一条 `data_flow_indicators`（`{sources[], sinks[], sanitizers[]}`，每个点带 `line`/`pattern`/`type`）。

### 3.2 Stage 2 — 域分类（1 次 LLM）

把 Stage 1 的静态信号（stdlib 信号、import 集合、关键调用链 top 20）拼成提示，用 `detect_domain.md` 作为 system prompt，一次 LLM 调用输出项目命中的**功能域**（10 个之一或几个：InputParsingAndDeserialization、PathHandlingAndFilesystemAccess、AuthenticationAndAuthorization、NetworkRequestAndProtocolHandling、CommandExecutionAndExternalProcessInteraction、QueryTemplateAndExpressionConstruction、ArchiveAndCompressionProcessing、ConcurrencyStateAndSharedResourceManagement、ResourceBoundingAndDoSProtection、CryptographicVerificationAndSecurityValidation）。

- 可用 `--domains` 手动指定，跳过这次 LLM 调用。
- LLM 失败时回退 `_infer_domains_from_signals`（纯 stdlib 信号统计推断，不阻塞流程）。

### 3.3 Stage 3 — 模式检索（本地）

根据活跃域从 `vuln_db.json` 的 `domain_index` 收集候选模板，再按 **API overlap**（项目 stdlib 信号与模板 `api_indicators` 的重合度）评分：

```
score = 域置信度 × 0.5 + API 重合率 × 0.5
```

输出候选模板列表（后续 decide.py 用于绑定 pattern_name / summary）。

### 3.4 Stage 4 — 函数排序（本地评分）

对每个函数打启发式分数，决定哪些进入语义提取。加分项：

| 信号 | 分值 |
|---|---|
| 同时有 source 和 sink | +3 |
| 只有 source 或 sink | +1 |
| 危险 sink（string_format/write/command_execution/sql_query） | +10 |
| 调用链命中模板 API 指标 | +2 |
| HTTP handler 特征 | +2 |
| 引入危险 stdlib（os/exec、database/sql 等） | +2 |
| 函数名含安全关键词（handle/parse/auth/upload 等） | +1 |

之后还有一道**危险 sink 强制补充**：有危险 sink 数据流但分数为 0 的函数，强制挂上 `score=15` 进入提取（避免漏掉高危函数）。

### 3.5 Stage 5 — 语义提取（N 次 LLM + flow gate）

**flow gate** 是成本控制的主力：一个函数的 AST 数据流**既没有 source 也没有 sink**，就不可能形成 span（决策引擎要求两者都在），因此直接跳过，不进 LLM。实测 gin 全量 502 个函数 → 跳过 404 个 → **63 个进提取**。

对通过的每个函数，用 `detect_extract.md` 作为 system prompt，让 LLM 只提取**事实**（明确禁止输出 findings/severity/confidence/cvss）：

- `purpose` — 函数用途
- `semantic_inputs` — 语义输入（`origin` + 行号）
- `semantic_sinks` — 语义汇聚点（`kind` + 行号）
- `observed_checks` — 观察到的检查（类别 + 行号）

关键细节：提取提示里嵌入了**绝对文件行号**（`N|` 前缀，从函数起始行算起），使语义通道的行号和 AST 通道共享同一个行空间，两个通道可以直接对齐。

成本控制的几个开关：

- **`--workers`** 并发（DeepSeek 下建议 4~32）。
- **`--batch-size`** 批处理：多个函数合并进一次 LLM 调用（`detect_extract.md` 输出 JSON 数组）。实测 batch=5 使调用数 92→16（−83%）、耗时减半；代价是单边函数（靠 LLM 补另一半）偶有 1-2 条漂移。
- **混合策略**（内置）：AST 同时识别出 source 且 sink 的「成对」函数单跑精跑（保证 check 提取准确），其余单边函数才批处理——把召回/成本取舍精确到函数粒度。
- **关 reasoning**（`thinking:{"type":"disabled"}`）：DeepSeek 默认思考模式占 94% completion token 和 15× 延迟，对本管线（低难度事实提取、判断本地化）是纯冗余。关闭后耗时 1041s→67s、completion −94%、truncation 归零、distinct 不降反升。

`max_tokens` 起点 2048（批处理时 ×批大小），截断自动翻倍重试。

### 3.6 本地决策 — decide.py

这是整个管线「LLM 去判断化」的落点。`build_findings` 对每个函数：

1. **事实合并** `merge_facts`：AST 通道与语义通道合并。**AST 权威**——同一行的类型冲突时 AST 胜出；语义事实只填空缺和补充描述。语义事实的行号在 AST 同类型事实 ±2 行内会**吸附**到 AST 行（消除 LLM 行号漂移和 origin/kind 翻转造成的幻影重复）。无行号的事实丢弃；`origin=internal` 的输入不算 source。
2. **span 判定**：每个 `(source, sink)` 对构成一个 span（同行的、sink 在 source 前 1-2 行的行计数漂移都排除）。对每个 span，用 `CATEGORY_FLOW_HINTS` 找出该 (source 类型, sink 类型) 能命中的 `missing_step_category`，再用 `unprotected_categories` 过滤掉**跨度内**有同类检查的类别。
3. **报告条件**：

   > **source 存在 且 sink 存在 且 跨度内无该类别检查 → 一个 finding**

4. **collapsing** 去重（避免 N×M 爆炸）：
   - sink-hint 类别：每个 `(sink, category)` 一条，取最早 source（最长流）。
   - source-only 类别（无 sink hint，如 bounds_check）：每个 `(函数, category)` 一条，取最宽 span。
5. **确定性构造** `_make_finding`：pattern_name 从模板 `pattern_names[0]` 或退化为 `{category}_via_{sink_type}`；evidence 用 `L<line> <type> → L<line> <type>` 构造；span 记录 source/sink 的行号、类型、描述。

### 3.7 评分 — cvss.py + confidence.py

**CVSS（cvss.py）**：严重度完全确定性计算，LLM 不产出任何 CVSS 指标。`resolve_metrics` 从 AST 事实 + 每个 `missing_step_category` 的默认向量出发，AST 数据流事实**只升不降**：网络 source 类型强制 `AV:N`，危险 sink 类型升级 C/I/A。每个 metric 的来源记录在 `cvss_provenance`。映射到 none/low/medium/high/critical。

**置信度（confidence.py）**：3 个可验证证据维度的确定性加权和：

| 维度 | 权重 | 含义 |
|---|---|---|
| code_evidence | 0.45 | `L<line>` 引用是否落在函数源码行界内 |
| ast_corroboration | 0.35 | 类别对应的 source/sink 类型是否在 AST 数据流中出现；跨度内同类 sanitizer 标记「已保护」→ 0.1 |
| template_support | 0.20 | template_id 是否在 vuln_db 中解析成功 |

级别：confirmed ≥0.75 / likely ≥0.5 / tentative <0.5。每维度的 score/provenance/detail 记录在 `confidence_breakdown`。

最终按 `--confidence-threshold`（默认 0.5）过滤后写入报告。

## 4. 关键设计原则

1. **LLM 去判断化**：LLM 只提取语义事实（`detect_extract.md`），是否漏洞、严重度、置信度全由 decide/cvss/confidence 本地决定。稳定性的根源：事实 token（行号、枚举类别）在 `temperature=0.1` 下是高 logit 差、稳定的，而判断 token 已完全不再由 LLM 生成。

2. **flow gate 成本控制**：无 source 且无 sink 的函数不可能形成 span，直接跳过。这是全量扫描最大的成本杠杆。

3. **行号对齐**：提取提示嵌绝对行号，两通道共享一行空间，`merge_facts` 的 ±2 行吸附消除漂移。

4. **AST 权威**：同一行两通道冲突时 AST 胜，语义通道只补缺、不覆盖——保证锚点稳定。

5. **确定性可复现**：pattern 命名、evidence 文本、模板绑定、CVSS、置信度全部由规则推导，相同事实 → 相同报告。

## 5. 关键模块

| 模块 | 作用 |
|---|---|
| `ast_analyzer/main.go` | Go 静态分析器：三张模式表 + import 门控 + 多包合并 |
| `detect_vulns.py` | 主流程：5 阶段编排 + 报告生成 |
| `decide.py` | 确定性决策引擎：事实合并 + span 规则 + finding 构造 |
| `cvss.py` | 确定性 CVSS 3.1 评分 |
| `confidence.py` | 证据加权置信度 + `CATEGORY_FLOW_HINTS`（12 类别的 source/sink 类型提示） |
| `llm_config.py` | 统一 LLM provider 配置（`LLM_PROVIDER` → `LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL`） |
| `detect_domain.md` | 域分类 system prompt |
| `detect_extract.md` | 语义事实提取 system prompt |

### CATEGORY_FLOW_HINTS（12 个 missing_step_category 的流类型提示）

每个类别定义 `(source 类型集, sink 类型集)`，决定哪些 (source, sink) 对能命中该类别：

| 类别 | source 提示 | sink 提示 |
|---|---|---|
| input_sanitization | 全部 source | command_execution / sql_* / string_format / write / html_injection / js_injection |
| output_encoding | 全部 source | string_format / write / html_injection / js_injection |
| path_validation | 全部 source | file_read / file_write |
| bounds_check | json_decode / xml_decode / binary_read / scan / read* / buffered_read / io_copy / http_body | （空，source-only） |
| resource_limit | 同上 + network_accept / read_message | （空，source-only） |
| origin_validation | http_request / http_body | （空，source-only） |
| access_control | http_request / http_body / network_accept / read_message | （空，source-only） |
| identity_verification | 同上 | （空，source-only） |
| state_synchronization | channel_recv | （空，source-only） |
| protocol_validation | network_read / network_accept / read_message / scan / binary_read | （空，source-only） |
| cryptographic_verification | （空） | （空） |
| error_handling | （空） | （空） |

后两者无流类型信号，仅能通过 LLM 语义通道或模板间接命中，置信度走中性 0.5。

## 6. 配置

所有 LLM 相关配置集中在 `.env`，通过 `llm_config.py` 解析：

```bash
# 切换 provider 只改这一行 + 对应 provider 的 *_API_KEY/_BASE_URL/_MODEL
LLM_PROVIDER=deepseek

DEEPSEEK_API_KEY=sk-...
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
```

支持 9 个 provider：deepseek / zhipu / ark / openai / moonshot / qwen / anthropic / google / openrouter。所有 LLM 脚本（detect_vulns / classify_vulns / classify_vulns_v2 / behavior_chain_extract / gen_testcases）统一读 `LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL`，`resolve_llm` 根据 `LLM_PROVIDER` 从对应 provider 变量解析。

**运行**：

```bash
# 中小项目：默认即可（关 reasoning 后单函数全量 ~1 分钟）
python detect_vulns.py --target /path/to/project --workers 4

# 万级函数项目：批处理省时间（接受丢 1-2 条单边函数的 check 误报）
python detect_vulns.py --target /path/to/project --workers 16 --batch-size 5

python detect_vulns.py --git-url https://github.com/owner/repo --git-ref v1.0.0
```

- `--workers` 并发，默认 1，DeepSeek 下建议 4（中小）~32（大项目）。
- `--batch-size` 批处理（每批函数数），默认 1（单函数，最准）；万级函数项目才显式传 5。
- 混合策略内置：成对函数（source+sink）自动单跑精跑，单边函数才批处理。

## 7. 输出结构

每次运行创建 `projects/YYYYMMDD_HHMMSS/`：

```
projects/<id>/
├── source/          # 源码副本（或 git clone）
└── report.json      # 检测报告
```

`report.json` 关键字段：

- `scan_info` — 元信息：`model`、`total_functions`、`analyzed_functions`、`total_duration`、`llm_usage`（calls/prompt_tokens/completion_tokens）
- `project_domains` — Stage 2 的域分类结果
- `findings[]` — 每条 finding 带：
  - `function` / `missing_step_category` / `pattern_name` / `template_id`
  - `span` — `{source: {line, type, desc}, sink: {line, type, desc}}`
  - `evidence` — `L<line> <type> → L<line> <type>，跨度内无 <category> 检查`
  - `cvss_score` / `cvss_vector` / `cvss_provenance` / `severity`
  - `confidence` / `confidence_breakdown` / `confidence_level`

## 8. 已知边界与副作用

- **框架自扫的 sink 命中**：source/sink 的 import 门控按「文件 import 了框架模块或其子包」判定，框架自身源码通过 `internal/` 自引用也满足门控。因此扫描框架自身（如 gin）时，6 个 Context 方法（`AbortWithStatus`、`Render` 等）会被标为 `write` sink——但它们是 sink-only，无 source 则无 span，只多几次提取调用，不产生 finding。真实业务项目因 `vendor`/module-cache 剪枝不受影响。
- **`deepseek-v4-pro` 的 reasoning 已默认关闭**（`thinking:{"type":"disabled"}`）：思考模式对本管线是纯冗余，关闭后耗时/completion 双减 94%、截断归零、distinct 不降反升。关闭后模型不再输出 `reasoning_content`，`content` 直接是干净 JSON（已验证无草稿泄漏）。
- **残余漂移**：无 AST 锚点的语义事实（如 sink-only 函数里 LLM 补出的 source）是架构下限，无法靠加 pattern 消除；当前通过「AST 权威 + 行号对齐」已大幅收敛。
- **检测器覆盖边界（召回验证结论）**：行为链模型检测的是「数据流中缺失了安全检查」（source→sink + 缺 check），能精确命中 path_validation/bounds_check/resource_limit 等数据流型漏洞（实测 go-unzip 的 Zip Slip 精确命中 `Extract` + `path_validation`）。但对「纯逻辑 bug」（运算符优先级错误、鉴权比较用 `!=` 而非 `ConstantTimeCompare`、算法错误）无能为力——判断「逻辑写错了」需要语义判定，不是「缺失步骤」能覆盖的。这决定了 detect_vulns 的定位是「行为链缺失步骤检测器」（适合 0-day 初筛），而非替代逻辑 bug 的代码审计。
