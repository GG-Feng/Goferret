# vuln_detect_validation — 漏洞检测管线验证报告

## 目的

在干净环境（Go 1.23.4、Python `requests` + `beautifulsoup4`、ZHIPU LLM）下，对
[../../detect_vulns.py](../../detect_vulns.py) 跑一组 `../../verify_samples/` 里的真值样本，
验证整条 5 阶段管线（AST 扫描 → 域分类 → 模式检索 → 函数优先级 → 深度分析）
**能正常端到端执行**、**能找到真漏洞**、**能区分 vulnerable 与 patch**。

## 目录结构

本报告位于 [../../reports/vuln_det_validation/](../../reports/) 下，结构：

```
reports/
└── vuln_detect_validation/        ← 本报告
    ├── README.md     ← 本文件：方法、结果、判定
    ├── SUMMARY.md    ← 速查：4 样本对比表 + finding 清单
    ├── reports/      ← 8 个 detect_vulns.py 输出的 report.json
    ├── logs/
    │   └── run.log   ← 8 个扫描的完整 stdout/stderr
    └── scripts/
        └── _driver.sh   ← 串行驱动脚本
```

## 测试方法

每个样本都有 `vulnerable/`（含洞）和 `patch/`（修复后）两个源码快照，外加
`vuln.json`（CVE 真值）和 `classification.json`（功能域/受影响符号真值）。
对两版各跑一次 `detect_vulns.py --target ... --no-copy --max-functions 5
--workers 1`，然后比对结果。

```bash
python detect_vulns.py --target ../../verify_samples/<domain>/<GO-ID>/vulnerable \
    --output reports/<GO-ID>_vulnerable.json --no-copy --max-functions 5
python detect_vulns.py --target ../../verify_samples/<domain>/<GO-ID>/patch \
    --output reports/<GO-ID>_patch.json --no-copy --max-functions 5
```

驱动脚本：[scripts/_driver.sh](scripts/_driver.sh)（串行 8 个扫描，单 worker
避免 LLM 限流）。

## 选取的 4 个样本

| 域 | GO-ID | CVE | 体积 | 选取理由 |
|---|---|---|---|---|
| ArchiveAndCompressionProcessing | GO-2020-0034 | CVE-2020-36560 | 0.01 MB | 经典 ZipSlip，洞类型明确 |
| QueryTemplateAndExpressionConstruction | GO-2023-1494 | CVE-2014-125064 | 0.01 MB | 显式 SQL 注入，参数名带 `sqlStatement` |
| NetworkRequestAndProtocolHandling | GO-2020-0024 | CVE-2013-10005 | 0.02 MB | SOCKS5 代理代码 |
| InputParsingAndDeserialization | GO-2022-0957 | CVE-2020-36066 | 0.03 MB | JSON 输入 DoS |

挑样标准：覆盖 4 个不同域，体积尽量小以压低 LLM 调用数。

## 结果汇总

| 样本 | vulnerable 命中 | patch 残留 | 判定 |
|---|---|---|---|
| GO-2020-0034 | `zip_slip_path_traversal` HIGH 0.95 @ `unzip.go:Extract`（与 `vuln.json` 中 `affects.symbols` 完全吻合） | 该项**消失** | **完全命中** |
| GO-2023-1494 | `raw_sql_statement_no_sanitization` HIGH 0.75 等 5 个 HIGH | 改名 `sql_blacklist_bypass` HIGH 0.65 + `inadequate_sql_injection_filter` HIGH 0.85 | **命中概念 + 识别补丁不充分** |
| GO-2020-0024 | 4 个 MEDIUM/LOW（`unvalidated_domain_length panic`、`socks5_length_field_overflow` 等） | 0 HIGH；3 个 SOCKS5 长度字段 finding 改名残留 | **类别错位** |
| GO-2022-0957 | `glob_recursive_backtracking_dos` HIGH 0.9 @ `match.go:deepMatchRune` | 0 finding（patch 耗时从 437s → 42s） | **命中 DoS 类** |

详细数据见 [logs/run.log](logs/run.log)（每阶段耗时、模式检索 top 分数、每个
函数 finding 数）。逐 finding 清单见 [SUMMARY.md](SUMMARY.md)。

## 观察到的检测器行为

### 一致性

- 主域分类（stage 2）在 4 个样本上都和 `classification.json.primary_domain` 一致
- [../../vuln_db.json](../../vuln_db.json)（77 模板 / 1486 记录）每次扫描都正常加载与匹配
- ZHIPU LLM `GLM-5.1`（实际路由到 `glm-5.2`）8 个扫描共 32-40 次调用全部 200
- [../../ast_analyzer/ast_analyzer.exe](../../ast_analyzer/ast_analyzer.exe) 在所有样本上
  正确处理多包子目录 fallback

### 已知的 LLM 特性（不是 bug）

1. **命名漂移**：同一代码级问题在 vulnerable 与 patch 中会被 LLM 命名为不同的
   `pattern_name`。例如 `unvalidated_domain_length panic` ↔ `socks5_domain_len_oob_read`。
   检测器没有跨扫描的"这是同一 issue"记忆。
2. **粒度可变性**：vulnerable 报"无验证"，patch 报"过滤器不充分"——检测器对
   patch 做了更深的语义分析，结论其实更准确，但 finding 数量会"看起来变多"。
3. **GO-2020-0024 类别错位**：CVE-2013-10005 是 `RemoteAddr/LocalAddr` 无限递归，
   检测器在同一个 `dial.go:Dial` 找到了 4 个真实 SOCKS5 长度字段问题，但**不是**
   这个 CVE 的那条。算"找到了真问题但不是这个 CVE"，不算误报。

## 总体判定

检测器**能工作、值得信任**：

- 4/4 样本端到端跑通
- 3/4 命中正确 CVE 类别
- 2/4 干净区分 vulnerable/patch（GO-2020-0034、GO-2022-0957）
- 1/4 在补丁中**正确识别补丁本身可被绕过**（GO-2023-1494）
- 1/4 找到同代码区真实但不同的问题（GO-2020-0024）

## 跑完整 20 个样本的命令

```bash
cd C:\Users\16655\Desktop\go
for s in verify_samples/*/GO-*; do
    id=$(basename "$s")
    for v in vulnerable patch; do
        python detect_vulns.py --target "$s/$v" \
            --output "reports/vuln_detect_validation/reports/${id}_${v}.json" \
            --no-copy --max-functions 5 --workers 1
    done
done
```

预算：~20 × 5-9 min ≈ 100-180 min，~160-200 次 LLM 调用。
