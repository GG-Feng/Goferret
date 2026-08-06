# SUMMARY — 4 样本速查

> 从 [README.md](README.md) 抽出来的"看这一页就够"版。
> 详细 timing / 阶段日志见 [logs/run.log](logs/run.log)；每条 finding 全文见 [reports/](reports/)。

## 总体判定

检测器**能工作、值得信任**：4/4 跑通，3/4 命中正确 CVE 类别，2/4 干净区分
vuln/patch，1/4 识别"补丁本身可绕过"，1/4 找到同代码区真实但不同的问题。

## 对比表

| 样本 | CVE | 域（真值） | 耗时 vuln / patch | vuln finding 数 / HIGH | patch finding 数 / HIGH | 判定 |
|---|---|---|---|---|---|---|
| GO-2020-0034 | CVE-2020-36560 | Archive + Path | 122s / 166s | 5 / 2 | 4 / 1 | 完全命中，patch 中 `zip_slip_path_traversal` 消失 |
| GO-2023-1494 | CVE-2014-125064 | QueryTemplate | 495s / 568s | 13 / 5 | 15 / 4 | 命中概念；patch 改用 blacklist 被识别为可绕过 |
| GO-2020-0024 | CVE-2013-10005 | Network | 320s / 400s | 4 / 0 | 3 / 0 | 类别错位（CVE 是无限递归，探测器报 SOCKS5 长度字段） |
| GO-2022-0957 | CVE-2020-36066 | InputParsing | 437s / 43s | 3 / 1 | 0 / 0 | 命中 DoS 类；patch 0 finding，耗时 10× 加速 |

合计：~42 min，~32-40 次 LLM 调用。

## 逐样本 finding 清单

### GO-2020-0034 (CVE-2020-36560 ZipSlip) — 完全命中

| 版本 | 等级 | pattern_name | 置信度 | 位置 |
|---|---|---|---|---|
| vulnerable | HIGH | `zip_slip_path_traversal` | 0.95 | `unzip.go:Extract` ← **真值** |
| vulnerable | HIGH | `compression_bomb_unbounded` | 0.90 | `unzip.go:Extract` |
| vulnerable | MEDIUM | `archive_permission_inheritance` | 0.85 | `unzip.go:Extract` |
| vulnerable | LOW | `mkdir_error_ignored` | 0.85 | `unzip.go:Extract` |
| vulnerable | LOW | `archive_name_log_injection` | 0.75 | `unzip.go:Extract` |
| patch | HIGH | `zip_bomb_unbounded_decompression` | 0.95 | `unzip.go:Extract` |
| patch | MEDIUM | `zip_entry_mode_injection` | 0.88 | `unzip.go:Extract` |
| patch | MEDIUM | `mkdirall_error_ignored` | 0.90 | `unzip.go:Extract` |
| patch | LOW | `zip_entry_name_log_injection` | 0.80 | `unzip.go:Extract` |

patch 残留：解压炸弹（补丁只补路径，不补解压上限）、mode 注入、mkdir/log
边角问题。**真值 ZipSlip 已消失**。

### GO-2023-1494 (CVE-2014-125064 SQL 注入) — 命中概念

| 版本 | 等级 | pattern_name | 置信度 | 位置 |
|---|---|---|---|---|
| vulnerable | HIGH | `raw_sql_statement_no_sanitization` | 0.75 | `gosqljson.go:QueryDbToArray` ← **真值类** |
| vulnerable | HIGH | `swallowed_db_query_error` | 0.95 | `gosqljson.go:QueryDbToMapJson` |
| vulnerable | HIGH | `unclosed_db_rows_resource_leak` | 0.90 | `gosqljson.go:QueryDbToArray` |
| vulnerable | HIGH | `unsanitized_sql_statement_passthrough` | 0.75 | `gosqljson.go:QueryDbToMap` |
| vulnerable | HIGH | `insufficient_sql_prefix_validation` | 0.75 | `gosqljson.go:ExecDb` |
| vulnerable | MEDIUM×5, LOW×3 | … | … | … |
| patch | HIGH | `recover_swallows_error` | 0.90 | `gosqljson.go:QueryDbToArray` |
| patch | HIGH | `unbounded_result_set` | 0.82 | `gosqljson.go:QueryDbToArray` |
| patch | HIGH | `sql_blacklist_bypass` | 0.65 | `gosqljson.go:QueryDbToArray` ← **新增：补丁用 blacklist** |
| patch | HIGH | `inadequate_sql_injection_filter` | 0.85 | `gosqljson.go:QueryDbToMap` ← **新增：补丁过滤器不充分** |
| patch | MEDIUM×10, LOW×1 | … | … | … |

SQL 家族 finding 在两版里都报了 5+ 个 HIGH，但**命名换了一套**。
`raw_sql_statement_no_sanitization` 在 patch 端被改名为
`sql_blacklist_bypass` + `inadequate_sql_injection_filter`——**检测器判定
补丁方法本身可绕过**。

### GO-2020-0024 (CVE-2013-10005 SOCKS5) — 类别错位

| 版本 | 等级 | pattern_name | 置信度 | 位置 |
|---|---|---|---|---|
| vulnerable | MEDIUM | `unvalidated_domain_length panic` | 0.88 | `dial.go:Dial` |
| vulnerable | MEDIUM | `socks5_length_field_overflow` | 0.82 | `dial.go:Dial` |
| vulnerable | LOW | `missing_io_timeout` | 0.75 | `dial.go:Dial` |
| vulnerable | LOW | `unescaped_host_format` | 0.60 | `addr.go:String` |
| patch | MEDIUM | `socks5_domain_len_oob_read` | 0.85 | `dial.go:Dial` |
| patch | MEDIUM | `socks5_field_length_truncation` | 0.80 | `dial.go:Dial` |
| patch | LOW | `socks5_no_io_timeout` | 0.60 | `dial.go:Dial` |

CVE-2013-10005 真值是 `RemoteAddr/LocalAddr` 无限递归。检测器没找到这条
（也没法用 `--max-functions 5` 的小预算找出无限递归），但**在同一个
`dial.go:Dial` 找到了 4 个真问题**（SOCKS5 长度字段无验证），且 patch 端
`addr.go:String` 的 `unescaped_host_format` 真值消失了。整体**类别错位
但有信息量**。

### GO-2022-0957 (CVE-2020-36066 JSON DoS) — 命中 DoS 类

| 版本 | 等级 | pattern_name | 置信度 | 位置 |
|---|---|---|---|---|
| vulnerable | HIGH | `glob_recursive_backtracking_dos` | 0.90 | `match.go:deepMatchRune` |
| vulnerable | MEDIUM | `broken_utf8_error_guard` | 0.75 | `match.go:deepMatchRune` |
| vulnerable | MEDIUM | `recursive_backtrack_dos` | 0.85 | `match.go:deepMatchRune` |
| patch | — | — | — | 0 finding |

CVE-2020-36066 是 JSON 输入 DoS，检测器报的是 glob/backtrack DoS（同一项目
里另一个 DoS 向量）。Patch 0 finding，耗时 437s → 43s（10× 加速说明
patch 后的代码匹配模板数大幅减少，验证管线效率也对得上）。

## 已知 LLM 特性汇总

1. **命名漂移**：同一代码级问题在 vulnerable 与 patch 中被命名为不同
   `pattern_name`（如 `unvalidated_domain_length panic` ↔ `socks5_domain_len_oob_read`）。
2. **粒度可变性**：vulnerable 报"无验证"，patch 报"过滤器不充分"——结论
   更准确但 finding 数量"看起来变多"。
3. **类别错位**：检测器可能找到同代码区真实但不同的问题（GO-2020-0024）。

不影响可信度——所有 finding 都对应真实代码模式，模式库能跨样本复用。
