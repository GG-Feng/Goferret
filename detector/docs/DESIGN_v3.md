# GOFORRET 检测器 v3 设计文档（草案）

> 基线：v2（tag `v2`，commit 0fc043c）。状态：草案，待作者审阅。
> 依据：消融实验 exp2（`消融实验/exp2/07_results/`）对 Full 组 7 个漏检项目的根因分析。

## 0. 摘要

v2 的判定规则只在一种形态下报告漏洞：**同一个函数里同时有攻击者输入（source）和危险操作（sink），且两者之间缺少同类检查**。exp2 中 Full 漏检的 7 个项目，大多不在这一形态里。v3 在不改变整体架构（“LLM 只提取事实，本地规则判定”）的前提下，增加三类规则：

| 编号 | 改进 | 解决的漏检形态 | exp2 中对应的项目（仅用于验证改动是否生效） |
|---|---|---|---|
| R1 | 类别对应表放宽，并新增“尺寸敏感”的 sink | 请求中的数值直接决定内存分配或下标 | vouch-proxy |
| R2 | 参数外部可达 + 跨函数污点传播 | 输入经参数传入漏洞函数，被 v2 当作内部数据 | fabric-ca、registry（与 R3 配合） |
| R3 | 校验函数契约 | 校验函数存在但不完整；校验结果在调用方流入 sink | openrun、registry |

**不在 v3 范围内**：授权逻辑的 control_flow 匹配器（migration-planner、identrail）、配置默认值检查（mcp-shell）、LLM 直接判定通道。

## 0.1 实现进度
- R1：已实现（commit f74edae）。回归：只开 v2 规则时，6 个项目的输出与 v2 逐字节一致（固定 PYTHONHASHSEED）。真实运行验证：vouch-proxy 漏洞版报出 2 条 R1（L130 分配长度、L136 下标），修复版为 0 条。
- F1（新增）：修复 v2 模板绑定的不确定性（候选模板 set 在同分时的顺序依赖哈希种子）。同分按 template_id 排序；作为独立开关，默认开启。验证：开启 F1 时，3 个不同种子的输出一致；关闭时不一致。
- 作者已定：R2 最多传播 4 跳，默认开启同名方法匹配（name_dispatch）；R3 按参数名推断用途默认开启；5 个评估仓库由作者提供；评估只跑 v3 一组、一轮（v3 报告按 rule_id 区分 v2_span 与 R1/R2/R3，新规则的增量直接从中统计），A0 参照组暂不做；评估集见 `消融实验/数据集/v3评估数据集.csv`。
- R2：已实现（`ast_analyzer/param_flow.go` + `param_taint.py` + decide/confidence/detect 接入）。与第 3.2 节草案的差异和补充：
  - **分析器输出 `param_flows`**（独立字段）：每个函数的参数（含首次使用行）、入口类型、带污点“根”的调用点、注册为处理函数的引用、实参带污点的危险 sink（`taint_sinks`），以及 R2 专用 sanitizer。根为 `param:i`、`entry`（请求类型参数；或传给路由注册调用的闭包的非 context 参数）、`src`（AST source 或请求访问器，如 `.BasicAuth(`、`.FormValue(`、`.Header.Get(`，按调用文本匹配，所以 `ctx.req.BasicAuth()` 也算）。
  - **函数内传播**：不区分语句顺序的 def-use（赋值、var、range），不动点；`x, err := f(a)` 只传给第一个结果；`len()`/`cap()` 不传播；R2 sanitizer（`ldap.EscapeFilter`/`EscapeDN`）的返回值不带污点；`x.F` 中的字段名、结构体字面量的键不视为变量。
  - **sink 只看承载危险值的实参**：SQL 调用只看查询字符串（`Query/Exec` 第 0 个，`*Context` 第 1 个）；`*sql.Stmt`（接收者名含 stmt）不算 sink；`http.Redirect` 只看目标 URL；文件操作只看路径。`alloc_size` 为 `make` 的长度参数。未采用 `index_access`（map 下标无法与切片区分，噪声过大）。
  - **跨函数传播**（`param_taint.py`）：按 go.mod 的 module path 把导入路径映射到目录；同包函数、`self` 方法精确解析；接收者类型未知时做 name_dispatch（同名、参数个数兼容，候选不超过 5 个，否则放弃）。按 (是否经过 name_dispatch, 跳数) 取最优路径。来源取值：`param_entry`（0 跳）、`param_1hop`、`param_nhop`（2–4 跳）、`name_dispatch`。开关：`--r2-max-hops`、`--no-name-dispatch`。
  - **判定**：类别由 sink 类型决定（命令/SQL → input_sanitization；query_exec、html/js → output_encoding；文件 → path_validation；redirect → origin_validation；alloc_size → resource_limit）。同类检查（AST、R2 sanitizer、LLM observed_checks）位于 [source 行, sink 行) 内视为已保护。每个函数每个类别只报最早的 sink；与 v2 span 规则的（函数, 类别, sink 行）重复时丢弃 R2。source 行取参数首次使用行；若它不早于 sink（多行调用），取函数声明行。R2 finding 额外带 `source_provenance`、`taint_path`。需要 LLM 提取结果；带污点 sink 的函数若未入选打分，会以 15 分补入提取集合（只在开启 R2 时）。
  - **置信度** ast_corroboration：param_entry / param_1hop 0.7，param_nhop 0.6，name_dispatch 0.5。
  - **降噪说明（如实记录）**：sink 实参限定、stmt、`len()`、字段名这四项修正是在 exp2 的 10 个项目上观察 R2 事实数时发现的（identrail 241→18，openrun 139→29），属于通用缺陷修复，但 exp2 因此属于开发集；效果评估只用 5 个新仓库。
  - **验证**：自写夹具 `tests/fixtures/r2`（1 跳包调用、name_dispatch、闭包 2 跳、按引用注册、字符串拼接 SQL、预编译语句与同名字段两个反例、转义阻断、超过 4 跳、关闭 name_dispatch）；decide 新增 7 个 R2 用例；只开 v2 规则时 6 个项目输出与 v2 逐字节一致。生效验证（只看污点事实，未调用 LLM）：fabric-ca 漏洞版 `Client.GetUser` 的 `ldap.NewSearchRequest`（L172）被 `BasicAuthentication@L107` 经 name_dispatch 污染，修复版因 `EscapeFilter` 为 0 条。

- R2 追加修正（R3 开发中发现，同样是通用缺陷）：包名（import 别名）不携带污点；请求、ResponseWriter、context 类型的参数只在初始时标为 `entry`，不再通过 `r = r.WithContext(...)` 之类的赋值吸收其他值的污点。修正后 R2 事实数：openrun 29→25，其余项目不变。
- R3：已实现（`param_flow.go` 的 check_facts / vret / varg 标记 + `validator_contract.py` + `validator_rules.json`）。与第 4.2 节草案的差异：
  - **强/弱校验表用 JSON**（`validator_rules.json`），因为运行环境没有 PyYAML；每条都注明公开出处（OWASP 备忘单、CWE、Go 官方博客）。
  - **识别校验函数**：名称匹配 validate/valid/check/verify/sanitize 开头，或 is…Valid/Allowed/Safe。其中 check/valid/is 这几个词也常用于非校验的辅助函数，所以要求最后一个返回值是 bool 或 error；validate/verify/sanitize 不限返回类型（registry 的 `validateWebsiteURL` 返回 `*ValidationResult`）。还要求至少一个参数经 R2 外部可达。
  - **用途**：分析器在调用方给校验函数的返回值打 `vret:L`、给被校验的实参打 `varg:L` 标记，调用方的 sink 若带这些标记，就按 sink 类型确定用途（redirect / path / encoding / input）。请求、ResponseWriter、context 对象不打 `varg`。
  - **判定只看强校验模式**，不使用 LLM 的 observed_checks：校验函数本身就是一次“检查”，LLM 几乎总会报出同类别检查，无法区分强弱。
  - **按参数名推断用途**（第 9 节问题 2）：作者已定**默认开启**；关闭用 `--no-r3-infer-purpose`。推断出的 finding 标 `purpose_inferred=true`，置信度维度 0.4，评估时单独统计其命中与噪声。
  - 置信度 ast_corroboration：用途来自调用方 sink 且找到弱校验 0.7；来自 sink 但未找到任何校验模式 0.6；按参数名推断 0.4。
  - **开发集观察（如实记录）**：identrail 的 `sanitizeAuthReturnTo` 把校验委托给 `authReturnTo…Allowed` 辅助函数，最初被误报；据 OWASP“优先使用允许列表”的建议，把调用名含 allowed/allowlist/whitelist 的辅助函数计为强校验。
  - **生效验证**（只看事实，未调用 LLM）：默认模式下，10 个项目中只有 openrun 有 R3 事实：`validatedRefererRedirect`（漏洞版 1 条，修复版 0 条，修复加入了拒绝 `//` 前缀）。打开参数名推断后：registry 的 `validateWebsiteURL` 漏洞版 1 条、修复版 0 条；但另外多出 3 条修复前后都存在的疑似误报（identrail 2 条、openrun 1 条）。
  - 回归：只开 v2 规则时 7 个项目（新增 openrun）输出与 v2 逐字节一致。stub 全规则运行：openrun 新增 R2 11 条、R3 1 条；fabric-ca 新增 R2 1 条。

- **v3.1（v3eval 1 轮评估后）**：v3 在 5 个新仓库上 R1–R3 命中 0 个（`消融实验/v3eval/07_results/结论.md`）。按漏洞类别补强，**exp2 的 10 个与 v3eval 的 5 个都降为开发集**，泛化效果只用未看过代码的留出仓库评估。
  - R2 的 source 只认网络来源（HTTP 请求、网络读、K8s 对象的注解/标签 `GetAnnotations/GetLabels`）；stdin、文件、通用解码不算（ffuf 交互终端输入造成的误报）。
  - 包内返回值摘要：函数的返回值带外部输入时，调用处视为 source（4 轮不动点，仅同包函数与 self 方法）。
  - SSRF（CWE-918）：`http.Get/Post/Head/PostForm` 的 URL、`http.NewRequest(WithContext)` 的 URL、`net.Dial(Timeout)` 的地址作为 R2 sink（类别 input_sanitization）；给 `Address/Addr/URL/BaseURL/Endpoint/Host/ServerURL` 字段**赋值**也算（结构体字面量不算，多为响应/状态值）。R3 新增用途 outbound（强校验：IsPrivate/IsLoopback 等、允许列表；依据 OWASP SSRF 备忘单）。
  - **R4 无上限读取**（CWE-400/409，新规则、独立开关）：`io.ReadAll`、`ioutil.ReadAll`、`io.Copy` 的源、`.ReadFrom` 读取外部输入，且未经 `io.LimitReader`/`http.MaxBytesReader` 限流；经过解压器（gzip/zlib/flate/brotli/zstd 等 NewReader）后限流失效。HTTP 响应体（`.Body`）本身不算外部输入，只有解压后才算（解压炸弹）；请求体经处理函数入参算外部输入。类别 resource_limit。
  - 同函数内的网络 source 直接到达 R2/R4 sink 时也报告（来源 `direct`，置信度维度 0.7），与 v2 span 规则重复的仍丢弃。
  - 生成代码（`// Code generated ... DO NOT EDIT.`）不参与 R2/R4。
  - R4 的保护只看 AST 看到的读取限流器（`lim`），不采信 LLM 报出的 resource_limit 检查：Content-Length 等大小检查由攻击者控制，也与解压后的大小无关。**开发集观察（如实记录）**：v3.1 首轮在 ffuf 上 R4 事实存在但被 L168 的 `size > MAX_DOWNLOAD_SIZE`（Content-Length）判为已保护，由此修正。
  - 开发集上的事实（未调用 LLM）：新增覆盖 ffuf `SimpleRunner.Execute`（R4，修复版消失）、vault-secrets-webhook 两个真值函数（R2 SSRF）、podinfo `echoHandler`（R4，非该通告类别）；exp2 原有的 fabric-ca / openrun / registry 保持。降噪过程（生成代码 69→2 条等）如实记录在提交历史中。
  - 回归：只开 v2 规则时 7 个项目输出与 v2 逐字节一致。

- **v3.2（作者要求：先让 v3eval 5 个仓库全部正确命中，再做泛化验证）**。范围由作者选定：越权/IDOR、路径穿越扩展、注入泛化 + XSS。全部按 CWE 通用写法实现；开发集仍为 exp2 10 个 + v3eval 5 个。
  - 传播：多返回值中除 err/ok 外的每个结果都带污点；`Unmarshal/Decode/ReadJSON/Bind…(&x)` 的输出参数接收其他实参与接收者的污点；跨包/未解析方法调用的结果记为 `call:L`，由 `param_taint.external_returns` 在全模块做不动点（精确解析任一被调者返回外部输入即可；name_dispatch 要求全部候选都返回外部输入）。
  - 出站 URL 按位置区分（Sprintf 格式串或字符串拼接，需带 `scheme://` 字面量）：主机/端口 → SSRF（input_sanitization），路径/查询 → `url_path`（path_validation，CWE-22）。
  - 注入泛化（CWE-943）：Sprintf 或含字符串字面量的拼接结果作为 Query/Exec/Search/Raw/Where/Run/Eval/Mutate/Do 等调用的实参（非标准库）→ `query_built`（input_sanitization）。
  - XSS（CWE-79）：外部数据经 `w.Write`、`fmt.Fprint*(w, …)`、`io.WriteString(w, …)` 写入 `http.ResponseWriter`，且函数未设置非 HTML 的 Content-Type → `response_write`（output_encoding）。html/template/url 转义函数阻断污点。
  - **R5 越权（同类处理函数授权不一致，CWE-862/639，新规则）**：同一文件、同一接收者类型的处理函数中，按请求中的标识（`request.Id` 等）访问数据的至少 3 个，其中至少一半确立了调用者身份或做了授权检查；其余未检查者报 access_control。所有同类都不检查时不报（鉴权可能在中间件）。置信度维度 0.6。
  - **netfoil 不做专门规则**：其漏洞是 DNS 阻断响应返回 0.0.0.0/::（协议语义设计错误），没有“外部输入→危险操作”的数据流；为它写规则等于对题作答，违背泛化目标。
  - **开发集观察（如实记录）**：R5 最初按目录分组，migration-planner 中 accounts.go 的群组处理函数与 source.go 混组产生 6 条误报，改为按文件分组；URL 位置分析最初把 `"http://%s:%d%s"` 的第三个占位符算作主机，已修正（主机后仅紧跟 ':' 的占位符为端口，其余为路径）。
  - 开发集事实（未调用 LLM）：新增覆盖 openhole `ForwardToLocal`（url_path，修复版消失）、podinfo `echoHandler`（response_write，修复版消失）、migration-planner `GetSourceDownloadURL`（R5，修复版消失）；v3.1 已覆盖的保持。仍未覆盖：netfoil（见上）、identrail（跨租户 IDOR 位于 3000 行的路由注册函数中）、mcp-shell（安全模式允许列表绕过）。
  - 回归：只开 v2 规则时 7 个项目输出与 v2 逐字节一致。夹具：`tests/fixtures/r5`（R5）、`tests/fixtures/r6`（v3.2 传播与 sink）。
  - **留出集说明**：为冻结类别，已读过原定留出集 5 个仓库的通告摘要（未读代码），v3.2 的类别与之有重叠；最终泛化评估建议另选规则冻结后才查看的新通告。

- **v3.3（降噪）**：v3.2 两批真实扫描中新规则的噪声主要来自“出站请求的响应被当作攻击者输入”。通用修正：
  - 出站调用（`http.Get/Post/Head/PostForm`、任意 `.Do`/`.RoundTrip`、接收者名含 client 的 `.Get/.Post/.Head/.PostForm`）的返回值只带 `resp` 标记，不继承参数的污点；
  - 类型为 `*http.Response` 的参数视为响应对象；对响应对象调用 `.Header.Get`、`.Cookies` 等访问器不算请求输入，也不做跨包/同名方法解析。
  - 响应体仍只在经过解压器时算外部输入（R4 解压炸弹不受影响）。
  - 开发集事实（未调用 LLM）：vouch-proxy R4 8→0（OAuth 提供方响应），ffuf R2 5→0（扫描器递归请求）；所有真值覆盖保持（fabric-ca、migration-planner、openrun、registry、vouch-proxy、openhole、vault、ffuf、podinfo）。夹具 r4 增加反例（由请求构造的 client 的响应）。回归：只开 v2 规则时 7 个项目输出与 v2 逐字节一致。

- **v4.0（结构化的外部输入模型；留出集评估失败后的重做）**。v3.3 在 5 个留出仓库上新规则命中增量为 0。作者要求：不再用枚举入口的方式，要能在陌生仓库上检出真实漏洞。原定留出集 5 个仓库自此**降为开发集**（共 20 个开发仓库：exp2 10 + v3eval 5 + 原留出 5）；泛化评估须另选规则冻结后才查看的新通告。
  - **来源类别（origin class）取代“只认网络来源”的枚举**。每条污点带来源类别与到达方式，置信度维度按类别打分：`net` 0.7（请求/网络读，沿用原有入口）、`wire` 0.6（解码数据：**带字段 tag 的结构体**类型的参数——tag 是数据跨边界的语言级标记，不枚举 tag 名；以及从 `any` 断言出基本类型且容器来源未知的值）、`io` 0.5（任何非网络的读取/解码，只排除进程自己的控制台 `os.Stdin`）、`cb` 0.5（**逃逸的函数值**的参数：函数值被放进复合字面量、赋给字段/下标、或作为实参传给非标准库调用——由框架/他方以其选择的实参调用）。经同名方法匹配 −0.1，≥2 跳 −0.05。原路由注册名单 `HandleFunc/GET/Register…` 整张删除，由 `cb` 结构规则覆盖。
  - **两条来源规则的边界（开发集上纠正，如实记录）**：`any`/`map[string]any` **参数**本身不是来源（migration-planner 的 `buildQuery(params any)` 曾把所有 SQL 模板染色），只有从容器中断言出的值才是；带 tag 结构体参数只在**模块内没有任何调用者**的函数上作为来源（由框架解码后调用；fabric-ca 的 `*ClientConfig` 内部配置曾被误判）——为此分析器输出每个函数的完整被调者列表 `callees`。
  - **参数直通摘要**：函数把参数（或其派生）作为返回值时，调用点的结果继承对应实参的污点（同包在 Go 内做不动点；跨包由 `ret_calls` 带实参根在 Python 侧解析）。函数自身的返回状态只由来源与调用链决定，不把参数透传汇总成状态——否则一个被污染的调用者会污染所有调用者（openrun 上 174→95 条事实）。
  - **接口分发按签名扩展**：同名方法超过 5 个但参数类型签名完全一致时，视为同一接口的多个实现（插件/驱动架构），全部传播（mcp-toolbox 的 40 个 `Tool.Invoke`）；签名各异则视为巧合同名，放弃。调用点状态按轮次记忆化并防环。
  - 输出参数语义扩展到模板渲染（`Execute/ExecuteTemplate` 把数据写进其 writer 实参）；新增 `url_path` sink：外部数据经 `ResolveReference`/`JoinPath` 成为 URL 对象的相对引用（给 URL 的 Path 字段赋值是安全写法——openhole 的修复正是如此——不算 sink）。
  - **F2**：取消包目录扫描深度上限（logging-operator 的漏洞文件在 5 层深，v2 从未扫到）。
  - **F3（从实验数据学到的）**：exp2 的 50 张盲审卡按类别统计，`output_encoding`/`input_sanitization` 配 `fmt.Sprintf`/`.Write` 的 finding 0/25 为真，仅看 source 的三类 0/10 为真；而它们占 v3.3 全部 6787 条告警的 62%。F3 在 span 规则中去掉泛化 sink（`write`、`string_format`）配对与仅看 source 的类别；去重顺序改为先 F3 再合并，使同位置的结构性 finding（如 podinfo 的 `response_write`）得以保留。开发集上告警 6787→1139，项目级类别一致的主口径命中无损失（唯一掉的 mcp-shell 四条盲审均判假）。
  - 新增 `--dump-extractions`：把每个函数的 LLM 提取事实、AST 数据流与 R2/R3/R5 事实写入 `extractions.json`，以便事后审计已知漏洞在哪一步断链（此前的运行日志只有 token 元数据，无法做这种审计）。
  - **开发集事实（未调用 LLM，工具 v4.0）**：结构规则覆盖真值函数 12/20——exp2：fabric-ca、migration-planner、openrun、registry、vouch-proxy；v3eval：openhole、vault、ffuf、podinfo；原留出：nezha、infracost（`readFile` 经 `template.FuncMap` 逃逸→cb）、mcp-toolbox（服务端处理函数→接口分发 `Invoke`→`getURL` 的 `ResolveReference`）。未覆盖：yutu、aqua、bird-lg-go（v2 规则命中）、identrail、mcp-shell、netfoil、logging-operator（配置渲染无危险 API）、dgraph（链长 ≥5 跳且查询以对象构造，超出 4 跳上限与字符串拼接 sink 的定义）。新规则事实数（漏洞版）：exp2 10 仓库 231、v3eval 5 仓库 30、原留出 5 仓库 183；其中 openrun 74、dgraph 86、infracost 52 为主要来源（cb/io 类别）。
  - 回归：只开 v2 规则时 7 个项目输出与 v2 逐字节一致（每次改动后重跑）。夹具 `tests/fixtures/r7`。

- **v4.1（G1 污点闸门：成本）**。全量扫描把每个有分数的函数都送 LLM（v3.3 的 16 个仓库：24,633 次调用、37M token）。G1 用 AST/污点事实决定哪些函数值得问 LLM——一个函数只有在“可能产生 finding”时才送：有 R2/R3/R4/R5 事实，或 R1 尺寸 sink 且有 source，或 span 规则可配对的 AST source 与 sink。LLM 只能补一侧，所以分三档：A（以上条件）、B（A 或任一可配对的 AST sink，LLM 补 source）、C（B 或任一 AST source，LLM 补 sink；**默认**）。`--gate-level A|B|C`，规则开关 `G1`；`--rules v2` 不受影响。
  - 用 v3.3 的 16 次漏洞版扫描离线评估（闸门按 v4 事实计算，finding 取 F3 过滤后的）：送 LLM 的函数 12,122 → A 427（4%）/ B 901（7%）/ C 1,460（12%）；真值命中 10/10 全部保留；F3 后的 finding 保留 A 44% / B 65% / C 91%。C 档损失的 9% 主要是 registry、aqua、dgraph 上 LLM 单侧补足的 span finding。
  - 记录：`scan_info.filters.taint_gate_level`、`funnel.gate_skipped`。回滚标签：`v4.0`（闸门之前）、`v3.3`、`v2`。

- **v4.2（引擎三项 + 评估口径）**。
  - 跳数上限改为软上限：硬上限 8（`--r2-max-hops`），超过 4 跳每跳置信度 −0.05（下限 0.3）。开发集：dgraph 的 `passwordQuery` 参数现已被污染，但仍无 sink（查询以对象构造后交给 `Execute`，不是字符串拼接）——保留为已知缺口，未按其形态加 sink。
  - R5 覆盖内联注册的处理闭包：分析器为逃逸且带请求类型参数的函数字面量输出 `closure_handlers`（各自的身份检查/资源访问事实），同一函数内注册的闭包互为同类。资源访问的实参判据改为“带请求污点且源码文本含 id 一词”（原来用 `exprToString` 丢失了实参）。夹具 `tests/fixtures/r5/routes.go`。identrail 仍未覆盖：其 79 个闭包无一在闭包内做身份检查（鉴权在中间件），缺陷是“信任客户端提供的 InstallationID 而未验证归属”，不属于同类不一致形态。
  - **F4**：LLM 报告的检查必须落在 AST 有调用或比较的行（±1）上才算保护，否则不采信；分析器输出 `check_lines`。无行事实时不丢弃。
  - **评估口径（`消融实验/tools/eval_l123.py`）**：L1 定位（finding 在真值函数内或污点路径经过真值函数，且跨度 ±3 行与修复 hunk 相交）、L2 类别（∈ 修复类别；修复类别由 diff **新增行**按通用模式推断，推不出时人工指定并记录）、L3 消失（以（函数，类别，sink 类型，sink 行源码文本）为键，漏洞版有、修复版无）；检出 = L1∧L2∧L3，按级别与规则分别计数。用 v3.3 的 16 个仓库报告试算：L1 12/16、L1∧L2 9/16、检出 6/16；类别推断在 yutu、nezha、netfoil 上为空（需人工指定）。
  - 回归：只开 v2 规则时 7 个项目输出与 v2 逐字节一致。

- **v4.3（v4.2 在 10 个小仓库真实运行后的两处修正，均为结构性）**：R4 把“在 reader 上构造流式解码器”（`.NewDecoder(reader)`）计为无上限读取（bird-lg-go：`json.NewDecoder(r.Body).Decode`，修复为 `MaxBytesReader`）；R2 的 `alloc_size` sink 承认 R1 的范围检查为保护（vouch-proxy：修复加了 `maxCookieParts` 上限后 R1 消失而 R2 仍报）。

- **v5.0（LLM 通道升级；作者决定：消融改以 v5 为 Full 组，用 v5 的开关做归因，exp2 结果作为历史记录）**。留出集 v43holdout（6 案例）v4.3 结果 0/6；关闭闸门的对照证明断在事实层而非闸门：capsule（K8s 对象参数被 AST/LLM 均判为内部）、coredns（gRPC/QUIC 流读取不在 sink 表；resource_limit 在 F3 后只能由结构 sink 产生）、centrifugo（“输入被当作可信元数据转发”无此配对）、perses-6528（路径进入非文件 sink）。这 6 个案例自此转为开发集。
  - **X1 入口判定**（`detect_triage.md`）：签名级 LLM 调用（每 40 个函数一批，只给签名、接收者类型、包路径、第三方 import），判断函数是否由外部主体触发及哪些参数携带外部数据；结果作为来源类别 `llm`（置信度 0.5）种入传播引擎，先于闸门。用 LLM 承担“认框架/协议/对象模型”这一 AST 做不到的部分，不枚举框架。
  - **X2 提取提示词 v5**（`detect_extract_v5.md`）：sink 按形态命名（`query`、`alloc`、`unbounded_read`、`url_path`、`network`、`redirect`、`response_html`、`forward`、`template`、`log`），映射到结构 sink 类型后按形态配对（`V5_SINK_CATEGORY`），不经 v2 的类别提示表；`forward`（输入被当作可信元数据转发/用于身份判断）对应 identity_verification/input_sanitization。消息中附带入口判定结果，这些参数在函数体内首次使用行计为 network 输入。v2 的提示词与类别表不动，`--rules v2` 仍逐字节复现 v2（7/7）。
  - **X3 跨函数保护**（`validator_contract.callee_checks`）：路径上调用的校验函数若其 `check_facts` 含某用途的强模式，则调用行计为该类别的 AST 级检查（针对 mcp-shell、vault 这类“修复在别处”的 L3 失败）。
  - 消融设计（v5 通道内）：Full；−X1；−结构规则（仅 v2 span）；A0。

- **v5.1**：入口判定为外部的函数直接通过 G1 闸门（coredns 的 gRPC/QUIC 处理函数曾因无 AST sink 被跳过，LLM 没机会报形态化 sink）；R5 在提取之后做第二遍，把 LLM 观察到的 access_control/identity_verification 检查计为身份检查再比较同类处理函数（perses-6514：同类代理处理函数部分有授权检查、部分没有）。v5.0 在 16 个开发案例：检出 8/16（v4.3 6/16），告警 501→882（几乎全是 v2 span 规则因入口判定新增的 source），调用 3397→3916、token 6.0M→10.2M。
- **v5.2（X4，行为链对齐，弱类别专用；未评估）**：强类别（数据流：路径/注入/资源/编码）检测方法不变。弱类别（授权、身份、来源、协议、状态、错误处理——没有“危险 sink”，是“少了一步”）改为**模板引导的逐步对齐**。① 候选 = 入口判定为外部 / AST 处理函数 / 污点引擎从外部来源可达的任何函数，且至少有一行调用或比较。**初版只取入口函数，离线核对 8 个弱类别开发案例时发现 convoy、mcp-shell、netfoil、registry 的真值函数全部不在候选内**（它们是被入口调用的服务层/校验函数），故扩大到可达函数。② 扩大后每个仓库 400–1500 个候选；**离线测得按 API 词汇重合度排序时真值函数排在中位数或更后**（convoy 785/1531、perses-6528 284/419），词汇重合不能当筛选器。因此加一步签名级**角色判定**（`detect_role.md`，只看签名、返回类型和被调函数名，40 个一批）：resource_access / authorization / authentication / trusted_forwarding / validator / redirect_origin / protocol_handler / state_mutation / none，按 `ROLE_CATEGORIES` 路由到链类别，none 丢弃。③ 检索只在路由到的类别里进行：按 IDF 加权的词重合（驼峰拆分的函数名、被调函数、参数类型 vs. 链摘要/步骤描述/证据 API）取最佳真实链 + 最佳通用链（`behavior_chains/` 544 条非 data_flow 链 + `behavior_chains_generic/` 13 条）。④ LLM（`detect_align.md`）只做对齐：每一步对应哪一行、MISSING 那一步 present/absent/unknown。⑤ 本地规则（`chain_align.decide`）只在入口、出口步骤都对上、≥60% 非缺失步骤落在 AST 调用/比较行、缺失步骤判为 absent 时才报告，unknown 一律不报；同文件对齐到同一模板且执行了该步骤的函数数记为 peers_present（提升置信度）；每个（函数，类别）只保留一条，且只补充其他规则没报出的。短的同包被调函数（≤30 行）随函数一起给出。链目录用 `--chain-dirs` 挂载（与 vuln_db.json 一样不进镜像）；`--align-max-funcs`（默认 150）限制对齐数。`--rules v2` 仍逐字节一致（7 个夹具）。
- **v5.2b（X4 修订，依据第 1 步 3 个小案例 0/3 的逐函数追踪）**：A 角色→主类别 + 固定通用链（ROLE_PRIMARY / ROLE_GENERIC），真实链只在主类别内检索（原先跨三个类别按词重合挑链，校验函数被配上“开放重定向”等不相干链）；B 片段对齐：LLM 给出函数实现的连续片段 segment=[i,j]，报告条件改为片段触及缺失步骤位置、段内≥2 且≥60% 非缺失步骤落在 AST 调用/比较行、缺失步骤 absent（原先要求入口与出口都在本函数，被调的校验/响应构造函数必然对不上）；C 通用链事实需同文件兄弟函数执行了该步骤或同函数另有真实链事实，否则只写入 extractions.json 的 x4_withheld；D 角色提示词加入签名形态判据（字符串/结构体参数 + bool/error 返回 + 比较/匹配/解析调用 → validator）。未解决：channel 传递（netfoil worker.process）、配置默认值类（mcp-shell）。

## 1. 设计原则（沿用 v2，并补充两条）

1. **LLM 只提取事实**：不改动 `detect_extract.md`。v3 新增的事实全部由 AST 和本地分析得出，这样提取阶段与 v2 完全可比。
2. **判定是确定性的**：相同的输入得到相同的报告；新规则也是纯本地计算。
3. **AST 的结论优先**：与 v2 相同。
4. **（新）每条 finding 标注来源规则**：新增字段 `rule_id`，取值 `v2_span`、`R1`、`R2`、`R3`，以及 `source_provenance`（取值 `direct`、`param_1hop`、`param_nhop`、`name_dispatch`），用于按规则统计贡献和噪声。
5. **（新）每条规则都有开关**：`--rules v2,R1,R2,R3`，默认全部开启。关掉 R1–R3 后的输出必须与 v2 逐字节一致，作为回归基准。

## 2. R1：类别对应表放宽 + 尺寸敏感的 sink

### 2.1 问题
v2 中 `resource_limit`、`bounds_check` 是“仅 source”类别：只要函数里有 `json_decode`、`read_all` 等 source，就报告；而 source 的提示集**不包含** `http_request`。因此，“从请求头或 cookie 读出一个数，再用它决定分配大小或下标”（vouch-proxy 的 `make([]string, numParts)`）在结构上报不出。

### 2.2 设计
- **AST 新增两个 sink 类型**（`ast_analyzer/main.go`，需要专门的 Go 逻辑，不能靠子串匹配）：
  - `alloc_size`：`make(T, n)` 或 `make(T, 0, n)`，其中 n 不是常量；
  - `index_access`：`x[i]`，其中 i 不是常量、也不是 range 循环的下标变量。
- **CATEGORY_FLOW_HINTS 新增“带 sink 的变体”**（`confidence.py`）：
  - `resource_limit`：source 包括 `http_request`、`http_body`、`read_message`、`param_external`（R2），sink 包括 `alloc_size`；
  - `bounds_check`：source 同上，sink 包括 `index_access`、`alloc_size`。
  - 原来的“仅 source”匹配**保持不变**，保证 v2 已有的命中（如 bird-lg-go）不丢。
- **补充 sanitizer 表**：数值范围比较，例如 `n > max`、`n < 1`、`n >= len(x)`。这类比较无法用子串识别，由 AST 识别“对同一变量的比较，并伴随 return 或 error 分支”，记为 `bounds_check` / `resource_limit`，行号取比较所在行。LLM 提取的 `observed_checks` 照常合并。

### 2.3 预期（验证用）
vouch-proxy：source 为 `r.Cookies()`（语义通道给出 http_request），sink 为第 130 行的 `make([]string, numParts)`，中间没有范围比较，因此报出 `resource_limit`。修复版新增了 `numParts < 1 || numParts > maxCookieParts`，位于 span 内，被判为已保护，这条 finding 会消失，满足严格口径。

### 2.4 噪声风险
`index_access` 在 Go 代码中非常常见。缓解办法：只有当下标变量的来源与 source 在同一条数据链上（下标变量由 source 值经赋值或转换得到，比如 `strconv.Atoi`）时才构成配对。只做函数内的简单 def-use 追踪。

## 3. R2：参数外部可达 + 跨函数污点传播

### 3.1 问题
v2 的提取规则规定“普通函数参数一律视为内部数据”。所以 fabric-ca 的 `Client.GetUser(username)`、registry 的 `validateWebsiteURL(ctx, websiteURL)` 都没有 source。

exp2 中核实的调用路径：
- fabric-ca：`serverrequestcontext.go:107` 的 `ca.registry.GetUser(username, nil)`，这是**接口调用**，实现之一是 LDAP 的 `Client.GetUser`；username 来自请求认证信息。
- registry：huma 框架的处理函数 `publish.go:58` 调用 `validators.ValidateServerJSON(&input.Body, …)`，再到 `validators.go:92` 的 `validateWebsiteURL(ctx.Field(...), serverJSON.WebsiteURL)`；`input` 是框架从请求 JSON 解码得到的结构体参数。

### 3.2 设计
**(a) AST 新增输出**（`ast_analyzer/main.go`）
- `FuncDef.params`：`[{index, name, type}]`；
- `FuncDef.entry_kind`：入口类型：
  - `http_handler`：签名含 `http.ResponseWriter` / `*http.Request`，或 gin、echo、fiber、beego 的上下文类型；
  - `registered_handler`：作为参数传给路由或处理器注册函数（`HandleFunc`、`Handle`、`GET`、`POST`、`huma.Register`、`mux.Handle` 等，维护一张可扩展的表）；
  - `grpc_method`：签名为 `(ctx, *XxxRequest)`，且方法属于实现了生成的 `XxxServer` 接口的类型；
  - `exported` 或 `internal`。
- `FuncDef.call_sites`：`[{line, callee_expr, resolved: [qname…], resolution: exact|pkg|name_dispatch, args: [{index, expr, idents}]}]`；
  - 解析方法：
    - 同包按名称和接收者解析；
    - 跨包通过 `go.mod` 的 module path 把导入路径映射到目录后解析；
    - 接口或变量类型未知时，匹配模块内同名、同参数个数的所有方法，记为 `name_dispatch`。
- `FuncDef.param_uses`：每个参数在函数体内第一次被使用的行号，以及它流入的字段访问（`p.X`）。

**(b) 本地污点传播**（新模块 `param_taint.py`，纯 Python，确定性）
- **初始污点**：
  - 入口函数中的请求类参数，以及 `registered_handler` 的全部非 context 参数；
  - 任何函数内被 AST source 赋值的局部变量（函数内 def-use，只做一层）。
- **传播规则**：调用点的某个实参表达式引用了污点标识符（参数、局部变量，或其字段 `x.F`、`&x.F`），则被调函数对应位置的形参被标记为污点。
- **不动点迭代**：深度不超过 4 跳，按函数键排序迭代，保证可复现。每个污点形参记录传播路径和解析方式。
- **输出**：为每个污点形参在其首次使用行生成一个合成 source `{type: param_external, line, provenance: param_1hop|param_nhop|name_dispatch, path}`，并入该函数的 data flow，再交给 `decide.merge_facts`。

**(c) 判定规则**
- `param_external` 加入 input_sanitization、output_encoding、path_validation、bounds_check、resource_limit 的 source 提示集；**不加入** origin_validation、access_control、identity_verification，避免噪声。
- **噪声控制（关键）**：`param_external` 只与“危险 sink”配对，即 command_execution、sql_*、`query_exec`（新增）、file_*、html_injection、js_injection、`redirect`（新增）、`alloc_size`、`index_access`。**不与** `string_format`、`write`、`log` 这类泛化 sink 配对。
- **AST 新增 sink 模式**：
  - `query_exec`：`ldap.NewSearchRequest(`、`.Search(`（ldap）、`bson.M{`、`gorm .Where(` 等，维护一张可扩展的表；
  - `redirect`：`http.Redirect(`、`c.Redirect(`。
- **新增 sanitizer**：`ldap.EscapeFilter(`、`ldap.EscapeDN(` 记为 output_encoding。
- **置信度**：`ast_corroboration` 中，`param_external` 按来源打分：直接可达 0.7，多跳 0.6，`name_dispatch` 0.5；`code_evidence` 不变。

### 3.3 预期（验证用）
- fabric-ca：username 经接口调用（`name_dispatch`）传入 `Client.GetUser`；第 172 行的 `ldap.NewSearchRequest` 是 `query_exec`，第 175 行的 `Sprintf` 就在其参数中，因此报出 output_encoding / input_sanitization。修复版使用了 `ldap.EscapeFilter`，被判为已保护，finding 消失。
- registry：`input` 是注册处理函数的参数，`&input.Body` 传入 `ValidateServerJSON`，`serverJSON.WebsiteURL` 再传入 `validateWebsiteURL`，经 2 跳成为 `param_external`。它的 sink 在另一个组件（目录页渲染），需要 R3 配合。

### 3.4 风险
- `name_dispatch` 会过度近似（同名方法有多个实现）。缓解：来源单独标注，置信度较低，按规则单独统计噪声。
- 各种 Web 框架的注册方式很多：注册函数表需要随评估集扩充，**但不得按评估集的具体项目定制**。

## 4. R3：校验函数契约

### 4.1 问题
- openrun：`validatedRefererRedirect` 返回一个重定向目标，**sink 在调用方**（`handler.go:409` 的 `http.Redirect`）；校验本身存在但不完整（`strings.HasPrefix(path, "/")` 会接受 `//host`）。修复只加了 3 行：拒绝 `//` 前缀。
- registry：`validateWebsiteURL` 只检查了 URL 的格式，没有拒绝 `"'<>` 和空白字符；这个值最终会进入 HTML 的 href 属性。修复新增了 `strings.IndexAny(websiteURL, "\"'<> \t\n\r")`。

### 4.2 设计
**(a) 识别校验函数**（本地规则）：名称匹配 `^(validate|valid|check|verify|sanitize|is.*(Valid|Allowed|Safe))`，并且满足以下之一：返回 `bool` 或 `error`；返回 `(T, bool)` 或 `(T, error)`；其中至少一个参数为外部可达（R2）或来自调用方的 source。

**(b) 确定校验的“用途类别”**：
- 调用方把校验函数的返回值或被校验的实参传入某个 sink 时，按 sink 类型确定需要的类别：`redirect` 对应 origin_validation；file_* 对应 path_validation；html、template 或 query_exec 对应 output_encoding / input_sanitization；
- 调用方找不到 sink 时，按参数或字段名推断：包含 `URL`、`Url`、`URI`、`Href`、`Link` 的，对应 input_sanitization（URL 字符约束）。这种情况置信度较低，标注 `purpose_inferred`。

**(c) 强校验与弱校验表**（新文件 `validator_rules.yaml`，与 sanitizer 表并列，维护通用的安全知识，**不按项目定制**）：

| 用途 | 视为“强校验”的模式 | 已知的“弱校验”模式 |
|---|---|---|
| 站内重定向（origin_validation） | 拒绝 `//` 和 `/\` 前缀；`url.Parse` 之后 Host 为空且路径不以 `//` 开头；白名单比对 host | 只检查 `HasPrefix(x, "/")`；只检查 Scheme |
| URL 字段（input_sanitization） | 按字符类拒绝（`IndexAny` / `ContainsAny` / 带锚点的正则），拒绝引号、`<>`、空白；或对输出做转义 | 只做 `url.Parse` 或只检查 scheme |
| 路径（path_validation） | `filepath.Clean` 之后做前缀比对；`filepath.IsLocal`；`os.Root` | 只检查 `strings.Contains(x, "..")` |

**(d) 判定**：校验函数内（AST sanitizer 加上 LLM 提取的 observed_checks）**没有**该用途的强校验，就在校验函数上报一条 finding：`rule_id=R3`，类别为用途类别；span 取“参数首次使用行 → 弱校验所在行，或 return 行”，evidence 引用这两行。

### 4.3 预期（验证用）
- openrun：调用方把返回值传给 `http.Redirect`，用途为 origin_validation；函数内只有 `HasPrefix(path, "/")` 这种弱校验，因此报出。修复版加入了 `HasPrefix(x, "//")` 这一强校验，finding 消失。
- registry：用途按字段名 `websiteUrl` 推断为 input_sanitization；函数内只有 `url.Parse` 和 scheme 检查，因此报出（置信度较低）。修复版加入了 `IndexAny` 字符类拒绝，finding 消失。

### 4.4 风险
- 强弱校验表是一份需要维护的安全知识。为避免“对着考题写答案”，**表的初版只能根据公开的通用资料和 CWE 条目来写**，每条都注明出处；评估前冻结。
- 按字段名推断用途容易误报，因此单独统计。

## 5. 需要修改的文件

| 文件 | 改动 |
|---|---|
| `ast_analyzer/main.go` | 输出 params、entry_kind、call_sites、param_uses；新增 sink 类型 `alloc_size`、`index_access`、`query_exec`、`redirect`；新增 sanitizer（ldap 转义、数值范围比较、`//` 前缀拒绝、字符类拒绝）；识别路由和处理器注册 |
| `param_taint.py`（新） | 污点不动点传播，生成 `param_external` source |
| `validator_rules.yaml`（新） | 强校验和弱校验模式表 |
| `decide.py` | 支持带 sink 的 R1 变体；实现 R3 校验函数契约判定；finding 增加 `rule_id`、`source_provenance` |
| `confidence.py` | 更新 CATEGORY_FLOW_HINTS；按来源为 `param_external` 打分 |
| `detect_vulns.py` | 在 Stage 1 之后调用 `param_taint`；增加 `--rules` 开关；`scan_info` 中按规则统计 finding 数 |
| `detect_extract.md` | **不改** |
| 知识库 / `build_vuln_db.py` | **不改** |

## 6. 测试
- **单元测试**：沿用各模块现有的 `--selftest` 风格，每条规则至少覆盖“报出”“被保护”“不相关”三种用例。测试代码用自己编写的最小 Go 片段，**不使用 exp2 的 10 个项目**。
- **回归测试**：`--rules v2` 在 exp2 的 20 个版本上，输出必须与 v2 逐字节一致。LLM 的提取结果从已有的运行中缓存复用，避免重复调用。
- **生效验证**：在 exp2 的 10 个项目上分别开启 R1、R2、R3，确认第 2.3、3.3、4.3 节的预期是否出现。**这一步只证明改动生效，不作为效果证据。**

## 7. 评估方案：5 个新仓库
- **选取**：沿用 exp1/exp2 的选取条件（C1–C13）。排除这 10 个项目和它们的同谱系项目；优先从候选池中“未核查（名额已满）”的项目和 vuln.go.dev 的新通告中选。**选取在 v3 规则冻结之后进行，由作者确认名单**，以免规则受到评估集的影响。
- **对比组**：v2 与 v3。可选再加 A0 作为参照。每组跑 2 轮，汇总规则与 exp2 一致（两轮都命中才算命中）。
- **指标**：与 exp2 相同（修复区域命中 + 盲审确认、严格口径、类别一致、告警量、成本）；另外按规则开关做消融，报告 R1、R2、R3 各自带来的命中和告警增量。
- **报告要求**：必须同时报告“命中增加”和“告警量增加”，不能只报前者。

## 8. 开发顺序（建议）
1. R1（改动最小，先验证框架：rule_id、开关、回归测试）；
2. R2 的 AST 输出部分，再做 `param_taint.py`，再做判定接入；
3. R3（依赖 R2 的外部可达判断）；
4. 冻结规则和表，然后选定 5 个新仓库，跑评估。

## 9. 待作者决定的问题
1. R2 的传播深度上限：4 跳是否合适？`name_dispatch` 是否默认开启？
2. R3 按字段名推断用途的规则，是否纳入默认规则，还是只作为可选项？
3. 5 个新仓库在漏洞形态上是否要有覆盖要求，比如至少包含一个参数传入型、一个校验函数型？这要在选取前定好。
4. 评估时是否再加 A0 作为参照组？
