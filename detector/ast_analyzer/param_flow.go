package main

// v3 R2: per-function facts for inter-procedural parameter taint.
//
// The analyzer only records intra-procedural facts: which parameters, request
// values and external sources reach each call argument and each dangerous
// sink. Resolving callees and propagating taint across functions (bounded
// hops, name dispatch) is done by param_taint.py, which sees all packages.
//
// Taint roots:
//   param:i  the function's i-th explicit parameter (receiver excluded)
//   entry    a request-typed parameter (*http.Request, *gin.Context ...), or a
//            non-context parameter of a func literal passed to a route
//            registration call
//   src      a value produced by an AST source pattern or a request accessor
//
// Kept in its own output field so the v2 decision path is unaffected.

import (
	"go/ast"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type ParamFlow struct {
	Function  string      `json:"function"`
	File      string      `json:"file"`
	Line      int         `json:"line"`
	RecvType  string      `json:"recv_type,omitempty"`
	Params    []ParamInfo `json:"params"`
	Variadic  bool        `json:"variadic,omitempty"`
	EntryKind string      `json:"entry_kind"` // http_handler | exported | internal
	CallSites []CallSite  `json:"call_sites,omitempty"`
	// v4: function values that escape (composite literal, field, argument of a
	// non-stdlib call); their parameters are supplied by whoever invokes them.
	CallbackRefs []CallSite `json:"callback_refs,omitempty"`
	// v4: every callee this function names (deduplicated, no lines / arguments), so
	// param_taint.py can tell which functions no module code calls.
	Callees    []CallSite       `json:"callees,omitempty"`
	TaintSinks []TaintSink      `json:"taint_sinks,omitempty"`
	Sanitizers []SanitizerPoint `json:"sanitizers,omitempty"`
	// v3 R3: result types, body end, and (validator-named functions only) the
	// calls and comparisons in the body, matched against validator_rules.json.
	Results    []string    `json:"results,omitempty"`
	EndLine    int         `json:"end_line,omitempty"`
	CheckFacts []CheckFact `json:"check_facts,omitempty"`
	// v3.2: roots of the returned values (call:L = result of a cross-package or
	// unresolved method call at line L, resolved by param_taint.py), those calls,
	// and the facts rule R5 compares across sibling handlers.
	ReturnRoots    []string    `json:"return_roots,omitempty"`
	RetCalls       []CallSite  `json:"ret_calls,omitempty"`
	RetParams      []int       `json:"ret_params,omitempty"` // v4: parameters that flow to the result
	Handler        bool        `json:"handler,omitempty"`
	PrincipalCheck bool        `json:"principal_check,omitempty"`
	ResourceAccess []CheckFact `json:"resource_access,omitempty"`
	// v4.2: handler closures registered inline (escaping function values with a
	// request-typed parameter), each with its own R5 facts; and the lines that hold
	// a call or a comparison, so a check the LLM reports can be corroborated.
	ClosureHandlers []ClosureHandler `json:"closure_handlers,omitempty"`
	CheckLines      []int            `json:"check_lines,omitempty"`
}

type ClosureHandler struct {
	Line           int         `json:"line"`
	EndLine        int         `json:"end_line"`
	PrincipalCheck bool        `json:"principal_check,omitempty"`
	ResourceAccess []CheckFact `json:"resource_access,omitempty"`
}

type CheckFact struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

type ParamInfo struct {
	Index    int    `json:"index"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	FirstUse int    `json:"first_use,omitempty"`
	// v4: the type's package (import path; "" = same package) and base name, for
	// the wire-struct lookup in param_taint.py; Dynamic = any / map[string]any / []any.
	TypePkg  string `json:"type_pkg,omitempty"`
	TypeBase string `json:"type_base,omitempty"`
	Dynamic  bool   `json:"dynamic,omitempty"`
}

// WireType (v4): a struct type with field tags. Tags exist to map an external
// representation onto the struct, so values of such types are decoded data.
type WireType struct {
	File string `json:"file"`
	Name string `json:"name"`
}

func collectWireTypes(files []fileInfo) []WireType {
	var out []WireType
	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}
		for _, decl := range fi.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				for _, f := range st.Fields.List {
					if f.Tag != nil {
						out = append(out, WireType{File: fi.relPath, Name: ts.Name.Name})
						break
					}
				}
			}
		}
	}
	return out
}

// typeInfo: package qualifier, base identifier and dynamic-ness of a parameter type.
func typeInfo(t ast.Expr, aliases map[string]string) (pkg, base string, dynamic bool) {
	for {
		switch x := t.(type) {
		case *ast.StarExpr:
			t = x.X
			continue
		case *ast.Ellipsis:
			t = x.Elt
			continue
		case *ast.ParenExpr:
			t = x.X
			continue
		case *ast.ArrayType:
			t = x.Elt
			continue
		case *ast.MapType:
			t = x.Value
			continue
		}
		break
	}
	switch x := t.(type) {
	case *ast.InterfaceType:
		return "", "", x.Methods == nil || len(x.Methods.List) == 0
	case *ast.Ident:
		return "", x.Name, x.Name == "any"
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return aliases[id.Name], x.Sel.Name, false
		}
	}
	return "", "", false
}

// isBasicTarget: the target of a type assertion is a basic or dynamic type, so the
// asserted value came out of an untyped container (decoded data).
func isBasicTarget(t ast.Expr) bool {
	_, base, dyn := typeInfo(t, nil)
	if dyn {
		return true
	}
	switch base {
	case "string", "bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
		"uint32", "uint64", "float32", "float64", "byte", "rune":
		return true
	}
	return false
}

// CallSite: Pkg is set for pkg.Func calls (import path); Recv is "self" when the
// receiver is the enclosing method's receiver, else the receiver expression.
type CallSite struct {
	Line  int       `json:"line"`
	Name  string    `json:"name"`
	Pkg   string    `json:"pkg,omitempty"`
	Recv  string    `json:"recv,omitempty"`
	NArgs int       `json:"nargs"`
	Args  []CallArg `json:"args,omitempty"`
}

type CallArg struct {
	Index int      `json:"index"`
	Roots []string `json:"roots"`
}

type TaintSink struct {
	Line    int      `json:"line"`
	Type    string   `json:"type"`
	Pattern string   `json:"pattern"`
	Roots   []string `json:"roots"`
}

var gateLdap = []string{"github.com/go-ldap/ldap", "gopkg.in/ldap.v2", "gopkg.in/ldap.v3"}
var gateSQL = []string{"database/sql", "github.com/jmoiron/sqlx"}
var gateGorm = []string{"gorm.io/gorm", "github.com/jinzhu/gorm"}

// Sinks R2 pairs with parameter taint. v2 dangerous sink types are reused from
// sinkPatterns (filtered by r2SinkTypes); these add query builders and redirects.
var r2ExtraSinks = []flowPattern{
	{"ldap.NewSearchRequest(", "query_exec", nil},
	{".Search(", "query_exec", gateLdap},
	{".Query(", "sql_query", gateSQL},
	{".QueryRow(", "sql_query", gateSQL},
	{".QueryContext(", "sql_query", gateSQL},
	{".QueryRowContext(", "sql_query", gateSQL},
	{".Exec(", "sql_exec", gateSQL},
	{".ExecContext(", "sql_exec", gateSQL},
	{".Where(", "query_exec", gateGorm},
	{".Raw(", "query_exec", gateGorm},
	{"http.Redirect(", "redirect", nil},
	// v3.1 outbound destination (SSRF) and R4 unbounded reads
	{"http.NewRequestWithContext(", "http_request", nil},
	{"http.Head(", "http_request", nil},
	{"http.PostForm(", "http_request", nil},
	{"net.Dial(", "http_request", nil},
	{"net.DialTimeout(", "http_request", nil},
	// v4: external data becoming the path / query component of a URL object
	{".ResolveReference(", "url_path", nil},
	{".JoinPath(", "url_path", nil},
	{"io.ReadAll(", "unbounded_read", nil},
	// v4.3: a stream decoder built over a reader consumes the whole input (CWE-400)
	{".NewDecoder(", "unbounded_read", nil},
	{"ioutil.ReadAll(", "unbounded_read", nil},
	{"io.Copy(", "unbounded_read", nil},
	{".ReadFrom(", "unbounded_read", nil},
	{"c.Redirect(", "redirect", gateGinEcho},
}

// Which arguments of a sink carry the dangerous value; absent = all arguments.
// Bind parameters of SQL calls, the request/writer of http.Redirect and the data
// of os.WriteFile are not injection points.
var sinkArgIndex = map[string][]int{
	".Query(": {0}, ".QueryRow(": {0}, ".Exec(": {0},
	".QueryContext(": {1}, ".QueryRowContext(": {1}, ".ExecContext(": {1},
	".Where(": {0}, ".Raw(": {0},
	"http.Redirect(": {2}, "c.Redirect(": {1},
	"os.Create(": {0}, "os.Open(": {0}, "os.OpenFile(": {0}, "os.WriteFile(": {0},
	"os.MkdirAll(": {0}, "os.Stat(": {0}, "os.ReadFile(": {0}, "ioutil.ReadFile(": {0},
	"os.Chmod(": {0}, "os.Rename(": {0, 1}, "os.RemoveAll(": {0},
	"http.Get(": {0}, "http.Post(": {0}, "http.Head(": {0}, "http.PostForm(": {0},
	"http.NewRequest(": {1}, "http.NewRequestWithContext(": {2},
	"net.Dial(": {1}, "net.DialTimeout(": {1},
	"io.ReadAll(": {0}, "ioutil.ReadAll(": {0}, "io.Copy(": {1}, ".ReadFrom(": {0}, ".NewDecoder(": {0},
	".ResolveReference(": {0},
}

var r2SinkTypes = map[string]bool{
	"command_execution": true, "sql_query": true, "sql_exec": true,
	"file_read": true, "file_write": true, "html_injection": true, "js_injection": true,
	"http_request": true,
}

var r2Sanitizers = []struct {
	pattern  string
	category string
}{
	{"ldap.EscapeFilter(", "output_encoding"},
	{"ldap.EscapeDN(", "output_encoding"},
	// v3.2: context escaping (XSS / URL path)
	{"html.EscapeString(", "output_encoding"},
	{"template.HTMLEscapeString(", "output_encoding"},
	{"template.JSEscapeString(", "output_encoding"},
	{"url.PathEscape(", "output_encoding"},
	{"url.QueryEscape(", "output_encoding"},
}

// Accessors on an HTTP request whose result is attacker-controlled. Matched on
// the call text so that a request stored in a struct field (ctx.req.BasicAuth())
// still counts.
var requestAccessors = []string{
	".BasicAuth(", ".FormValue(", ".PostFormValue(", ".URL.Query(", ".Header.Get(",
	".Header.Values(", ".Cookie(", ".Cookies(", ".PathValue(", ".MultipartForm(",
	".FormFile(",
	// Kubernetes object metadata is written by whoever creates the object
	".GetAnnotations(", ".GetLabels(",
}

// Parameter types that make a function an HTTP entry point.
var requestTypes = []string{
	"*http.Request", "*gin.Context", "echo.Context", "*fiber.Ctx", "*context.Context",
	"*fasthttp.RequestCtx",
}

var versionElem = regexp.MustCompile(`^v[0-9]+$`)

// v3 R3: validator-like function names. Calls to them mark their result (vret:L)
// and their arguments (varg:L) so the caller's sinks reveal what the check is for.
var validatorName = regexp.MustCompile(`^(?i:validate|valid|check|verify|sanitize)|^(?:is|Is)[A-Z].*(?:Valid|Allowed|Safe)`)

func importAliases(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			if imp.Name.Name != "_" && imp.Name.Name != "." {
				out[imp.Name.Name] = path
			}
			continue
		}
		parts := strings.Split(path, "/")
		name := parts[len(parts)-1]
		if versionElem.MatchString(name) && len(parts) > 1 {
			name = parts[len(parts)-2]
		}
		name = strings.TrimPrefix(name, "go-")
		if i := strings.IndexAny(name, ".-"); i > 0 {
			name = name[:i]
		}
		out[name] = path
	}
	return out
}

func isRequestType(t string) bool {
	for _, r := range requestTypes {
		if t == r {
			return true
		}
	}
	return false
}

func isObjectType(t string) bool {
	return isRequestType(t) || t == "http.ResponseWriter" || t == "context.Context"
}

func paramList(fset *token.FileSet, ft *ast.FuncType, aliases map[string]string) ([]ParamInfo, bool) {
	ps := []ParamInfo{}
	variadic := false
	if ft == nil || ft.Params == nil {
		return ps, false
	}
	for _, field := range ft.Params.List {
		t := exprText(fset, field.Type)
		if _, ok := field.Type.(*ast.Ellipsis); ok {
			variadic = true
		}
		pkg, base, dyn := typeInfo(field.Type, aliases)
		mk := func(name string) ParamInfo {
			return ParamInfo{Index: len(ps), Name: name, Type: t, TypePkg: pkg, TypeBase: base, Dynamic: dyn}
		}
		if len(field.Names) == 0 {
			ps = append(ps, mk("_"))
			continue
		}
		for _, n := range field.Names {
			ps = append(ps, mk(n.Name))
		}
	}
	return ps, variadic
}

type rootSet map[string]bool

func (r rootSet) sorted() []string {
	out := make([]string, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type taintCtx struct {
	fset    *token.FileSet
	env     map[string]rootSet
	sources []flowPattern
	pkgs    map[string]string // import aliases: package names never carry taint
	objects map[string]bool   // request / writer / context parameters: never "the validated value"
	// v3.1: same-package functions whose return value carries external input
	// (keyed by qualName), and the enclosing method's receiver for self calls.
	retOrig   map[string]rootSet // v4: origin roots a same-package callee returns
	retParams map[string][]int   // v4: parameters a same-package callee passes through
	recvName  string
	recvType  string
	// v3.2: definitions of local names (for URL / query string builds), and
	// http.ResponseWriter parameters
	defs    map[string][]ast.Expr
	appends map[string][]ast.Expr
	writers map[string]bool
}

// v3.2: callee names whose pointer arguments receive decoded data from the
// other arguments or the receiver (json.Unmarshal(data, &v), dec.Decode(&v), c.Bind(&v)).
var decodeNames = map[string]bool{
	"Unmarshal": true, "Decode": true, "ReadJSON": true, "UnmarshalJSON": true,
	"Execute": true, "ExecuteTemplate": true, // template rendering writes data into its writer argument
	"Bind": true, "BindJSON": true, "BindQuery": true, "ShouldBind": true, "ShouldBindJSON": true,
	"ShouldBindQuery": true, "ShouldBindUri": true, "BodyParser": true, "DecodeElement": true,
}

// v3.2: query-like calls; a string-built argument carrying external input is an
// injection point (CWE-943) whatever the query language.
var queryCallName = regexp.MustCompile(`^(?i:query|queryrow|querycontext|queryrowcontext|exec|execcontext|execute|search|raw|where|run|eval|mutate|newquery|do|dql|gql)$`)

// v3.2 R5 facts: a call that establishes the caller's identity or checks authorization,
// and data access by an identifier taken from the request.
var principalCall = regexp.MustCompile(`^(?i:(must|require)?(have|get|current)?(user|principal|identity|claims|subject|caller|session|tenant)(from\w*|context)?)$|(?i:authoriz|permission|enforce|checkaccess|canaccess|isowner|isallowed|rbac|verifyaccess)`)
var accessCall = regexp.MustCompile(`^(?i:get|find|load|fetch|read|update|delete|remove|patch|save|put|download|upload|list|describe|export)`)
var requestIDExpr = regexp.MustCompile(`^(?i:request|req|input|params|in|body|args|r|c)\.([A-Za-z_]+\.)*[A-Za-z_]*(Id|ID|Ids|IDs)$`)
var idWord = regexp.MustCompile(`(?i)(^|[^a-z])ids?([^a-z]|$)|Ids?$|IDs?$`)

func isStdlibPath(p string) bool { return isStdlib(p) }

// v3.1: only network-origin sources are external for R2/R4 (stdin, files and
// generic decoders are local or of unknown origin).
var netSourceTypes = map[string]bool{
	"http_request": true, "http_body": true, "read_message": true,
	"network_read": true, "network_accept": true,
}

// v3.1 R4: readers that bound what can be read, and decompressors that undo
// such a bound (a limited compressed stream still expands without limit).
var limiterCalls = []string{"io.LimitReader(", "http.MaxBytesReader(", "io.NewSectionReader("}
var decompressor = regexp.MustCompile(`\b(gzip|zlib|flate|lzw|bzip2|brotli|zstd|snappy|xz|lz4|s2)\.NewReader`)

// v3.3: outbound HTTP calls whose result is a response from a remote server.
// Get/Post/Head/PostForm methods count only on receivers named like a client
// (they are too common otherwise: maps, caches, url.Values).
var clientRecv = regexp.MustCompile(`(?i)client`)

func isOutboundCall(c *ast.CallExpr) bool {
	switch exprToString(c.Fun) {
	case "http.Get", "http.Post", "http.Head", "http.PostForm":
		return true
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Do", "RoundTrip":
		return true
	case "Get", "Post", "Head", "PostForm":
		return clientRecv.MatchString(exprToString(sel.X))
	}
	return false
}

// onResponse: an accessor (Header.Get, Cookie ...) called on a response value;
// response headers are the remote server's, not request input.
func (tc *taintCtx) onResponse(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	rs := tc.env[baseIdent(sel.X)]
	return rs["resp"] && !rs["entry"]
}

// v3.1: assigning to these fields sets the destination of an outbound
// connection (client configs, URLs): SSRF when the value is attacker-chosen.
var destFields = map[string]bool{
	"Address": true, "Addr": true, "URL": true, "Url": true, "BaseURL": true, "BaseUrl": true,
	"Endpoint": true, "Host": true, "ServerURL": true,
}

// isGenerated: the Go convention for generated files (golang.org/s/generatedcode).
var generatedHeader = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)

func isGenerated(f *ast.File) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if generatedHeader.MatchString(c.Text) {
				return true
			}
		}
	}
	return false
}

func hasAny(code string, pats []string) bool {
	for _, p := range pats {
		if strings.Contains(code, p) {
			return true
		}
	}
	return false
}

// crossCall: a call whose result param_taint.py may resolve (a non-stdlib package
// function, or a method on a receiver other than the enclosing method's own).
func (tc *taintCtx) crossCall(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if p, isPkg := tc.pkgs[id.Name]; isPkg {
			return !isStdlibPath(p)
		}
		if tc.recvName != "" && id.Name == tc.recvName {
			return false
		}
	}
	if tc.env[baseIdent(sel.X)]["resp"] {
		return false // v3.3: methods of a response object (Header.Get, Cookies ...)
	}
	return true
}

// calleeKey: qualName of a same-package callee, or "" when it cannot be named.
func (tc *taintCtx) calleeKey(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok && tc.recvName != "" && id.Name == tc.recvName {
			return tc.recvType + "." + f.Sel.Name
		}
	}
	return ""
}

func callText(c *ast.CallExpr) string { return exprToString(c.Fun) + "(" }

// sourceClass (v4): "src" for network input, "io" for any other read / decode of
// data from outside the process (files, pipes, decoders); "" otherwise. The
// process's own console (os.Stdin) is the operator's, not data it was handed.
func (tc *taintCtx) sourceClass(c *ast.CallExpr) string {
	code := callText(c)
	for _, a := range requestAccessors {
		if strings.Contains(code, a) {
			return "src"
		}
	}
	for _, sp := range tc.sources {
		// type-only patterns ("http.Request", ".Body") describe values, not calls
		if !strings.HasSuffix(sp.pattern, "(") || !strings.Contains(code, sp.pattern) {
			continue
		}
		if netSourceTypes[sp.fType] {
			return "src"
		}
		for _, a := range c.Args {
			if exprToString(a) == "os.Stdin" {
				return ""
			}
		}
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok && exprToString(sel.X) == "os.Stdin" {
			return ""
		}
		return "io"
	}
	return ""
}

// rootsOf: roots reaching an expression.
func (tc *taintCtx) rootsOf(e ast.Node) rootSet {
	out := rootSet{}
	if e == nil {
		return out
	}
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.SelectorExpr:
			for r := range tc.rootsOf(x.X) {
				out[r] = true
			}
			if x.Sel.Name == "Body" {
				// HTTP body: a request body already carries "entry" through its base;
				// a response body is external only once decompressed (see R4)
				out["body"] = true
			}
			return false
		case *ast.KeyValueExpr:
			if _, ok := x.Key.(*ast.Ident); !ok {
				for r := range tc.rootsOf(x.Key) {
					out[r] = true
				}
			}
			for r := range tc.rootsOf(x.Value) {
				out[r] = true
			}
			return false
		case *ast.Ident:
			for r := range tc.env[x.Name] {
				out[r] = true
			}
		case *ast.TypeAssertExpr:
			// v4: a value asserted from an interface to a basic / dynamic type came
			// out of an untyped container: decoded data
			inner := tc.rootsOf(x.X)
			for r := range inner {
				out[r] = true
			}
			// a projection of a value we already track keeps that value's roots; only
			// an untyped container of unknown provenance is new decoded data
			if len(inner) == 0 && x.Type != nil && isBasicTarget(x.Type) {
				out["wire"] = true
			}
			return false
		case *ast.CallExpr:
			if isR2Sanitizer(callText(x)) {
				return false // escaped value: taint stops here
			}
			if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "len" || id.Name == "cap") {
				return false // a size of existing data is not attacker-chosen
			}
			code := callText(x)
			if isOutboundCall(x) {
				// v3.3: a response carries the remote server's data, not the
				// request's arguments (a client built from the request does not
				// make its responses attacker input)
				out["resp"] = true
				return false
			}
			if hasAny(code, limiterCalls) || decompressor.MatchString(code) {
				lim := hasAny(code, limiterCalls)
				for _, a := range x.Args {
					for r := range tc.rootsOf(a) {
						if r != "lim" {
							out[r] = true
						}
					}
				}
				if lim {
					out["lim"] = true
				} else {
					out["decomp"] = true
				}
				return false
			}
			if cls := tc.sourceClass(x); cls != "" && !tc.onResponse(x) {
				out[cls] = true
			}
			if k := tc.calleeKey(x.Fun); k != "" {
				for r := range tc.retOrig[k] {
					out[r] = true
				}
				// v4: pass-through — the callee returns (something derived from) these arguments
				for _, i := range tc.retParams[k] {
					if i < len(x.Args) {
						for r := range tc.rootsOf(x.Args[i]) {
							out[r] = true
						}
					}
				}
			}
			if tc.crossCall(x) {
				out["call:"+strconv.Itoa(tc.fset.Position(x.Pos()).Line)] = true
			}
		}
		return true
	})
	return out
}

// ── v3.2 helpers: string-built URLs and queries ──────────────────────────

func litString(e ast.Expr) (string, bool) {
	if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
		if v, err := strconv.Unquote(bl.Value); err == nil {
			return v, true
		}
	}
	return "", false
}

func flattenAdd(e ast.Expr, out []ast.Expr) []ast.Expr {
	if be, ok := e.(*ast.BinaryExpr); ok && be.Op == token.ADD {
		return flattenAdd(be.Y, flattenAdd(be.X, out))
	}
	if pe, ok := e.(*ast.ParenExpr); ok {
		return flattenAdd(pe.X, out)
	}
	return append(out, e)
}

func isSprintf(c *ast.CallExpr) bool {
	t := exprToString(c.Fun)
	return t == "fmt.Sprintf" || t == "fmt.Sprint"
}

// urlSplit: for a scheme-prefixed URL built with fmt.Sprintf or string
// concatenation, the roots that land in the authority (host[:port]) and those
// that land in the path / query. ok is false when e is not such a build.
func (tc *taintCtx) urlSplit(e ast.Expr, depth int) (auth, path rootSet, ok bool) {
	auth, path = rootSet{}, rootSet{}
	add := func(dst, src rootSet) {
		for r := range src {
			dst[r] = true
		}
	}
	switch x := e.(type) {
	case *ast.Ident:
		if depth > 2 {
			return auth, path, false
		}
		for _, d := range tc.defs[x.Name] {
			if a, p, k := tc.urlSplit(d, depth+1); k {
				add(auth, a)
				add(path, p)
				ok = true
			}
		}
		if ok {
			for _, d := range tc.appends[x.Name] {
				add(path, tc.rootsOf(d))
			}
		}
		return auth, path, ok
	case *ast.CallExpr:
		if !isSprintf(x) || len(x.Args) == 0 {
			return auth, path, false
		}
		f, isLit := litString(x.Args[0])
		i := strings.Index(f, "://")
		if !isLit || i < 0 {
			return auth, path, false
		}
		// after "://": the first verb is the host, a verb right after ':' is the port;
		// anything after a '/' or '?', or a further verb, is path / query
		arg, hostSeen, inPath := 1, false, false
		for k := 0; k < len(f); k++ {
			if k > i+2 && (f[k] == '/' || f[k] == '?') {
				inPath = true
			}
			if f[k] != '%' {
				continue
			}
			if k+1 < len(f) && f[k+1] == '%' {
				k++
				continue
			}
			isAuth := false
			if k < i {
				isAuth = true // scheme verb
			} else if !inPath {
				if !hostSeen {
					isAuth, hostSeen = true, true
				} else if f[k-1] == ':' {
					isAuth = true
				} else {
					inPath = true
				}
			}
			if arg < len(x.Args) {
				if isAuth {
					add(auth, tc.rootsOf(x.Args[arg]))
				} else {
					add(path, tc.rootsOf(x.Args[arg]))
				}
			}
			arg++
		}
		return auth, path, true
	case *ast.BinaryExpr:
		parts := flattenAdd(x, nil)
		seenScheme, inPath := false, false
		for _, p := range parts {
			if v, isLit := litString(p); isLit {
				if !seenScheme {
					if i := strings.Index(v, "://"); i >= 0 {
						seenScheme = true
						if strings.ContainsAny(v[i+3:], "/?") {
							inPath = true
						}
					}
				} else if strings.ContainsAny(v, "/?") {
					inPath = true
				}
				continue
			}
			if !seenScheme {
				return rootSet{}, rootSet{}, false
			}
			if inPath {
				add(path, tc.rootsOf(p))
			} else {
				add(auth, tc.rootsOf(p))
			}
		}
		return auth, path, seenScheme
	}
	return auth, path, false
}

// builtString: e (or the local it names) is built with fmt.Sprintf or by
// concatenating a string literal with other values.
func (tc *taintCtx) builtString(e ast.Expr, depth int) bool {
	switch x := e.(type) {
	case *ast.Ident:
		if depth > 2 {
			return false
		}
		for _, d := range tc.defs[x.Name] {
			if tc.builtString(d, depth+1) {
				return true
			}
		}
		return len(tc.appends[x.Name]) > 0
	case *ast.CallExpr:
		return isSprintf(x)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return false
		}
		for _, p := range flattenAdd(x, nil) {
			if _, ok := litString(p); ok {
				return true
			}
		}
	}
	return false
}

// safeContentType: the function sets a non-HTML Content-Type on a response.
func safeContentType(body *ast.BlockStmt) bool {
	safe := false
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) < 2 {
			return true
		}
		if t := exprToString(c.Fun); !strings.HasSuffix(t, ".Header().Set") && !strings.HasSuffix(t, ".Header().Add") {
			return true
		}
		k, ok1 := litString(c.Args[0])
		v, ok2 := litString(c.Args[1])
		if ok1 && strings.EqualFold(k, "Content-Type") && (!ok2 || !strings.Contains(strings.ToLower(v), "html")) {
			safe = true
		}
		return true
	})
	return safe
}

func matchedPattern(code string, pats []flowPattern) string {
	for _, sk := range pats {
		if strings.Contains(code, sk.pattern) {
			return sk.pattern
		}
	}
	return ""
}

// resourceAccess (R5): a data-access call whose argument is an identifier taken
// from the request.
func (tc *taintCtx) resourceAccess(fset *token.FileSet, c *ast.CallExpr) (CheckFact, bool) {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || !accessCall.MatchString(sel.Sel.Name) {
		return CheckFact{}, false
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if _, isPkg := tc.pkgs[id.Name]; isPkg {
			return CheckFact{}, false
		}
	}
	for _, a := range c.Args {
		t := exprText(fset, a)
		rs := tc.rootsOf(a)
		if requestIDExpr.MatchString(t) || (idWord.MatchString(t) && (rs["entry"] || rs["src"])) {
			return CheckFact{Line: fset.Position(c.Pos()).Line, Text: truncate(exprText(fset, c), 120)}, true
		}
	}
	return CheckFact{}, false
}

func isStmtReceiver(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(exprToString(sel.X)), "stmt")
}

func isR2Sanitizer(code string) bool {
	if retainProtectionHypotheses {
		return false
	}
	for _, sa := range r2Sanitizers {
		if strings.Contains(code, sa.pattern) {
			return true
		}
	}
	return false
}

// baseIdent: x for x, x.F, x[i], *x, &x.F.
func baseIdent(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.Ident:
			if x.Name == "_" {
				return ""
			}
			return x.Name
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.UnaryExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		default:
			return ""
		}
	}
}

func (tc *taintCtx) addRoots(name string, rs rootSet) bool {
	if name == "" || len(rs) == 0 {
		return false
	}
	if _, isPkg := tc.pkgs[name]; isPkg {
		return false
	}
	if tc.objects[name] && tc.env[name] != nil {
		// request / writer / context: seeded once; r = r.WithContext(...) must not
		// turn the request into a carrier of every value stored in its context.
		// A body limit (r.Body = http.MaxBytesReader(...)) is still recorded.
		if rs["lim"] && !tc.env[name]["lim"] {
			tc.env[name]["lim"] = true
			return true
		}
		return false
	}
	cur := tc.env[name]
	if cur == nil {
		cur = rootSet{}
		tc.env[name] = cur
	}
	changed := false
	for r := range rs {
		if !cur[r] {
			cur[r] = true
			changed = true
		}
	}
	return changed
}

func selName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// seedFuncLits: parameters of handler func literals are external input.
// stdlibCallee: the call is pkg.Func on a standard-library package.
func (tc *taintCtx) stdlibCallee(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if p, isPkg := tc.pkgs[id.Name]; isPkg {
			return isStdlibPath(p)
		}
	}
	return false
}

// escapingValues (v4): expressions whose value is handed to code that will call
// it later — elements of composite literals, values stored into fields or
// indexed slots, and arguments of non-stdlib calls. A function value in such a
// position is invoked by someone else with arguments the program did not choose.
func (tc *taintCtx) escapingValues(body ast.Node) []ast.Expr {
	var out []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			for _, e := range x.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					out = append(out, kv.Value)
				} else {
					out = append(out, e)
				}
			}
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					switch l.(type) {
					case *ast.SelectorExpr, *ast.IndexExpr:
						out = append(out, x.Rhs[i])
					}
				}
			}
		case *ast.CallExpr:
			if _, isLit := x.Fun.(*ast.FuncLit); isLit || tc.stdlibCallee(x) {
				return true
			}
			if id, ok := x.Fun.(*ast.Ident); ok && (isBuiltin(id.Name) || isTypeConversion(id.Name)) {
				return true
			}
			out = append(out, x.Args...)
		}
		return true
	})
	return out
}

func (tc *taintCtx) seedFuncLits(body ast.Node) {
	escaping := map[*ast.FuncLit]bool{}
	for _, e := range tc.escapingValues(body) {
		if fl, ok := e.(*ast.FuncLit); ok {
			escaping[fl] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		fl, ok := n.(*ast.FuncLit)
		if !ok {
			return true
		}
		ps, _ := paramList(tc.fset, fl.Type, tc.pkgs)
		for _, p := range ps {
			if p.Name == "_" {
				continue
			}
			if isObjectType(p.Type) {
				tc.objects[p.Name] = true
			}
			switch {
			case isRequestType(p.Type):
				tc.addRoots(p.Name, rootSet{"entry": true})
			case escaping[fl] && !isObjectType(p.Type):
				tc.addRoots(p.Name, rootSet{"cb": true})
			}
		}
		return true
	})
}

// seedValidatorCalls: v := validateX(a) marks v with vret:L and a with varg:L.
func (tc *taintCtx) seedValidatorCalls(body ast.Node) {
	mark := func(c *ast.CallExpr, lhs ast.Expr) {
		if !validatorName.MatchString(selName(c.Fun)) {
			return
		}
		l := strconv.Itoa(tc.fset.Position(c.Pos()).Line)
		for _, a := range c.Args {
			if b := baseIdent(a); !tc.objects[b] {
				tc.addRoots(b, rootSet{"varg:" + l: true})
			}
		}
		if lhs != nil {
			tc.addRoots(baseIdent(lhs), rootSet{"vret:" + l: true})
		}
	}
	assigned := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && len(as.Lhs) > 0 {
			if c, ok := as.Rhs[0].(*ast.CallExpr); ok {
				assigned[c] = true
				mark(c, as.Lhs[0])
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && !assigned[c] {
			mark(c, nil)
		}
		return true
	})
}

// propagate: flow-insensitive def-use over assignments, var specs and range
// statements, to a fixed point (bounded).
func (tc *taintCtx) propagate(body ast.Node) {
	for pass := 0; pass < 6; pass++ {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) == len(x.Rhs) {
					for i := range x.Lhs {
						if tc.addRoots(baseIdent(x.Lhs[i]), tc.rootsOf(x.Rhs[i])) {
							changed = true
						}
					}
				} else if len(x.Rhs) == 1 && len(x.Lhs) > 0 {
					// a, b, err := f(x): every result but err / ok may carry the value
					rs := tc.rootsOf(x.Rhs[0])
					for _, l := range x.Lhs {
						if b := baseIdent(l); b != "err" && b != "ok" && tc.addRoots(b, rs) {
							changed = true
						}
					}
				}
			case *ast.CallExpr:
				// json.Unmarshal(data, &v) / dec.Decode(&v): v receives the decoded input
				if decodeNames[selName(x.Fun)] {
					rs := rootSet{}
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
						for r := range tc.rootsOf(sel.X) {
							rs[r] = true
						}
					}
					for _, a := range x.Args {
						for r := range tc.rootsOf(a) {
							rs[r] = true
						}
					}
					for _, a := range x.Args {
						if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND {
							if tc.addRoots(baseIdent(u.X), rs) {
								changed = true
							}
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range x.Names {
					if i < len(x.Values) && tc.addRoots(name.Name, tc.rootsOf(x.Values[i])) {
						changed = true
					}
				}
			case *ast.RangeStmt:
				rs := tc.rootsOf(x.X)
				for _, k := range []ast.Expr{x.Key, x.Value} {
					if k != nil && tc.addRoots(baseIdent(k), rs) {
						changed = true
					}
				}
			}
			return true
		})
		if !changed {
			return
		}
	}
}

// buildTaint: intra-procedural taint environment of one function body.
func buildTaint(fset *token.FileSet, sources []flowPattern, aliases map[string]string, params []ParamInfo,
	body *ast.BlockStmt, recvName, recvType string, retOrig map[string]rootSet, retParams map[string][]int) *taintCtx {
	tc := &taintCtx{fset: fset, env: map[string]rootSet{}, sources: sources, pkgs: aliases,
		objects: map[string]bool{}, retOrig: retOrig, retParams: retParams, recvName: recvName, recvType: recvType,
		defs: map[string][]ast.Expr{}, appends: map[string][]ast.Expr{}, writers: map[string]bool{}}
	for _, p := range params {
		if isObjectType(p.Type) {
			tc.objects[p.Name] = true
		}
		if p.Type == "http.ResponseWriter" {
			tc.writers[p.Name] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, l := range x.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						if x.Tok == token.ADD_ASSIGN {
							tc.appends[id.Name] = append(tc.appends[id.Name], x.Rhs[i])
						} else {
							tc.defs[id.Name] = append(tc.defs[id.Name], x.Rhs[i])
						}
					}
				}
			}
		case *ast.ValueSpec:
			for i, nm := range x.Names {
				if i < len(x.Values) {
					tc.defs[nm.Name] = append(tc.defs[nm.Name], x.Values[i])
				}
			}
		}
		return true
	})
	for _, p := range params {
		if p.Name == "_" {
			continue
		}
		if isRequestType(p.Type) {
			tc.addRoots(p.Name, rootSet{"entry": true})
		} else if p.Type == "*http.Response" {
			tc.addRoots(p.Name, rootSet{"resp": true}) // v3.3: a response object, not request input
		} else {
			tc.addRoots(p.Name, rootSet{"param:" + strconv.Itoa(p.Index): true})
		}
	}
	tc.seedFuncLits(body)
	tc.seedValidatorCalls(body)
	tc.propagate(body)
	return tc
}

var originRoots = map[string]bool{"src": true, "entry": true, "wire": true, "io": true, "cb": true}

// returnSummary (v4): the origin roots and the parameter indices that reach a
// return statement of body (closures excluded).
func (tc *taintCtx) returnSummary(body *ast.BlockStmt) (rootSet, []int) {
	orig := rootSet{}
	params := map[int]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				for k := range tc.rootsOf(r) {
					if originRoots[k] {
						orig[k] = true
					} else if strings.HasPrefix(k, "param:") {
						if i, err := strconv.Atoi(k[6:]); err == nil {
							params[i] = true
						}
					}
				}
			}
		}
		return true
	})
	idx := make([]int, 0, len(params))
	for i := range params {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return orig, idx
}

type funcSite struct {
	fi                 fileInfo
	name               string
	line               int
	ft                 *ast.FuncType
	body               *ast.BlockStmt
	recvName, recvType string
}

func collectFuncSites(fset *token.FileSet, files []fileInfo) []funcSite {
	var out []funcSite
	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}
		for _, decl := range fi.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				recvName := ""
				if d.Recv != nil && len(d.Recv.List) > 0 && len(d.Recv.List[0].Names) > 0 {
					recvName = d.Recv.List[0].Names[0].Name
				}
				out = append(out, funcSite{fi, qualName(d), fset.Position(d.Pos()).Line, d.Type, d.Body, recvName, recvBase(d)})
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							if fl, ok := vs.Values[i].(*ast.FuncLit); ok {
								out = append(out, funcSite{fi, name.Name, fset.Position(fl.Pos()).Line, fl.Type, fl.Body, "", ""})
							}
						}
					}
				}
			}
		}
	}
	return out
}

// packageReturnSummaries: fixed point (bounded) of "returns external input" over
// the package's functions, so a caller of such a function sees a source.
func packageReturnSummaries(fset *token.FileSet, sites []funcSite) (map[string]rootSet, map[string][]int) {
	retOrig := map[string]rootSet{}
	retParams := map[string][]int{}
	for round := 0; round < 4; round++ {
		changed := false
		for _, fs := range sites {
			if fs.body == nil || fs.ft.Results == nil {
				continue
			}
			imports := make(map[string]bool)
			for _, imp := range fs.fi.file.Imports {
				imports[strings.Trim(imp.Path.Value, `"`)] = true
			}
			aliases := importAliases(fs.fi.file)
			params, _ := paramList(fset, fs.ft, aliases)
			tc := buildTaint(fset, gatePatterns(sourcePatterns, imports), aliases, params,
				fs.body, fs.recvName, fs.recvType, retOrig, retParams)
			orig, idx := tc.returnSummary(fs.body)
			if len(orig) > len(retOrig[fs.name]) || len(idx) > len(retParams[fs.name]) {
				retOrig[fs.name], retParams[fs.name] = orig, idx
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return retOrig, retParams
}

func extractParamFlows(fset *token.FileSet, files []fileInfo, focusFuncs []string) []ParamFlow {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}
	retOrig, retParams := packageReturnSummaries(fset, collectFuncSites(fset, files))
	var flows []ParamFlow
	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") || isGenerated(fi.file) {
			continue
		}
		fileImports := make(map[string]bool)
		for _, imp := range fi.file.Imports {
			fileImports[strings.Trim(imp.Path.Value, `"`)] = true
		}
		aliases := importAliases(fi.file)
		activeSources := gatePatterns(sourcePatterns, fileImports)
		var activeSinks []flowPattern
		for _, sp := range gatePatterns(sinkPatterns, fileImports) {
			if r2SinkTypes[sp.fType] {
				activeSinks = append(activeSinks, sp)
			}
		}
		activeSinks = append(activeSinks, gatePatterns(r2ExtraSinks, fileImports)...)

		visit := func(name string, line int, ft *ast.FuncType, body *ast.BlockStmt, recvName, recvType string) {
			if body == nil || (len(focusFuncs) > 0 && !focusSet[bareName(name)]) {
				return
			}
			pf := ParamFlow{Function: name, File: fi.relPath, Line: line, RecvType: recvType}
			pf.Params, pf.Variadic = paramList(fset, ft, aliases)
			if ft.Results != nil {
				for _, r := range ft.Results.List {
					n := len(r.Names)
					if n == 0 {
						n = 1
					}
					for k := 0; k < n; k++ {
						pf.Results = append(pf.Results, exprText(fset, r.Type))
					}
				}
			}
			pf.EndLine = fset.Position(body.Rbrace).Line
			if validatorName.MatchString(bareName(name)) {
				ast.Inspect(body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.FuncLit:
						return false
					case *ast.CallExpr:
						pf.CheckFacts = append(pf.CheckFacts, CheckFact{Line: fset.Position(x.Pos()).Line,
							Text: truncate(exprText(fset, x), 160)})
					case *ast.BinaryExpr:
						switch x.Op {
						case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
							pf.CheckFacts = append(pf.CheckFacts, CheckFact{Line: fset.Position(x.Pos()).Line,
								Text: truncate(exprText(fset, x), 160)})
						}
					case *ast.CaseClause:
						for _, e := range x.List {
							pf.CheckFacts = append(pf.CheckFacts, CheckFact{Line: fset.Position(e.Pos()).Line,
								Text: truncate(exprText(fset, e), 160)})
						}
					}
					return true
				})
			}
			tc := buildTaint(fset, activeSources, aliases, pf.Params, body, recvName, recvType, retOrig, retParams)
			pf.EntryKind = "internal"
			if ast.IsExported(bareName(name)) {
				pf.EntryKind = "exported"
			}
			for _, p := range pf.Params {
				if p.Name != "_" && isRequestType(p.Type) {
					pf.EntryKind = "http_handler"
				}
			}
			// first use of each parameter
			idx := map[string]int{}
			for i, p := range pf.Params {
				idx[p.Name] = i
			}
			fieldNames := map[*ast.Ident]bool{}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					fieldNames[x.Sel] = true
				case *ast.KeyValueExpr:
					if k, ok := x.Key.(*ast.Ident); ok {
						fieldNames[k] = true
					}
				}
				return true
			})
			ast.Inspect(body, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && !fieldNames[id] {
					if i, ok := idx[id.Name]; ok && id.Name != "_" {
						l := fset.Position(id.Pos()).Line
						if pf.Params[i].FirstUse == 0 || l < pf.Params[i].FirstUse {
							pf.Params[i].FirstUse = l
						}
					}
				}
				return true
			})
			safeCT := !retainProtectionHypotheses && safeContentType(body)
			seenCallee := map[string]bool{}
			if pf.EntryKind == "http_handler" {
				pf.Handler = true
			} else if len(pf.Params) >= 2 && pf.Params[0].Type == "context.Context" {
				t := pf.Params[1].Type
				n := strings.ToLower(pf.Params[1].Name)
				if n == "request" || n == "req" || n == "input" || n == "params" || n == "in" ||
					strings.HasSuffix(t, "Request") || strings.HasSuffix(t, "RequestObject") ||
					strings.HasSuffix(t, "Input") || strings.HasSuffix(t, "Params") {
					pf.Handler = true
				}
			}
			ret := rootSet{}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						for k := range tc.rootsOf(r) {
							ret[k] = true
						}
					}
				}
				return true
			})
			pf.ReturnRoots = ret.sorted()
			for r := range ret {
				if strings.HasPrefix(r, "param:") {
					if i, err := strconv.Atoi(r[6:]); err == nil {
						pf.RetParams = append(pf.RetParams, i)
					}
				}
			}
			sort.Ints(pf.RetParams)
			ast.Inspect(body, func(n ast.Node) bool {
				// v3.1: attacker-chosen destination written into a client / URL field
				// (assignments only: struct literals are mostly response / status values)
				destSink := func(field string, val ast.Expr, at ast.Node) {
					// (assigning a path component to a URL object is the safe form — the
					// fix in openhole does exactly that — so only the destination fields count)
					if !destFields[field] || val == nil {
						return
					}
					if rs := tc.rootsOf(val); len(rs) > 0 {
						pf.TaintSinks = append(pf.TaintSinks, TaintSink{Line: fset.Position(at.Pos()).Line,
							Type: "http_request", Pattern: truncate(exprText(fset, at), 120), Roots: rs.sorted()})
					}
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && len(x.Lhs) == len(x.Rhs) {
							destSink(sel.Sel.Name, x.Rhs[i], x)
						}
					}
					return true
				}
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				line := fset.Position(c.Pos()).Line
				code := callText(c)
				// sanitizers (R2-only table)
				for _, sa := range r2Sanitizers {
					if strings.Contains(code, sa.pattern) {
						pf.Sanitizers = append(pf.Sanitizers, SanitizerPoint{Line: line, Pattern: code, Category: sa.category})
						break
					}
				}
				// argument roots
				var args []CallArg
				all := rootSet{}
				for i, a := range c.Args {
					rs := tc.rootsOf(a)
					if len(rs) > 0 {
						args = append(args, CallArg{Index: i, Roots: rs.sorted()})
						for r := range rs {
							all[r] = true
						}
					}
				}
				// dangerous sinks
				sinkType := ""
				for _, sk := range activeSinks {
					if strings.Contains(code, sk.pattern) {
						sinkType = sk.fType
						if (sk.fType == "sql_query" || sk.fType == "sql_exec") && isStmtReceiver(c.Fun) {
							// *sql.Stmt: the query was fixed at Prepare; arguments are bound
							sinkType = ""
							break
						}
						if idxs, ok := sinkArgIndex[sk.pattern]; ok {
							all = rootSet{}
							for _, i := range idxs {
								if i < len(c.Args) {
									for r := range tc.rootsOf(c.Args[i]) {
										all[r] = true
									}
								}
							}
						}
						break
					}
				}
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "make" && len(c.Args) >= 2 {
					sinkType = "alloc_size"
					all = rootSet{}
					for _, a := range c.Args[1:] {
						for r := range tc.rootsOf(a) {
							all[r] = true
						}
					}
				}
				// v3.2: outbound URL built from a scheme literal: authority -> SSRF,
				// path / query -> request path traversal
				if sinkType == "http_request" {
					if idxs, ok := sinkArgIndex[matchedPattern(code, activeSinks)]; ok && len(idxs) == 1 && idxs[0] < len(c.Args) {
						if a, pth, ok := tc.urlSplit(c.Args[idxs[0]], 0); ok {
							all = a
							if len(pth) > 0 {
								pf.TaintSinks = append(pf.TaintSinks, TaintSink{Line: line, Type: "url_path",
									Pattern: truncate(exprText(fset, c), 120), Roots: pth.sorted()})
							}
						}
					}
				}
				// v3.2: string-built argument to a query-like call (any query language)
				if sinkType == "" {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && queryCallName.MatchString(sel.Sel.Name) {
						pkgStd := false
						if id, ok := sel.X.(*ast.Ident); ok {
							if p, isPkg := tc.pkgs[id.Name]; isPkg && isStdlibPath(p) {
								pkgStd = true
							}
						}
						if !pkgStd {
							qs := rootSet{}
							for _, a := range c.Args {
								if tc.builtString(a, 0) {
									for r := range tc.rootsOf(a) {
										qs[r] = true
									}
								}
							}
							if len(qs) > 0 {
								sinkType, all = "query_built", qs
							}
						}
					}
				}
				// v3.2: external data written to an HTTP response without a safe Content-Type
				if sinkType == "" && len(tc.writers) > 0 && !safeCT {
					var data []ast.Expr
					fn := exprToString(c.Fun)
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" {
						if id, ok := sel.X.(*ast.Ident); ok && tc.writers[id.Name] {
							data = c.Args
						}
					}
					if (fn == "fmt.Fprintf" || fn == "fmt.Fprint" || fn == "fmt.Fprintln" || fn == "io.WriteString") && len(c.Args) > 1 {
						if id, ok := c.Args[0].(*ast.Ident); ok && tc.writers[id.Name] {
							data = c.Args[1:]
						}
					}
					if len(data) > 0 {
						ws := rootSet{}
						for _, a := range data {
							for r := range tc.rootsOf(a) {
								ws[r] = true
							}
						}
						if len(ws) > 0 {
							sinkType, all = "response_write", ws
						}
					}
				}
				if sinkType != "" && len(all) > 0 {
					pf.TaintSinks = append(pf.TaintSinks, TaintSink{Line: line, Type: sinkType,
						Pattern: truncate(exprText(fset, c), 120), Roots: all.sorted()})
				}
				// v3.2 R5 facts
				if principalCall.MatchString(selName(c.Fun)) {
					pf.PrincipalCheck = true
				}
				if cf, ok := tc.resourceAccess(fset, c); ok {
					pf.ResourceAccess = append(pf.ResourceAccess, cf)
				}
				// call sites and handler references
				cs := CallSite{Line: line, NArgs: len(c.Args)}
				switch f := c.Fun.(type) {
				case *ast.Ident:
					if isBuiltin(f.Name) || isTypeConversion(f.Name) {
						return true
					}
					cs.Name = f.Name
				case *ast.SelectorExpr:
					cs.Name = f.Sel.Name
					if id, ok := f.X.(*ast.Ident); ok {
						if p, ok := aliases[id.Name]; ok && tc.env[id.Name] == nil {
							cs.Pkg = p
						} else if recvName != "" && id.Name == recvName {
							cs.Recv = "self"
						} else {
							cs.Recv = id.Name
						}
					} else {
						cs.Recv = truncate(exprToString(f.X), 60)
					}
				default:
					return true
				}
				if len(args) > 0 {
					cs.Args = args
					pf.CallSites = append(pf.CallSites, cs)
				}
				ck := cs.Pkg + "|" + cs.Recv + "|" + cs.Name + "|" + strconv.Itoa(cs.NArgs)
				if !seenCallee[ck] {
					seenCallee[ck] = true
					pf.Callees = append(pf.Callees, CallSite{Name: cs.Name, Pkg: cs.Pkg, Recv: cs.Recv, NArgs: cs.NArgs})
				}
				return true
			})
			// v4.2: inline handler closures get their own R5 facts
			escapedLits := map[*ast.FuncLit]bool{}
			for _, e := range tc.escapingValues(body) {
				if fl, ok := e.(*ast.FuncLit); ok {
					escapedLits[fl] = true
				}
			}
			ast.Inspect(body, func(n ast.Node) bool {
				fl, ok := n.(*ast.FuncLit)
				if !ok || !escapedLits[fl] || fl.Body == nil {
					return true
				}
				ps, _ := paramList(fset, fl.Type, aliases)
				isHandler := false
				for _, p := range ps {
					if isRequestType(p.Type) {
						isHandler = true
					}
				}
				if !isHandler {
					return true
				}
				ch := ClosureHandler{Line: fset.Position(fl.Pos()).Line, EndLine: fset.Position(fl.Body.Rbrace).Line}
				ast.Inspect(fl.Body, func(m ast.Node) bool {
					if inner, ok := m.(*ast.FuncLit); ok && inner != fl {
						return false
					}
					if c, ok := m.(*ast.CallExpr); ok {
						if principalCall.MatchString(selName(c.Fun)) {
							ch.PrincipalCheck = true
						}
						if cf, ok := tc.resourceAccess(fset, c); ok {
							ch.ResourceAccess = append(ch.ResourceAccess, cf)
						}
					}
					return true
				})
				pf.ClosureHandlers = append(pf.ClosureHandlers, ch)
				return false
			})
			// v4.2: lines holding a call or a comparison (LLM-reported checks must land on one)
			clSeen := map[int]bool{}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					clSeen[fset.Position(x.Pos()).Line] = true
				case *ast.BinaryExpr:
					switch x.Op {
					case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ, token.LAND, token.LOR:
						clSeen[fset.Position(x.Pos()).Line] = true
					}
				case *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
					clSeen[fset.Position(n.Pos()).Line] = true
				}
				return true
			})
			for l := range clSeen {
				pf.CheckLines = append(pf.CheckLines, l)
			}
			sort.Ints(pf.CheckLines)
			// v4: function values that escape (see escapingValues) — resolved by
			// param_taint.py; a non-function value simply fails to resolve
			refAt := func(e ast.Expr) (CallSite, bool) {
				ref := CallSite{Line: fset.Position(e.Pos()).Line}
				switch r := e.(type) {
				case *ast.Ident:
					if r.Name == "nil" || r.Name == "true" || r.Name == "false" || tc.env[r.Name] != nil {
						return ref, false
					}
					if _, isPkg := aliases[r.Name]; isPkg {
						return ref, false
					}
					ref.Name = r.Name
				case *ast.SelectorExpr:
					ref.Name = r.Sel.Name
					if id, ok := r.X.(*ast.Ident); ok {
						if p, ok := aliases[id.Name]; ok && tc.env[id.Name] == nil {
							ref.Pkg = p
						} else if recvName != "" && id.Name == recvName {
							ref.Recv = "self"
						} else {
							ref.Recv = id.Name
						}
					} else {
						ref.Recv = truncate(exprToString(r.X), 60)
					}
				default:
					return ref, false
				}
				return ref, true
			}
			seenRef := map[string]bool{}
			for _, e := range tc.escapingValues(body) {
				if ref, ok := refAt(e); ok {
					k := ref.Pkg + "|" + ref.Recv + "|" + ref.Name
					if !seenRef[k] {
						seenRef[k] = true
						pf.CallbackRefs = append(pf.CallbackRefs, ref)
					}
				}
			}
			// v3.2: the cross-package / unresolved calls whose results reached any root set
			used := map[int]bool{}
			collect := func(rs []string) {
				for _, r := range rs {
					if strings.HasPrefix(r, "call:") {
						if l, err := strconv.Atoi(r[5:]); err == nil {
							used[l] = true
						}
					}
				}
			}
			collect(pf.ReturnRoots)
			for _, t := range pf.TaintSinks {
				collect(t.Roots)
			}
			for _, cs := range pf.CallSites {
				for _, a := range cs.Args {
					collect(a.Roots)
				}
			}
			if len(used) > 0 {
				ast.Inspect(body, func(n ast.Node) bool {
					c, ok := n.(*ast.CallExpr)
					if !ok || !tc.crossCall(c) {
						return true
					}
					l := fset.Position(c.Pos()).Line
					if !used[l] {
						return true
					}
					sel := c.Fun.(*ast.SelectorExpr)
					cs := CallSite{Line: l, Name: sel.Sel.Name, NArgs: len(c.Args)}
					if id, ok := sel.X.(*ast.Ident); ok {
						if p, isPkg := aliases[id.Name]; isPkg && tc.env[id.Name] == nil {
							cs.Pkg = p
						} else {
							cs.Recv = id.Name
						}
					} else {
						cs.Recv = truncate(exprToString(sel.X), 60)
					}
					for i, a := range c.Args { // v4: for cross-package pass-through
						if rs := tc.rootsOf(a); len(rs) > 0 {
							cs.Args = append(cs.Args, CallArg{Index: i, Roots: rs.sorted()})
						}
					}
					pf.RetCalls = append(pf.RetCalls, cs)
					return true
				})
			}
			flows = append(flows, pf)
		}

		for _, decl := range fi.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				recvName := ""
				if d.Recv != nil && len(d.Recv.List) > 0 && len(d.Recv.List[0].Names) > 0 {
					recvName = d.Recv.List[0].Names[0].Name
				}
				visit(qualName(d), fset.Position(d.Pos()).Line, d.Type, d.Body, recvName, recvBase(d))
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							if fl, ok := vs.Values[i].(*ast.FuncLit); ok {
								visit(name.Name, fset.Position(fl.Pos()).Line, fl.Type, fl.Body, "", "")
							}
						}
					}
				}
			}
		}
	}
	return flows
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
