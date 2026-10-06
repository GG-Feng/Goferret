// Package main implements a Go source code analyzer for vulnerability analysis.
// It extracts imports, call chains, data flow indicators, and stdlib signals
// from Go source directories.
//
// Usage:
//
//	go run ./ast_analyzer --dir <source_dir> [--focus-funcs func1,func2] [--focus-files file1.go]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ── Output types ──────────────────────────────────────────────────────────

type AnalysisResult struct {
	Imports             map[string]*FileImports `json:"imports"`
	CallChains          []CallChain             `json:"call_chains"`
	DataFlowIndicators  []DataFlowIndicator     `json:"data_flow_indicators"`
	StdlibSignals       []StdlibSignal          `json:"stdlib_signals"`
	ConcurrencyPatterns []ConcurrencyPattern    `json:"concurrency_patterns"`
	Functions           []FuncDef               `json:"functions,omitempty"`
	// v3 R1: size-sensitive sinks and range checks on numerically parsed values.
	// Kept out of DataFlowIndicators so the v2 decision path is unaffected.
	SizeFlows []SizeFlow `json:"size_flows,omitempty"`
	// v3 R2: per-function parameter/call-site taint facts (see param_flow.go).
	ParamFlows []ParamFlow `json:"param_flows,omitempty"`
	// v4: struct types with field tags (decoded data), for the wire-parameter lookup.
	WireTypes []WireType `json:"wire_types,omitempty"`
	ParseMode  string      `json:"parse_mode"`
}

// SizeFlow (v3 R1): per function, sinks where a numerically parsed value is used as an
// allocation length or an index, and relational comparisons on those values.
type SizeFlow struct {
	Function    string       `json:"function"`
	File        string       `json:"file"`
	SizeSinks   []SizeSink   `json:"size_sinks"`
	RangeChecks []RangeCheck `json:"range_checks,omitempty"`
}

type SizeSink struct {
	Line    int    `json:"line"`
	Type    string `json:"type"` // alloc_size | index_access
	Var     string `json:"var"`
	Pattern string `json:"pattern"`
}

type RangeCheck struct {
	Line    int    `json:"line"`
	Var     string `json:"var"`
	Pattern string `json:"pattern"`
}

type FileImports struct {
	Stdlib        []string `json:"stdlib"`
	ThirdParty    []string `json:"third_party"`
	StdlibMarkers []string `json:"stdlib_markers"`
}

type FuncDef struct {
	Name     string   `json:"name"`
	Receiver string   `json:"receiver,omitempty"`
	QName    string   `json:"qname,omitempty"` // 方法为 "Recv.Name"，与 data flow / call chain 的 function 字段一致
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Calls    []string `json:"calls,omitempty"`
}

type CallChain struct {
	RootFunction string      `json:"root_function"`
	RootFile     string      `json:"root_file"`
	Calls        []CallEntry `json:"calls"`
}

type CallEntry struct {
	Callee  string `json:"callee"`
	Depth   int    `json:"depth"`
	Type    string `json:"type"` // "local", "method", "stdlib", "third_party", "unknown"
	Package string `json:"package,omitempty"`
}

type DataFlowIndicator struct {
	Function   string           `json:"function"`
	File       string           `json:"file"`
	Sources    []FlowPoint      `json:"sources"`
	Sinks      []FlowPoint      `json:"sinks"`
	Sanitizers []SanitizerPoint `json:"sanitizers,omitempty"`
}

type FlowPoint struct {
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
	Type    string `json:"type"`
}

type SanitizerPoint struct {
	Line     int    `json:"line"`
	Pattern  string `json:"pattern"`
	Category string `json:"category"`
}

type StdlibSignal struct {
	Package     string   `json:"package"`
	APIs        []string `json:"apis"`
	DomainHints []string `json:"domain_hints"`
}

type ConcurrencyPattern struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line"`
	Type     string `json:"type"` // "goroutine", "channel_send", "channel_recv", "mutex_lock", "mutex_unlock", "waitgroup"
	Code     string `json:"code"`
}

// ── Stdlib domain mapping ─────────────────────────────────────────────────

type domainInfo struct {
	domainHints   []string
	sensitiveAPIs []string
}

var stdlibDomainMap = map[string]domainInfo{
	"encoding/json": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"Unmarshal", "Marshal", "Decode", "Encode", "NewDecoder"},
	},
	"encoding/xml": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"Unmarshal", "Marshal", "Decode", "Encode", "NewDecoder"},
	},
	"encoding/gob": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"NewDecoder", "NewEncoder", "Decode", "Encode"},
	},
	"encoding/asn1": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"Unmarshal", "Marshal"},
	},
	"encoding/binary": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"Read", "Write", "BigEndian", "LittleEndian", "PutUint16", "Uint16"},
	},
	"mime": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"ParseMediaType", "FormatMediaType"},
	},
	"mime/multipart": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"NewReader", "NewWriter"},
	},
	"os": {
		domainHints:   []string{"PathHandlingAndFilesystemAccess"},
		sensitiveAPIs: []string{"Open", "Create", "OpenFile", "Rename", "Remove", "MkdirAll", "Getenv", "ReadFile", "WriteFile"},
	},
	"path": {
		domainHints:   []string{"PathHandlingAndFilesystemAccess"},
		sensitiveAPIs: []string{"Join", "Clean", "Base", "Dir", "Ext"},
	},
	"path/filepath": {
		domainHints:   []string{"PathHandlingAndFilesystemAccess"},
		sensitiveAPIs: []string{"Join", "Clean", "Walk", "Abs", "Rel", "EvalSymlinks"},
	},
	"crypto/tls": {
		domainHints:   []string{"AuthenticationAndAuthorization", "CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Dial", "Listen", "LoadX509KeyPair", "Config"},
	},
	"crypto/x509": {
		domainHints:   []string{"AuthenticationAndAuthorization", "CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"ParseCertificate", "CertPool", "Verify"},
	},
	"net/http": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"Get", "Post", "Serve", "ListenAndServe", "HandleFunc", "Error", "Redirect", "NewRequest", "ReadRequest", "ReadResponse"},
	},
	"net": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"Dial", "Listen", "Accept", "Conn"},
	},
	"net/url": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"Parse", "ParseQuery", "Values"},
	},
	"net/rpc": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"Call", "ServeConn", "Register"},
	},
	"net/smtp": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"SendMail", "PlainAuth", "CRAMMD5Auth"},
	},
	"net/textproto": {
		domainHints:   []string{"NetworkRequestAndProtocolHandling"},
		sensitiveAPIs: []string{"ReadMIMEHeader", "Dial"},
	},
	"os/exec": {
		domainHints:   []string{"CommandExecutionAndExternalProcessInteraction"},
		sensitiveAPIs: []string{"Command", "Run", "Start", "Output", "CombinedOutput"},
	},
	"syscall": {
		domainHints:   []string{"CommandExecutionAndExternalProcessInteraction"},
		sensitiveAPIs: []string{"Exec", "ForkExec", "StartProcess"},
	},
	"database/sql": {
		domainHints:   []string{"QueryTemplateAndExpressionConstruction"},
		sensitiveAPIs: []string{"Query", "Exec", "QueryRow", "Prepare"},
	},
	"text/template": {
		domainHints:   []string{"QueryTemplateAndExpressionConstruction"},
		sensitiveAPIs: []string{"New", "Parse", "Execute"},
	},
	"html/template": {
		domainHints:   []string{"QueryTemplateAndExpressionConstruction"},
		sensitiveAPIs: []string{"New", "Parse", "Execute", "HTML", "JS"},
	},
	"regexp": {
		domainHints:   []string{"QueryTemplateAndExpressionConstruction"},
		sensitiveAPIs: []string{"Compile", "MustCompile", "Match", "Find"},
	},
	"archive/zip": {
		domainHints:   []string{"ArchiveAndCompressionProcessing"},
		sensitiveAPIs: []string{"OpenReader", "Create", "CreateHeader", "FileHeader"},
	},
	"archive/tar": {
		domainHints:   []string{"ArchiveAndCompressionProcessing"},
		sensitiveAPIs: []string{"NewReader", "NewWriter", "FileInfoHeader"},
	},
	"compress/gzip": {
		domainHints:   []string{"ArchiveAndCompressionProcessing"},
		sensitiveAPIs: []string{"NewReader", "NewWriter"},
	},
	"compress/zlib": {
		domainHints:   []string{"ArchiveAndCompressionProcessing"},
		sensitiveAPIs: []string{"NewReader", "NewWriter"},
	},
	"sync": {
		domainHints:   []string{"ConcurrencyStateAndSharedResourceManagement"},
		sensitiveAPIs: []string{"Mutex", "RWMutex", "WaitGroup", "Once", "Cond"},
	},
	"sync/atomic": {
		domainHints:   []string{"ConcurrencyStateAndSharedResourceManagement"},
		sensitiveAPIs: []string{"AddInt64", "LoadInt64", "StoreInt64", "CompareAndSwapInt64"},
	},
	"context": {
		domainHints:   []string{"ConcurrencyStateAndSharedResourceManagement"},
		sensitiveAPIs: []string{"WithCancel", "WithTimeout", "WithValue", "Background"},
	},
	"crypto": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Hash", "Signer", "PrivateKey", "PublicKey"},
	},
	"crypto/cipher": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"NewCTR", "NewCBCDecrypter", "NewCBCEncrypter", "NewGCM"},
	},
	"crypto/rsa": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"EncryptPKCS1v15", "DecryptPKCS1v15", "SignPKCS1v15", "VerifyPKCS1v15"},
	},
	"crypto/ecdsa": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Sign", "Verify"},
	},
	"crypto/hmac": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"New", "Equal"},
	},
	"crypto/sha256": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Sum256", "New"},
	},
	"crypto/sha512": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Sum512", "New"},
	},
	"crypto/md5": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Sum", "New"},
	},
	"crypto/rand": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"Read", "Prime"},
	},
	"crypto/subtle": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"ConstantTimeCompare", "ConstantTimeCopy"},
	},
	"hash": {
		domainHints:   []string{"CryptographicVerificationAndSecurityValidation"},
		sensitiveAPIs: []string{"New"},
	},
	"bufio": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"NewReader", "NewWriter", "ReadString", "ReadBytes"},
	},
	"io": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"ReadFull", "ReadAll", "Copy", "CopyN"},
	},
	"io/ioutil": {
		domainHints:   []string{"InputParsingAndDeserialization", "PathHandlingAndFilesystemAccess"},
		sensitiveAPIs: []string{"ReadAll", "ReadFile", "WriteFile", "ReadDir"},
	},
	"html": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"EscapeString", "UnescapeString"},
	},
	"strings": {
		domainHints:   []string{"InputParsingAndDeserialization"},
		sensitiveAPIs: []string{"Contains", "HasPrefix", "HasSuffix", "Replace", "Split", "NewReader"},
	},
}

// fileInfo holds a parsed Go file and its relative path.
type fileInfo struct {
	relPath string
	file    *ast.File
}

// importMap holds the import alias mapping for a single file.
type importMap struct {
	aliases map[string]string // alias or package name -> import path
}

// flowPattern is a source/sink API matched by substring against the text
// form of each AST node. gateImports optionally restricts the pattern to
// files importing one of the given module paths: receiver-name patterns
// like "c.Query(" only read an HTTP parameter inside gin/echo/beego files —
// elsewhere the same receiver could be a *sql.DB or context.Context.
type flowPattern struct {
	pattern     string
	fType       string
	gateImports []string
}

// Import gates for receiver-name patterns. Gates are module roots: a gate
// matches the exact path or any subpackage under it, so gateEcho covers
// both github.com/labstack/echo and .../echo/v4, and gateBeego covers
// beego's server/web context subpackage. Subpackage imports also let a
// framework's own source through (gin imports gin/internal/...), which is
// correct: inside the framework, c.Status( really is a response write.
var (
	gateGin     = []string{"github.com/gin-gonic/gin"}
	gateEcho    = []string{"github.com/labstack/echo"}
	gateGinEcho = []string{"github.com/gin-gonic/gin", "github.com/labstack/echo"}
	gateBeego   = []string{"github.com/beego/beego/v2", "github.com/astaxie/beego"}
	gateMux     = []string{"github.com/gorilla/mux"}
)

// Source/sink patterns for data flow detection
var sourcePatterns = []flowPattern{
	{".Read(", "read", nil},
	{".ReadAll(", "read_all", nil},
	{".Recv(", "channel_recv", nil},
	{".Accept(", "network_accept", nil},
	{".ReadMessage(", "read_message", nil},
	{".ReadTCP(", "network_read", nil},
	{".ReadUDP(", "network_read", nil},
	{"http.Request", "http_request", nil},
	{".Body", "http_body", nil},
	{"bufio.NewReader(", "buffered_read", nil},
	{"bufio.NewScanner(", "buffered_read", nil},
	{"json.Unmarshal(", "json_decode", nil},
	{"json.Decode(", "json_decode", nil},
	{"xml.Unmarshal(", "xml_decode", nil},
	{"binary.Read(", "binary_read", nil},
	{".Scan(", "scan", nil},
	{"io.Copy(", "io_copy", nil},
	{"io.CopyN(", "io_copy", nil},
	{"json.NewDecoder(", "json_decode", nil},
	{"xml.NewDecoder(", "xml_decode", nil},
	{"yaml.Unmarshal(", "json_decode", nil},
	{"URL.Query(", "http_request", nil},
	// Web framework context reads (receiver-name patterns, import-gated).
	// r.FormValue needs no gate: the method is unique to *http.Request.
	{"c.QueryParam(", "http_request", gateEcho},
	{"c.Param(", "http_request", gateGinEcho},
	{"c.Query(", "http_request", gateGin},
	{"c.FormFile(", "http_request", gateGin},
	{"c.ShouldBind(", "http_request", gateGin},
	{"c.ShouldBindJSON(", "http_request", gateGin},
	{"c.Bind(", "http_request", gateGinEcho},
	{"c.BindJSON(", "http_request", gateGin},
	{"ctx.Query(", "http_request", gateBeego},
	{"r.FormValue(", "http_request", nil},
	// Header, cookie and route params are attacker-controlled request input
	// just as much as query and form values. Without these a handler that
	// only reads a header has no data flow at all and the flow gate skips
	// it, so nothing downstream ever looks at it.
	{"r.Header.Get(", "http_request", nil},
	{"r.Cookie(", "http_request", nil},
	{"mux.Vars(", "http_request", gateMux},
}

var sinkPatterns = []flowPattern{
	{"exec.Command(", "command_execution", nil},
	{"os.Create(", "file_write", nil},
	{"os.Open(", "file_read", nil},
	{"os.OpenFile(", "file_write", nil},
	{"os.WriteFile(", "file_write", nil},
	{"filepath.Join(", "path_construction", nil},
	{"sql.Query(", "sql_query", nil},
	{"sql.Exec(", "sql_exec", nil},
	{"sql.QueryRow(", "sql_query", nil},
	{"http.Get(", "http_request", nil},
	{"http.Post(", "http_request", nil},
	{"template.HTML(", "html_injection", nil},
	{"template.JS(", "js_injection", nil},
	{"json.Marshal(", "json_encode", nil},
	{"fmt.Sprintf(", "string_format", nil},
	{"fmt.Sprintf(", "string_format", nil},
	{".Write(", "write", nil},
	{".WriteString(", "write", nil},
	{"os.MkdirAll(", "file_write", nil},
	{"os.Stat(", "file_read", nil},
	{"path.Join(", "path_construction", nil},
	{"os.ReadFile(", "file_read", nil},
	{"ioutil.ReadFile(", "file_read", nil},
	{"os.Chmod(", "file_write", nil},
	{"os.Rename(", "file_write", nil},
	{"os.RemoveAll(", "file_write", nil},
	{"exec.CommandContext(", "command_execution", nil},
	{"http.NewRequest(", "http_request", nil},
	{"w.Header(", "write", nil},
	// Web framework context response writes (receiver-name, import-gated)
	{"c.JSON(", "write", gateGinEcho},
	{"c.String(", "write", gateGinEcho},
	{"c.Status(", "write", gateGinEcho},
	{"c.Header(", "write", gateGinEcho},
}

// Sanitizer patterns: security-check APIs. When one sits between a source
// and a sink of the same data flow, the span is protected for that
// missing_step_category. bounds_check / error_handling / protocol_validation
// have no reliable API-level signal and are intentionally absent.
var sanitizerPatterns = []struct {
	pattern  string
	category string
}{
	{"filepath.Clean(", "path_validation"},
	{"filepath.IsLocal(", "path_validation"},
	{"path.Clean(", "path_validation"},
	{"html.EscapeString(", "output_encoding"},
	{"template.HTMLEscapeString(", "output_encoding"},
	{"url.QueryEscape(", "output_encoding"},
	{"url.PathEscape(", "output_encoding"},
	{"strconv.Quote(", "output_encoding"},
	{".MatchString(", "input_sanitization"},
	{"strconv.Atoi(", "input_sanitization"},
	{"strconv.ParseInt(", "input_sanitization"},
	{"strconv.ParseFloat(", "input_sanitization"},
	{"validator.New(", "input_sanitization"},
	{"io.LimitReader(", "resource_limit"},
	{"http.MaxBytesReader(", "resource_limit"},
	{"context.WithTimeout(", "resource_limit"},
	{"context.WithDeadline(", "resource_limit"},
	{"csrf.Protect(", "origin_validation"},
	{"SameSite", "origin_validation"},
	{".AllowOrigins(", "origin_validation"},
	{".Enforce(", "access_control"},
	{"ed25519.Verify(", "cryptographic_verification"},
	{"ecdsa.Verify(", "cryptographic_verification"},
	{"rsa.VerifyPKCS1v15(", "cryptographic_verification"},
	{"rsa.VerifyPSS(", "cryptographic_verification"},
	{"hmac.Equal(", "cryptographic_verification"},
	{"subtle.ConstantTimeCompare(", "cryptographic_verification"},
	{"cert.Verify(", "cryptographic_verification"},
	{"jwt.Parse(", "identity_verification"},
	{"jwt.ParseWithClaims(", "identity_verification"},
	{"bcrypt.CompareHashAndPassword(", "identity_verification"},
	{"atomic.CompareAndSwap(", "state_synchronization"},
	{"atomic.Load", "state_synchronization"},
	{"atomic.Store", "state_synchronization"},
	{".Lock(", "state_synchronization"},
	{"filepath.Base(", "path_validation"},
	{"filepath.Dir(", "path_validation"},
	{"strconv.ParseUint(", "input_sanitization"},
	{"bluemonday.NewPolicy(", "output_encoding"},
	{"strings.HasPrefix(", "path_validation"},
	{"strings.Contains(", "input_sanitization"},
}

// ── Analysis ──────────────────────────────────────────────────────────────

func main() {
	dir := flag.String("dir", ".", "Source directory to analyze")
	focusFuncs := flag.String("focus-funcs", "", "Comma-separated function names to focus on")
	focusFiles := flag.String("focus-files", "", "Comma-separated file paths to focus on")
	guardsFile := flag.String("guards", "", "Guard-chain mode: file path relative to --dir")
	guardFunc := flag.String("guard-func", "", "Guard-chain mode: function name")
	guardLine := flag.Int("guard-line", 0, "Guard-chain mode: stop at this line (0 = whole function)")
	flag.Parse()

	if *guardsFile != "" {
		gr, err := extractGuards(*dir, *guardsFile, *guardFunc, *guardLine)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(gr); err != nil {
			fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	var fFuncs, fFiles []string
	if *focusFuncs != "" {
		fFuncs = strings.Split(*focusFuncs, ",")
	}
	if *focusFiles != "" {
		fFiles = strings.Split(*focusFiles, ",")
	}

	result, err := analyze(*dir, fFuncs, fFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
		os.Exit(1)
	}
}

func analyze(dir string, focusFuncs, focusFiles []string) (*AnalysisResult, error) {
	// Step 1: Try parsing the entire directory tree
	result, err := analyzeDir(dir, focusFuncs, focusFiles)
	if err != nil {
		return nil, err
	}

	// Step 2: If root parsing produced no structured data, try subdirectory fallback
	hasData := len(result.CallChains) > 0 || len(result.DataFlowIndicators) > 0
	if !hasData && len(focusFiles) > 0 {
		subdirResult := analyzeSubdirectoryFallback(dir, focusFuncs, focusFiles)
		if subdirResult != nil && (len(subdirResult.CallChains) > 0 || len(subdirResult.DataFlowIndicators) > 0) {
			result = subdirResult
		}
	}

	return result, nil
}

// analyzeSubdirectoryFallback extracts parent directories from focus files
// and parses each one separately, merging results.
func analyzeSubdirectoryFallback(rootDir string, focusFuncs, focusFiles []string) *AnalysisResult {
	// Collect unique parent directories of changed files
	dirSet := make(map[string]bool)
	for _, f := range focusFiles {
		parent := filepath.Dir(f)
		// Walk up at most 3 levels to find a directory with .go files
		for i := 0; i < 3; i++ {
			absPath := filepath.Join(rootDir, parent)
			if hasGoFiles(absPath) {
				dirSet[parent] = true
				break
			}
			parent = filepath.Dir(parent)
		}
	}

	var merged AnalysisResult
	merged.Imports = make(map[string]*FileImports)
	merged.CallChains = nil
	merged.DataFlowIndicators = nil
	merged.StdlibSignals = nil
	merged.ConcurrencyPatterns = nil
	merged.ParseMode = "parser"

	chainSeen := make(map[string]bool)
	signalSeen := make(map[string]bool)
	flowSeen := make(map[string]bool)

	for sub := range dirSet {
		absSub := filepath.Join(rootDir, sub)
		subResult, err := analyzeDir(absSub, focusFuncs, nil)
		if err != nil {
			continue
		}

		// Merge imports with adjusted paths
		for k, v := range subResult.Imports {
			adjPath := filepath.Join(sub, k)
			adjPath = filepath.ToSlash(adjPath)
			merged.Imports[adjPath] = v
		}

		// Merge call chains (dedup by root_function)
		for _, cc := range subResult.CallChains {
			key := cc.RootFile + ":" + cc.RootFunction
			if !chainSeen[key] {
				chainSeen[key] = true
				// Adjust file paths to be relative to rootDir
				cc.RootFile = filepath.Join(sub, cc.RootFile)
				cc.RootFile = filepath.ToSlash(cc.RootFile)
				merged.CallChains = append(merged.CallChains, cc)
			}
		}

		// Merge data flow indicators (dedup)
		for _, df := range subResult.DataFlowIndicators {
			key := df.File + ":" + df.Function
			if !flowSeen[key] {
				flowSeen[key] = true
				df.File = filepath.Join(sub, df.File)
				df.File = filepath.ToSlash(df.File)
				merged.DataFlowIndicators = append(merged.DataFlowIndicators, df)
			}
		}

		// Merge stdlib signals (dedup by package)
		for _, s := range subResult.StdlibSignals {
			if !signalSeen[s.Package] {
				signalSeen[s.Package] = true
				merged.StdlibSignals = append(merged.StdlibSignals, s)
			}
		}

		// Merge concurrency patterns
		for _, cp := range subResult.ConcurrencyPatterns {
			cp.File = filepath.Join(sub, cp.File)
			cp.File = filepath.ToSlash(cp.File)
			merged.ConcurrencyPatterns = append(merged.ConcurrencyPatterns, cp)
		}

		// Merge functions
		for _, fd := range subResult.Functions {
			fd.File = filepath.Join(sub, fd.File)
			fd.File = filepath.ToSlash(fd.File)
			merged.Functions = append(merged.Functions, fd)
		}
	}

	return &merged
}

func hasGoFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			return true
		}
	}
	return false
}

func analyzeDir(dir string, focusFuncs, focusFiles []string) (*AnalysisResult, error) {
	fset := token.NewFileSet()

	// Parse all .go files
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
	if err != nil {
		// ParseDir may return partial results along with the error.
		// Only fall back if we got no packages at all.
		if len(pkgs) == 0 {
			pkgs, err = parseFilesLenient(fset, dir)
			if err != nil {
				return nil, fmt.Errorf("parse error: %w", err)
			}
		}
	}

	result := &AnalysisResult{
		Imports: make(map[string]*FileImports),
	}

	// Collect all files and their ASTs
	var files []fileInfo
	for _, pkg := range pkgs {
		for path, f := range pkg.Files {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				rel = path
			}
			// Convert to forward slashes for consistency
			rel = filepath.ToSlash(rel)
			files = append(files, fileInfo{relPath: rel, file: f})
		}
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].relPath < files[j].relPath
	})

	// Filter files if focus-files is specified
	focusSet := make(map[string]bool)
	for _, f := range focusFiles {
		focusSet[f] = true
	}

	// Step 1: Extract imports
	result.Imports = extractImports(files)

	// Step 2: Extract all function definitions
	allFuncs := extractFuncDefs(fset, files)

	// Step 3: Extract call chains for focus functions
	result.CallChains = extractCallChains(fset, files, allFuncs, focusFuncs)

	// Step 4: Extract stdlib signals from imports
	result.StdlibSignals = extractStdlibSignals(result.Imports)

	// Step 5: Extract data flow indicators for focus functions
	result.DataFlowIndicators = extractDataFlow(fset, files, focusFuncs)

	// Step 6: Extract concurrency patterns for focus functions
	result.ConcurrencyPatterns = extractConcurrency(fset, files, focusFuncs)

	// Step 7 (v3 R1): size-sensitive sinks on numerically parsed values
	result.SizeFlows = extractSizeFlows(fset, files, focusFuncs)

	// Step 8 (v3 R2): parameter taint facts for inter-procedural propagation
	result.ParamFlows = extractParamFlows(fset, files, focusFuncs)
	result.WireTypes = collectWireTypes(files)

	// Store function list (only for focus files)
	result.Functions = filterFuncDefs(allFuncs, focusFuncs, focusSet)
	result.ParseMode = "parser"

	return result, nil
}

// parseFilesLenient tries to parse Go files individually, skipping ones with errors.
func parseFilesLenient(fset *token.FileSet, dir string) (map[string]*ast.Package, error) {
	pkgs := make(map[string]*ast.Package)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != dir && (info.Name() == "vendor" || info.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil // skip problematic files
		}
		pkgName := f.Name.Name
		if _, ok := pkgs[pkgName]; !ok {
			pkgs[pkgName] = &ast.Package{
				Name:  pkgName,
				Files: make(map[string]*ast.File),
			}
		}
		pkgs[pkgName].Files[path] = f
		return nil
	})
	return pkgs, err
}

// ── Import extraction ─────────────────────────────────────────────────────

func extractImports(files []fileInfo) map[string]*FileImports {
	result := make(map[string]*FileImports)

	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}
		imports := &FileImports{}
		for _, imp := range fi.file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if isStdlib(path) {
				imports.Stdlib = append(imports.Stdlib, path)
			} else {
				imports.ThirdParty = append(imports.ThirdParty, path)
			}
		}
		// Generate stdlib markers from imports
		for _, pkg := range imports.Stdlib {
			if info, ok := stdlibDomainMap[pkg]; ok {
				for _, api := range info.sensitiveAPIs {
					imports.StdlibMarkers = append(imports.StdlibMarkers, pkg+"."+api)
				}
			}
		}
		if len(imports.Stdlib) > 0 || len(imports.ThirdParty) > 0 {
			result[fi.relPath] = imports
		}
	}

	return result
}

func isStdlib(importPath string) bool {
	// Standard library packages have no dots in the first segment
	// Exceptions: golang.org/x/... is not stdlib
	parts := strings.Split(importPath, "/")
	first := parts[0]
	if strings.Contains(first, ".") {
		return false
	}
	// golang.org/x/* is extended stdlib but treated as third-party for our purposes
	if strings.HasPrefix(importPath, "golang.org/x/") {
		return false
	}
	return true
}

// ── Function definition extraction ────────────────────────────────────────

type funcDefInfo struct {
	Name     string
	Receiver string // e.g., "*Conn"
	QName    string // "Recv.Name" for methods, else Name
	File     string
	Line     int
	Node     ast.Node // *ast.FuncDecl or *ast.FuncLit
	FileAST  *ast.File
}

func extractFuncDefs(fset *token.FileSet, files []fileInfo) []funcDefInfo {
	var defs []funcDefInfo

	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}
		for _, decl := range fi.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				def := funcDefInfo{
					Name:    d.Name.Name,
					QName:   qualName(d),
					File:    fi.relPath,
					Line:    fset.Position(d.Pos()).Line,
					Node:    d,
					FileAST: fi.file,
				}
				if d.Recv != nil && len(d.Recv.List) > 0 {
					def.Receiver = receiverType(d.Recv.List[0].Type)
				}
				defs = append(defs, def)

			case *ast.GenDecl:
				// Handle: var FuncName = func(...) { ... }
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) == 0 {
						continue
					}
					for idx, name := range vs.Names {
						if idx < len(vs.Values) {
							if fl, ok := vs.Values[idx].(*ast.FuncLit); ok {
								defs = append(defs, funcDefInfo{
									Name:    name.Name,
									File:    fi.relPath,
									Line:    fset.Position(fl.Pos()).Line,
									Node:    fl,
									FileAST: fi.file,
								})
							}
						}
					}
				}
			}
		}
	}

	return defs
}

// recvBase 返回方法接收者的类型名（去掉指针与泛型参数）；非方法返回 ""
func recvBase(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	switch x := t.(type) {
	case *ast.IndexExpr:
		t = x.X
	case *ast.IndexListExpr:
		t = x.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// qualName 给方法加上接收者类型前缀，避免同一文件内不同类型的同名方法互相覆盖
func qualName(fd *ast.FuncDecl) string {
	if r := recvBase(fd); r != "" {
		return r + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// bareName 去掉 qualName 加的接收者前缀（focus 过滤仍按裸函数名）
func bareName(n string) string {
	if i := strings.LastIndex(n, "."); i >= 0 {
		return n[i+1:]
	}
	return n
}

func receiverType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return "*" + exprName(t.X)
	case *ast.Ident:
		return t.Name
	default:
		return exprName(expr)
	}
}

func exprName(expr ast.Expr) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func filterFuncDefs(defs []funcDefInfo, focusFuncs []string, focusFiles map[string]bool) []FuncDef {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}

	var result []FuncDef
	for _, d := range defs {
		if len(focusFuncs) > 0 && !focusSet[d.Name] {
			continue
		}
		if len(focusFiles) > 0 && !focusFiles[d.File] {
			continue
		}
		fd := FuncDef{
			Name:     d.Name,
			Receiver: d.Receiver,
			QName:    d.QName,
			File:     d.File,
			Line:     d.Line,
		}
		result = append(result, fd)
	}
	return result
}

// ── Call chain extraction ─────────────────────────────────────────────────

func extractCallChains(fset *token.FileSet, files []fileInfo, allFuncs []funcDefInfo, focusFuncs []string) []CallChain {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}

	// Build function lookup map: name -> []funcDefInfo
	funcMap := make(map[string][]funcDefInfo)
	for _, fd := range allFuncs {
		funcMap[fd.Name] = append(funcMap[fd.Name], fd)
	}

	// Build import alias map per file: alias -> package path
	importMaps := make(map[string]*importMap)
	for _, fi := range files {
		im := &importMap{aliases: make(map[string]string)}
		for _, imp := range fi.file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			// Get package name from path
			parts := strings.Split(path, "/")
			pkgName := parts[len(parts)-1]
			if imp.Name != nil {
				im.aliases[imp.Name.Name] = path
			} else {
				im.aliases[pkgName] = path
			}
		}
		importMaps[fi.relPath] = im
	}

	var chains []CallChain

		for _, fi := range files {
			if strings.HasSuffix(fi.relPath, "_test.go") {
				continue
			}

			iterFuncDecls(fi, func(v funcVisitor) {
				if len(focusFuncs) > 0 && !focusSet[bareName(v.name)] {
					return
				}

				calls := extractCallsFromNode(v.body, v.file, importMaps[v.file], 1)

				var depth2Calls []CallEntry
				for _, c := range calls {
					depth2Calls = append(depth2Calls, c)
					if c.Type == "local" || c.Type == "method" {
						targetName := c.Callee
						if idx := strings.LastIndex(targetName, "."); idx >= 0 {
							targetName = targetName[idx+1:]
						}
						if defs, ok := funcMap[targetName]; ok {
							for _, def := range defs {
								body := funcBody(def.Node)
								if body != nil {
									im := importMaps[def.File]
									subCalls := extractCallsFromNode(body, def.File, im, 2)
									for _, sc := range subCalls {
										depth2Calls = append(depth2Calls, sc)
									}
								}
							}
						}
					}
				}

				chains = append(chains, CallChain{
					RootFunction: v.name,
					RootFile:     v.file,
					Calls:        depth2Calls,
				})
			})
		}

		return chains
	}
func extractCallsFromNode(node ast.Node, currentFile string, imports *importMap, depth int) []CallEntry {
	var calls []CallEntry
	seen := make(map[string]bool)

	ast.Inspect(node, func(n ast.Node) bool {
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		var callee string
		var callType string
		var pkg string

		switch fun := callExpr.Fun.(type) {
		case *ast.Ident:
			// Simple call: foo()
			callee = fun.Name
			// Check if it's a built-in or type conversion
			if isBuiltin(fun.Name) || isTypeConversion(fun.Name) {
				return true
			}
			callType = "local"

		case *ast.SelectorExpr:
			// Method or package call: obj.Method() or pkg.Func()
			callee = fun.Sel.Name
			callType = "method"

			// Check if the prefix is a package name or alias
			if ident, ok := fun.X.(*ast.Ident); ok {
				prefix := ident.Name
				if imports != nil {
					if pkgPath, isImport := imports.aliases[prefix]; isImport {
						// It's a package-qualified call
						callee = prefix + "." + fun.Sel.Name
						pkg = pkgPath
						if isStdlib(pkgPath) {
							callType = "stdlib"
						} else {
							callType = "third_party"
						}
					} else {
						// It's a method call on a variable: x.Method()
						callee = prefix + "." + fun.Sel.Name
						callType = "method"
					}
				}
			} else {
				// Complex expression: could be chained calls, ignore
				callee = fun.Sel.Name
				callType = "method"
			}

		case *ast.FuncLit:
			// Immediately invoked function literal: func() { ... }()
			return true // recurse into it

		default:
			return true
		}

		if callType == "builtin" {
			return true
		}

		if !seen[callee] {
			seen[callee] = true
			calls = append(calls, CallEntry{
				Callee:  callee,
				Depth:   depth,
				Type:    callType,
				Package: pkg,
			})
		}

		return true
	})

	return calls
}

var builtins = map[string]bool{
	"make": true, "new": true, "len": true, "cap": true, "append": true,
	"copy": true, "delete": true, "close": true, "panic": true,
	"recover": true, "print": true, "println": true, "complex": true,
	"real": true, "imag": true,
}

// Type conversions that should not be treated as function calls.
var typeConversions = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
	"string": true, "byte": true, "rune": true, "bool": true,
	"uintptr": true,
}

func isBuiltin(name string) bool {
	return builtins[name]
}

func isTypeConversion(name string) bool {
	return typeConversions[name]
}

// ── Stdlib signal extraction ──────────────────────────────────────────────

func extractStdlibSignals(imports map[string]*FileImports) []StdlibSignal {
	seen := make(map[string]bool)
	var signals []StdlibSignal

	for _, fi := range imports {
		for _, pkg := range fi.Stdlib {
			if seen[pkg] {
				continue
			}
			seen[pkg] = true

			info, ok := stdlibDomainMap[pkg]
			if !ok {
				continue
			}

			signals = append(signals, StdlibSignal{
				Package:     pkg,
				APIs:        info.sensitiveAPIs,
				DomainHints: info.domainHints,
			})
		}
	}

	// Sort by package name for deterministic output
	sort.Slice(signals, func(i, j int) bool {
		return signals[i].Package < signals[j].Package
	})

	return signals
}

// ── Data flow indicator extraction ────────────────────────────────────────

// gatePatterns filters patterns down to those whose import gate (if any) is
// satisfied by the file's imports. An empty gate list means "always active".
func gatePatterns(patterns []flowPattern, fileImports map[string]bool) []flowPattern {
	active := make([]flowPattern, 0, len(patterns))
	for _, p := range patterns {
		if importGateSatisfied(fileImports, p.gateImports) {
			active = append(active, p)
		}
	}
	return active
}

// importGateSatisfied reports whether the gate is satisfied: either the
// pattern is ungated, or the file imports one of the gate paths or a
// subpackage under it. The "/" suffix keeps github.com/labstack/echo from
// matching github.com/labstack/echo-middleware.
func importGateSatisfied(fileImports map[string]bool, gate []string) bool {
	if len(gate) == 0 {
		return true
	}
	for imported := range fileImports {
		for _, g := range gate {
			if imported == g || strings.HasPrefix(imported, g+"/") {
				return true
			}
		}
	}
	return false
}

func extractDataFlow(fset *token.FileSet, files []fileInfo, focusFuncs []string) []DataFlowIndicator {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}

	var indicators []DataFlowIndicator

	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}

		// Receiver-name patterns (c.Query( etc.) are gated on the file's
		// imports so they only fire inside the framework they belong to.
		fileImports := make(map[string]bool)
		for _, imp := range fi.file.Imports {
			fileImports[strings.Trim(imp.Path.Value, `"`)] = true
		}
		activeSources := gatePatterns(sourcePatterns, fileImports)
		activeSinks := gatePatterns(sinkPatterns, fileImports)

		iterFuncDecls(fi, func(v funcVisitor) {
			if len(focusFuncs) > 0 && !focusSet[bareName(v.name)] {
				return
			}

			var sources, sinks []FlowPoint
			var sanitizers []SanitizerPoint

			ast.Inspect(v.body, func(n ast.Node) bool {
				if n == nil {
					return true
				}
				line := fset.Position(n.Pos()).Line

				// Get source text of the call/expression
				var code string
				if callExpr, ok := n.(*ast.CallExpr); ok {
					code = exprToString(callExpr.Fun) + "("
				} else {
					code = exprToString(n)
				}

				// Check source patterns
				for _, sp := range activeSources {
					if strings.Contains(code, sp.pattern) {
						sources = append(sources, FlowPoint{
							Line:    line,
							Pattern: code,
							Type:    sp.fType,
						})
						break
					}
				}

				// Check sink patterns
				for _, sk := range activeSinks {
					if strings.Contains(code, sk.pattern) {
						sinks = append(sinks, FlowPoint{
							Line:    line,
							Pattern: code,
							Type:    sk.fType,
						})
						break
					}
				}

				// Check sanitizer patterns
				for _, sa := range sanitizerPatterns {
					if strings.Contains(code, sa.pattern) {
						sanitizers = append(sanitizers, SanitizerPoint{
							Line:     line,
							Pattern:  code,
							Category: sa.category,
						})
						break
					}
				}

				return true
			})

			if len(sources) > 0 || len(sinks) > 0 {
				indicators = append(indicators, DataFlowIndicator{
					Function:   v.name,
					File:       v.file,
					Sources:    sources,
					Sinks:      sinks,
					Sanitizers: sanitizers,
				})
			}
		})
	}

	return indicators
}

// ── Concurrency pattern extraction ────────────────────────────────────────

func extractConcurrency(fset *token.FileSet, files []fileInfo, focusFuncs []string) []ConcurrencyPattern {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}

	var patterns []ConcurrencyPattern

	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}

		iterFuncDecls(fi, func(v funcVisitor) {
			if len(focusFuncs) > 0 && !focusSet[bareName(v.name)] {
				return
			}

			ast.Inspect(v.body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.GoStmt:
					patterns = append(patterns, ConcurrencyPattern{
						File:     v.file,
						Function: v.name,
						Line:     fset.Position(node.Pos()).Line,
						Type:     "goroutine",
						Code:     exprToString(node.Call.Fun),
					})
				case *ast.SendStmt:
					patterns = append(patterns, ConcurrencyPattern{
						File:     v.file,
						Function: v.name,
						Line:     fset.Position(node.Pos()).Line,
						Type:     "channel_send",
						Code:     exprToString(node.Chan) + " <- ...",
					})
				case *ast.UnaryExpr:
					if node.Op == token.ARROW {
						patterns = append(patterns, ConcurrencyPattern{
							File:     v.file,
							Function: v.name,
							Line:     fset.Position(node.Pos()).Line,
							Type:     "channel_recv",
							Code:     "<- " + exprToString(node.X),
						})
					}
				}
				return true
			})
		})
	}

	return patterns
}

// ── Utilities ─────────────────────────────────────────────────────────────

// funcVisitor holds info about a function-like declaration.
type funcVisitor struct {
	name string
	body *ast.BlockStmt
	file string
}

// iterFuncDecls iterates over all function-like declarations in a file,
// including both func declarations and var FuncName = func() assignments.
func iterFuncDecls(fi fileInfo, visit func(v funcVisitor)) {
	for _, decl := range fi.file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body == nil {
				continue
			}
			visit(funcVisitor{
				name: qualName(d),
				body: d.Body,
				file: fi.relPath,
			})
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) == 0 {
					continue
				}
				for idx, name := range vs.Names {
					if idx < len(vs.Values) {
						if fl, ok := vs.Values[idx].(*ast.FuncLit); ok && fl.Body != nil {
							visit(funcVisitor{
								name: name.Name,
								body: fl.Body,
								file: fi.relPath,
							})
						}
					}
				}
			}
		}
	}
}

func funcBody(node ast.Node) *ast.BlockStmt {
	switch n := node.(type) {
	case *ast.FuncDecl:
		return n.Body
	case *ast.FuncLit:
		return n.Body
	}
	return nil
}

func exprToString(expr ast.Node) string {
	if expr == nil {
		return ""
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprToString(e.Fun) + "()"
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.UnaryExpr:
		return e.Op.String() + " " + exprToString(e.X)
	case *ast.BinaryExpr:
		return exprToString(e.X) + " " + e.Op.String() + " " + exprToString(e.Y)
	case *ast.IndexExpr:
		return exprToString(e.X) + "[" + exprToString(e.Index) + "]"
	case *ast.ParenExpr:
		return "(" + exprToString(e.X) + ")"
	case *ast.TypeAssertExpr:
		return exprToString(e.X) + ".(" + exprToString(e.Type) + ")"
	case *ast.KeyValueExpr:
		return exprToString(e.Key) + ": " + exprToString(e.Value)
	case *ast.SliceExpr:
		return exprToString(e.X) + "[...]"
	case *ast.FuncLit:
		return "func() { ... }"
	case *ast.CompositeLit:
		return exprToString(e.Type) + "{...}"
	default:
		return ""
	}
}

// ── Guard-chain extraction (`--guards`) ──────────────────────────────
//
// A function's early returns between its entry and a reported line are the
// specification of what must hold for that line to execute. Handing an
// experiment designer that list — instead of letting it guess and see only a
// status code when it guesses wrong — is what makes a stateful scenario
// testable. Kept in its own subcommand so the detection pipeline's output is
// untouched.

type Guard struct {
	Line      int      `json:"line"`
	Condition string   `json:"condition"`
	Returns   string   `json:"returns"`
	DependsOn []string `json:"depends_on,omitempty"`
	Kind      string   `json:"kind"`
}

type GuardResult struct {
	File      string  `json:"file"`
	Function  string  `json:"function"`
	FuncStart int     `json:"func_start"`
	FuncEnd   int     `json:"func_end"`
	TargetentLine int `json:"target_line"`
	Guards    []Guard `json:"guards"`
}

// exprText renders a node back to source, trimmed to keep output readable.
func exprText(fset *token.FileSet, n ast.Node) string {
	if n == nil {
		return ""
	}
	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return ""
	}
	s := strings.Join(strings.Fields(buf.String()), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// statusOf names the HTTP status (or error form) a return statement yields.
func statusOf(fset *token.FileSet, ret *ast.ReturnStmt) string {
	if ret == nil || len(ret.Results) == 0 {
		return "return"
	}
	first := exprText(fset, ret.Results[0])
	if strings.HasPrefix(first, "http.Status") {
		return strings.TrimPrefix(first, "http.")
	}
	return first
}

// callsIn lists the selector-style calls an expression performs, e.g.
// "cache.GetLength" or "d.Check" — the state a guard depends on.
func callsIn(fset *token.FileSet, n ast.Node) []string {
	seen := map[string]bool{}
	var out []string
	ast.Inspect(n, func(node ast.Node) bool {
		switch v := node.(type) {
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				name := exprText(fset, sel)
				if name != "" && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		case *ast.SelectorExpr:
			name := exprText(fset, v)
			if strings.Count(name, ".") >= 2 && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		return true
	})
	return out
}

// returnsWithin reports whether the statement contains a return of its own.
func returnsWithin(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if found {
			return false
		}
		switch node.(type) {
		case *ast.ReturnStmt:
			found = true
			return false
		case *ast.FuncLit:
			return false // a nested closure's return is not this one's
		}
		return true
	})
	return found
}

func extractGuards(dir, relFile, funcName string, targetLine int) (*GuardResult, error) {
	fset := token.NewFileSet()
	path := filepath.Join(dir, relFile)
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var target ast.Node
	var body *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != funcName || fd.Body == nil {
			return true
		}
		target, body = fd, fd.Body
		return false
	})
	if body == nil {
		return nil, fmt.Errorf("function %s not found in %s", funcName, relFile)
	}

	res := &GuardResult{
		File: relFile, Function: funcName,
		FuncStart: fset.Position(target.Pos()).Line,
		FuncEnd:   fset.Position(target.End()).Line,
		TargetentLine: targetLine,
		Guards:    []Guard{},
	}
	limit := targetLine
	if limit <= 0 {
		limit = res.FuncEnd
	}

	add := func(line int, cond, ret, kind string, deps []string) {
		if line < res.FuncStart || line > limit {
			return
		}
		res.Guards = append(res.Guards, Guard{
			Line: line, Condition: cond, Returns: ret, Kind: kind, DependsOn: deps,
		})
	}

	// `x, err := call(); if err != nil { return ... }` is the dominant Go
	// idiom, and it puts the call one statement *above* the guard. Reading only
	// the condition yields a bare `err != nil` with no dependencies, which
	// hides exactly the state lookups worth knowing about — so each block
	// remembers what its preceding statements assigned.
	// Keyed by variable *and* line: `err` is reassigned throughout a function,
	// so a guard must resolve to the assignment directly above it, not to
	// whichever one the traversal happened to visit last.
	type assign struct {
		line  int
		calls []string
	}
	assignedBy := map[string][]assign{}
	recordAssign := func(st ast.Stmt) {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			return
		}
		var calls []string
		for _, rhs := range as.Rhs {
			calls = append(calls, callsIn(fset, rhs)...)
		}
		if len(calls) == 0 {
			return
		}
		line := fset.Position(as.Pos()).Line
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				assignedBy[id.Name] = append(assignedBy[id.Name], assign{line, calls})
			}
		}
	}
	var walkStmts func(list []ast.Stmt)
	walkStmts = func(list []ast.Stmt) {
		for _, st := range list {
			recordAssign(st)
			switch b := st.(type) {
			case *ast.IfStmt:
				if b.Init != nil {
					recordAssign(b.Init)
				}
			case *ast.BlockStmt:
				walkStmts(b.List)
			case *ast.ExprStmt:
				if call, ok := b.X.(*ast.CallExpr); ok {
					if fl, ok := call.Fun.(*ast.FuncLit); ok && fl.Body != nil {
						walkStmts(fl.Body.List)
					}
				}
			case *ast.ReturnStmt:
				for _, r := range b.Results {
					if call, ok := r.(*ast.CallExpr); ok {
						for _, a := range call.Args {
							if fl, ok := a.(*ast.FuncLit); ok && fl.Body != nil {
								walkStmts(fl.Body.List)
							}
						}
					}
				}
			}
		}
	}
	walkStmts(body.List)

	// Dependencies of a guard: what its condition calls, plus what produced any
	// variable it tests.
	depsFor := func(cond ast.Expr) []string {
		at := fset.Position(cond.Pos()).Line
		seen := map[string]bool{}
		var out []string
		push := func(vals []string) {
			for _, v := range vals {
				if v != "" && !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
		push(callsIn(fset, cond))
		ast.Inspect(cond, func(node ast.Node) bool {
			id, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			best := -1
			var calls []string
			for _, a := range assignedBy[id.Name] {
				if a.line <= at && a.line > best {
					best, calls = a.line, a.calls
				}
			}
			push(calls)
			return true
		})
		return out
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.IfStmt:
			if v.Body != nil && returnsWithin(v.Body) {
				var ret string
				for _, st := range v.Body.List {
					if r, ok := st.(*ast.ReturnStmt); ok {
						ret = statusOf(fset, r)
						break
					}
				}
				add(fset.Position(v.Cond.Pos()).Line, exprText(fset, v.Cond), ret,
					"if", depsFor(v.Cond))
			}
		case *ast.SwitchStmt:
			for _, c := range v.Body.List {
				cc, ok := c.(*ast.CaseClause)
				if !ok || len(cc.Body) == 0 {
					continue
				}
				var ret string
				for _, st := range cc.Body {
					if r, ok := st.(*ast.ReturnStmt); ok {
						ret = statusOf(fset, r)
						break
					}
				}
				if ret == "" {
					continue
				}
				var conds []string
				var deps []string
				for _, e := range cc.List {
					conds = append(conds, exprText(fset, e))
					deps = append(deps, depsFor(e)...)
				}
				cond := strings.Join(conds, " | ")
				if cond == "" {
					cond = "default"
				}
				add(fset.Position(cc.Pos()).Line, cond, ret, "switch-case", deps)
			}
		}
		return true
	})

	sort.Slice(res.Guards, func(i, j int) bool { return res.Guards[i].Line < res.Guards[j].Line })
	return res, nil
}

// ── v3 R1: size-sensitive sinks ───────────────────────────────────────────
//
// A value parsed from text or bytes (strconv.Atoi, binary.BigEndian.Uint32, ...) and
// then used as an allocation length (make) or an index is the classic
// "attacker-controlled size" pattern (CWE-789 / CWE-129). Variables are tracked by
// name inside one function body: seeded by numeric-parse calls, then propagated
// through assignments whose right-hand side references a tracked variable.

var numericParseFuncs = []string{
	"strconv.Atoi", "strconv.ParseInt", "strconv.ParseUint",
	"binary.BigEndian.Uint16", "binary.BigEndian.Uint32", "binary.BigEndian.Uint64",
	"binary.LittleEndian.Uint16", "binary.LittleEndian.Uint32", "binary.LittleEndian.Uint64",
	"binary.Uvarint", "binary.Varint", "binary.ReadUvarint", "binary.ReadVarint",
}

func isNumericParseCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := exprToString(call.Fun)
	for _, f := range numericParseFuncs {
		if name == f {
			return true
		}
	}
	return false
}

// identsIn returns the identifier names referenced by an expression.
func identsIn(e ast.Node) map[string]bool {
	out := map[string]bool{}
	if e == nil {
		return out
	}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name != "_" {
			out[id.Name] = true
		}
		return true
	})
	return out
}

func firstTracked(e ast.Node, tracked map[string]bool) string {
	names := identsIn(e)
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if tracked[k] {
			return k
		}
	}
	return ""
}

func extractSizeFlows(fset *token.FileSet, files []fileInfo, focusFuncs []string) []SizeFlow {
	focusSet := make(map[string]bool)
	for _, f := range focusFuncs {
		focusSet[f] = true
	}
	var flows []SizeFlow
	for _, fi := range files {
		if strings.HasSuffix(fi.relPath, "_test.go") {
			continue
		}
		iterFuncDecls(fi, func(v funcVisitor) {
			if len(focusFuncs) > 0 && !focusSet[bareName(v.name)] {
				return
			}
			tracked := map[string]bool{}
			// seed: x := strconv.Atoi(...) / x, err = binary.Uvarint(...)
			ast.Inspect(v.body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) == 0 {
					return true
				}
				for _, rhs := range as.Rhs {
					if isNumericParseCall(rhs) {
						if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
							tracked[id.Name] = true
						}
					}
				}
				return true
			})
			if len(tracked) == 0 {
				return
			}
			// propagate: y := x + 1 / y = int(x) (fixed point, bounded)
			for pass := 0; pass < 4; pass++ {
				changed := false
				ast.Inspect(v.body, func(n ast.Node) bool {
					as, ok := n.(*ast.AssignStmt)
					if !ok || len(as.Lhs) != len(as.Rhs) {
						return true
					}
					for i, rhs := range as.Rhs {
						id, ok := as.Lhs[i].(*ast.Ident)
						if !ok || id.Name == "_" || tracked[id.Name] {
							continue
						}
						if firstTracked(rhs, tracked) != "" {
							tracked[id.Name] = true
							changed = true
						}
					}
					return true
				})
				if !changed {
					break
				}
			}
			var sinks []SizeSink
			var checks []RangeCheck
			ast.Inspect(v.body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "make" && len(x.Args) >= 2 {
						for _, a := range x.Args[1:] {
							if name := firstTracked(a, tracked); name != "" {
								sinks = append(sinks, SizeSink{Line: fset.Position(x.Pos()).Line, Type: "alloc_size",
									Var: name, Pattern: exprText(fset, x)})
								break
							}
						}
					}
				case *ast.IndexExpr:
					if name := firstTracked(x.Index, tracked); name != "" {
						sinks = append(sinks, SizeSink{Line: fset.Position(x.Pos()).Line, Type: "index_access",
							Var: name, Pattern: exprText(fset, x)})
					}
				case *ast.IfStmt:
					ast.Inspect(x.Cond, func(c ast.Node) bool {
						be, ok := c.(*ast.BinaryExpr)
						if !ok {
							return true
						}
						switch be.Op {
						case token.LSS, token.GTR, token.LEQ, token.GEQ:
							if name := firstTracked(be, tracked); name != "" {
								checks = append(checks, RangeCheck{Line: fset.Position(be.Pos()).Line, Var: name,
									Pattern: exprText(fset, be)})
							}
						}
						return true
					})
				}
				return true
			})
			if len(sinks) > 0 {
				flows = append(flows, SizeFlow{Function: v.name, File: v.file, SizeSinks: sinks, RangeChecks: checks})
			}
		})
	}
	return flows
}
