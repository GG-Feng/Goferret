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
	ParseMode           string                  `json:"parse_mode"`
}

type FileImports struct {
	Stdlib        []string `json:"stdlib"`
	ThirdParty    []string `json:"third_party"`
	StdlibMarkers []string `json:"stdlib_markers"`
}

type FuncDef struct {
	Name     string   `json:"name"`
	Receiver string   `json:"receiver,omitempty"`
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
	Function string      `json:"function"`
	File     string      `json:"file"`
	Sources  []FlowPoint `json:"sources"`
	Sinks    []FlowPoint `json:"sinks"`
}

type FlowPoint struct {
	Line    int    `json:"line"`
	Pattern string `json:"pattern"`
	Type    string `json:"type"`
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

// Source/sink patterns for data flow detection
var sourcePatterns = []struct {
	pattern string
	fType   string
}{
	{".Read(", "read"},
	{".ReadAll(", "read_all"},
	{".Recv(", "channel_recv"},
	{".Accept(", "network_accept"},
	{".ReadMessage(", "read_message"},
	{".ReadTCP(", "network_read"},
	{".ReadUDP(", "network_read"},
	{"http.Request", "http_request"},
	{".Body", "http_body"},
	{"bufio.NewReader(", "buffered_read"},
	{"json.Unmarshal(", "json_decode"},
	{"json.Decode(", "json_decode"},
	{"xml.Unmarshal(", "xml_decode"},
	{"binary.Read(", "binary_read"},
	{".Scan(", "scan"},
	{"io.Copy(", "io_copy"},
	{"io.CopyN(", "io_copy"},
}

var sinkPatterns = []struct {
	pattern string
	fType   string
}{
	{"exec.Command(", "command_execution"},
	{"os.Create(", "file_write"},
	{"os.Open(", "file_read"},
	{"os.OpenFile(", "file_write"},
	{"os.WriteFile(", "file_write"},
	{"filepath.Join(", "path_construction"},
	{"sql.Query(", "sql_query"},
	{"sql.Exec(", "sql_exec"},
	{"sql.QueryRow(", "sql_query"},
	{"http.Get(", "http_request"},
	{"http.Post(", "http_request"},
	{"template.HTML(", "html_injection"},
	{"template.JS(", "js_injection"},
	{"json.Marshal(", "json_encode"},
	{"fmt.Sprintf(", "string_format"},
	{"fmt.Sprintf(", "string_format"},
	{".Write(", "write"},
	{".WriteString(", "write"},
}

// ── Analysis ──────────────────────────────────────────────────────────────

func main() {
	dir := flag.String("dir", ".", "Source directory to analyze")
	focusFuncs := flag.String("focus-funcs", "", "Comma-separated function names to focus on")
	focusFiles := flag.String("focus-files", "", "Comma-separated file paths to focus on")
	flag.Parse()

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

	// Store function list (only for focus files)
	result.Functions = filterFuncDefs(allFuncs, focusFuncs, focusSet)
	result.ParseMode = "parser"

	return result, nil
}

// parseFilesLenient tries to parse Go files individually, skipping ones with errors.
func parseFilesLenient(fset *token.FileSet, dir string) (map[string]*ast.Package, error) {
	pkgs := make(map[string]*ast.Package)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
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
				if len(focusFuncs) > 0 && !focusSet[v.name] {
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

		iterFuncDecls(fi, func(v funcVisitor) {
			if len(focusFuncs) > 0 && !focusSet[v.name] {
				return
			}

			var sources, sinks []FlowPoint

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
				for _, sp := range sourcePatterns {
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
				for _, sk := range sinkPatterns {
					if strings.Contains(code, sk.pattern) {
						sinks = append(sinks, FlowPoint{
							Line:    line,
							Pattern: code,
							Type:    sk.fType,
						})
						break
					}
				}

				return true
			})

			if len(sources) > 0 || len(sinks) > 0 {
				indicators = append(indicators, DataFlowIndicator{
					Function: v.name,
					File:     v.file,
					Sources:  sources,
					Sinks:    sinks,
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
			if len(focusFuncs) > 0 && !focusSet[v.name] {
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
				name: d.Name.Name,
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
