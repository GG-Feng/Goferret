package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SourceSpan struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Line      int    `json:"line"`
	EndLine   int    `json:"end_line"`
	Signature string `json:"signature,omitempty"`
}
type FieldUse struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Line       int    `json:"line"`
	Offset     int    `json:"offset"`
	Expression string `json:"expression"`
	TypeID     string `json:"type_id,omitempty"`
	ScopeStart int    `json:"scope_start,omitempty"`
	BindingID  int    `json:"binding_id,omitempty"`
}
type LocalAssignment struct {
	Name       string `json:"name"`
	Line       int    `json:"line"`
	Offset     int    `json:"offset"`
	ScopeStart int    `json:"scope_start"`
	BindingID  int    `json:"binding_id,omitempty"`
	Expression string `json:"expression"`
}
type IndexedFile struct {
	Path        string            `json:"path"`
	Package     string            `json:"package"`
	Imports     []string          `json:"imports"`
	Spans       []SourceSpan      `json:"spans"`
	FieldUses   []FieldUse        `json:"field_uses,omitempty"`
	Assignments []LocalAssignment `json:"assignments,omitempty"`
	Error       string            `json:"error,omitempty"`
}
type SourceIndex struct {
	Files    []IndexedFile       `json:"files"`
	Excluded []map[string]string `json:"excluded"`
	Errors   []map[string]string `json:"errors"`
}

// Index independently of build tags and known security APIs. Unparsed files
// remain visible so semantic discovery can inspect them with an explicit gap.
func sourceIndex(root string) SourceIndex {
	out := SourceIndex{Files: []IndexedFile{}, Excluded: []map[string]string{}, Errors: []map[string]string{}}
	skip := map[string]bool{".git": true, "vendor": true, "node_modules": true, "testdata": true}
	packagePaths := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, walkErr error) error {
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if walkErr != nil {
			out.Errors = append(out.Errors, map[string]string{"path": rel, "reason": walkErr.Error()})
			return nil
		}
		if d.IsDir() {
			if p != root && skip[d.Name()] {
				out.Excluded = append(out.Excluded, map[string]string{"path": rel, "reason": "dependency_or_test_directory"})
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			out.Excluded = append(out.Excluded, map[string]string{"path": rel, "reason": "symlink"})
			return nil
		}
		if !strings.HasSuffix(rel, ".go") {
			return nil
		}
		if strings.HasSuffix(rel, "_test.go") {
			out.Excluded = append(out.Excluded, map[string]string{"path": rel, "reason": "test"})
			return nil
		}
		fs := token.NewFileSet()
		f, e := parser.ParseFile(fs, p, nil, parser.ParseComments|parser.AllErrors)
		item := IndexedFile{Path: rel, Spans: []SourceSpan{}, Imports: []string{}}
		if e != nil {
			item.Error = e.Error()
		}
		if f != nil {
			if ast.IsGenerated(f) {
				out.Excluded = append(out.Excluded, map[string]string{"path": rel, "reason": "generated"})
				return nil
			}
			item.Package = f.Name.Name
			for _, i := range f.Imports {
				s, _ := strconv.Unquote(i.Path.Value)
				item.Imports = append(item.Imports, s)
			}
			for _, decl := range f.Decls {
				name, kind := "declaration", "declaration"
				signature := ""
				if fd, ok := decl.(*ast.FuncDecl); ok {
					name = qualName(fd)
					kind = "function"
					signature = name + " " + exprText(fs, fd.Type)
				} else if gd, ok := decl.(*ast.GenDecl); ok {
					kind = strings.ToLower(gd.Tok.String())
					var names []string
					for _, spec := range gd.Specs {
						switch s := spec.(type) {
						case *ast.TypeSpec:
							names = append(names, s.Name.Name)
						case *ast.ValueSpec:
							for _, n := range s.Names {
								names = append(names, n.Name)
							}
						}
					}
					if len(names) > 0 {
						name = strings.Join(names, ",")
					}
				}
				item.Spans = append(item.Spans, SourceSpan{Name: name, Kind: kind, Line: fs.Position(decl.Pos()).Line, EndLine: fs.Position(decl.End()).Line, Signature: signature})
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if fl, ok := n.(*ast.FuncLit); ok {
					l := fs.Position(fl.Pos()).Line
					item.Spans = append(item.Spans, SourceSpan{Name: "closure@" + strconv.Itoa(l), Kind: "closure", Line: l, EndLine: fs.Position(fl.End()).Line, Signature: exprText(fs, fl.Type)})
				}
				return true
			})
			dir := filepath.Dir(p)
			pkgPath, found := packagePaths[dir]
			if !found {
				pkgPath = packageImportPath(root, dir)
				packagePaths[dir] = pkgPath
			}
			collectFieldFacts(fs, f, pkgPath, &item)
		}
		out.Files = append(out.Files, item)
		return nil
	})
	if err != nil {
		out.Errors = append(out.Errors, map[string]string{"path": ".", "reason": err.Error()})
	}
	return out
}
