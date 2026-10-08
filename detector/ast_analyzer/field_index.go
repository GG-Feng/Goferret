package main

import (
	"go/ast"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

func packageImportPath(root, dir string) string {
	for current := dir; ; current = filepath.Dir(current) {
		if data, err := os.ReadFile(filepath.Join(current, "go.mod")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "module" {
					module := strings.Trim(fields[1], "\"`")
					rel, err := filepath.Rel(current, dir)
					if err != nil {
						return ""
					}
					if rel == "." {
						return module
					}
					return module + "/" + filepath.ToSlash(rel)
				}
			}
			return ""
		}
		if current == root || filepath.Dir(current) == current {
			return ""
		}
	}
}

func explicitTypeID(expr ast.Expr, pkgPath string, aliases map[string]string) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return explicitTypeID(t.X, pkgPath, aliases)
	case *ast.ParenExpr:
		return explicitTypeID(t.X, pkgPath, aliases)
	case *ast.IndexExpr:
		return explicitTypeID(t.X, pkgPath, aliases)
	case *ast.IndexListExpr:
		return explicitTypeID(t.X, pkgPath, aliases)
	case *ast.Ident:
		if pkgPath != "" && t.Name != "" {
			return pkgPath + "." + t.Name
		}
	case *ast.SelectorExpr:
		if alias, ok := t.X.(*ast.Ident); ok {
			if imported := aliases[alias.Name]; imported != "" {
				return imported + "." + t.Sel.Name
			}
		}
	}
	return ""
}

func valueTypeID(expr ast.Expr, pkgPath string, aliases map[string]string) string {
	switch x := expr.(type) {
	case *ast.CompositeLit:
		return explicitTypeID(x.Type, pkgPath, aliases)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return valueTypeID(x.X, pkgPath, aliases)
		}
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
			return explicitTypeID(x.Args[0], pkgPath, aliases)
		}
	}
	return ""
}

type fieldScope struct {
	start, end token.Pos
	id         int
}

func addType(types map[*ast.Object]string, name *ast.Ident, typeID string) {
	if name == nil || name.Name == "_" || name.Obj == nil || typeID == "" {
		return
	}
	if old, exists := types[name.Obj]; exists && old != typeID {
		types[name.Obj] = ""
		return
	}
	if _, exists := types[name.Obj]; !exists {
		types[name.Obj] = typeID
	}
}

func collectFieldFacts(fs *token.FileSet, f *ast.File, pkgPath string, item *IndexedFile) {
	aliases := map[string]string{}
	for _, imp := range f.Imports {
		imported, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		alias := path.Base(imported)
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias != "_" && alias != "." {
			aliases[alias] = imported
		}
	}
	scopes := []fieldScope{}
	objectTypes := map[*ast.Object]string{}
	bindingIDs := map[*ast.Object]int{}
	bindingID := func(ident *ast.Ident) int {
		if ident == nil || ident.Obj == nil {
			return 0
		}
		if id := bindingIDs[ident.Obj]; id != 0 {
			return id
		}
		id := len(bindingIDs) + 1
		bindingIDs[ident.Obj] = id
		return id
	}
	ast.Inspect(f, func(n ast.Node) bool {
		var body *ast.BlockStmt
		var params *ast.FieldList
		var recv *ast.FieldList
		switch x := n.(type) {
		case *ast.FuncDecl:
			body, params, recv = x.Body, x.Type.Params, x.Recv
		case *ast.FuncLit:
			body, params = x.Body, x.Type.Params
		default:
			return true
		}
		if body == nil {
			return true
		}
		scope := fieldScope{start: body.Pos(), end: body.End(), id: int(body.Pos())}
		for _, list := range []*ast.FieldList{params, recv} {
			if list == nil {
				continue
			}
			for _, field := range list.List {
				id := explicitTypeID(field.Type, pkgPath, aliases)
				for _, name := range field.Names {
					addType(objectTypes, name, id)
				}
			}
		}
		ast.Inspect(body, func(node ast.Node) bool {
			if _, nested := node.(*ast.FuncLit); nested {
				return false
			}
			switch x := node.(type) {
			case *ast.ValueSpec:
				for i, name := range x.Names {
					id := explicitTypeID(x.Type, pkgPath, aliases)
					if id == "" && i < len(x.Values) {
						id = valueTypeID(x.Values[i], pkgPath, aliases)
					}
					addType(objectTypes, name, id)
				}
			case *ast.AssignStmt:
				if x.Tok == token.DEFINE {
					for i, lhs := range x.Lhs {
						name, ok := lhs.(*ast.Ident)
						if ok && i < len(x.Rhs) {
							addType(objectTypes, name,
								valueTypeID(x.Rhs[i], pkgPath, aliases))
						}
					}
				}
			}
			return true
		})
		scopes = append(scopes, scope)
		return true
	})
	scopeFor := func(pos token.Pos) *fieldScope {
		var best *fieldScope
		for i := range scopes {
			s := &scopes[i]
			if s.start <= pos && pos <= s.end && (best == nil || s.end-s.start < best.end-best.start) {
				best = s
			}
		}
		return best
	}
	writes := map[token.Pos]bool{}
	keyTypes := map[token.Pos]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					writes[sel.Sel.Pos()] = true
				}
			}
			for i, lhs := range x.Lhs {
				name, ok := lhs.(*ast.Ident)
				if !ok || i >= len(x.Rhs) {
					continue
				}
				scope := scopeFor(x.Pos())
				if scope != nil {
					item.Assignments = append(item.Assignments, LocalAssignment{
						Name: name.Name, Line: fs.Position(lhs.Pos()).Line,
						Offset:     fs.Position(lhs.Pos()).Offset,
						ScopeStart: scope.id, Expression: exprText(fs, x.Rhs[i]),
						BindingID: bindingID(name),
					})
				}
			}
		case *ast.ValueSpec:
			for i, name := range x.Names {
				if i < len(x.Values) {
					scope := scopeFor(x.Pos())
					if scope != nil {
						item.Assignments = append(item.Assignments, LocalAssignment{
							Name: name.Name, Line: fs.Position(name.Pos()).Line,
							Offset:     fs.Position(name.Pos()).Offset,
							ScopeStart: scope.id, Expression: exprText(fs, x.Values[i]),
							BindingID: bindingID(name),
						})
					}
				}
			}
		case *ast.IncDecStmt:
			if sel, ok := x.X.(*ast.SelectorExpr); ok {
				writes[sel.Sel.Pos()] = true
			}
		case *ast.CompositeLit:
			id := explicitTypeID(x.Type, pkgPath, aliases)
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					keyTypes[kv.Key.Pos()] = id
				}
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		scope := scopeFor(n.Pos())
		scopeStart := 0
		if scope != nil {
			scopeStart = scope.id
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			kind := "selector_read"
			if writes[x.Sel.Pos()] {
				kind = "selector_write"
			}
			id := ""
			if root, ok := x.X.(*ast.Ident); ok && root.Obj != nil {
				id = objectTypes[root.Obj]
			}
			item.FieldUses = append(item.FieldUses, FieldUse{
				Name: x.Sel.Name, Kind: kind,
				Line:       fs.Position(x.Sel.Pos()).Line,
				Offset:     fs.Position(x.Sel.Pos()).Offset,
				Expression: exprText(fs, x), TypeID: id, ScopeStart: scopeStart,
			})
		case *ast.KeyValueExpr:
			if field, ok := x.Key.(*ast.Ident); ok {
				valueBinding := 0
				if value, ok := x.Value.(*ast.Ident); ok {
					valueBinding = bindingID(value)
				}
				item.FieldUses = append(item.FieldUses, FieldUse{
					Name: field.Name, Kind: "literal_field",
					Line:       fs.Position(field.Pos()).Line,
					Offset:     fs.Position(field.Pos()).Offset,
					Expression: exprText(fs, x.Value),
					TypeID:     keyTypes[field.Pos()], ScopeStart: scopeStart,
					BindingID: valueBinding,
				})
			}
		}
		return true
	})
}
