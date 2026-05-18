package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type UntypedMapDetector struct{}

func (d *UntypedMapDetector) Detect(pkgs []*packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			fname := filepath.Base(fset.File(file.Pos()).Name())
			issues = append(issues, detectUntypedMapsInFile(pkg, file, fname, fset, t)...)
		}
	}
	return issues
}

func detectUntypedMapsInFile(pkg *packages.Package, file *ast.File, fname string, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue

	ast.Inspect(file, func(n ast.Node) bool {
		comp, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		if !isUntypedMapType(comp.Type, pkg.TypesInfo) {
			return true
		}

		keyCount := len(comp.Elts)
		if keyCount < t.MaxMapLiteralKeys {
			return true
		}

		pos := fset.Position(comp.Pos())
		enclosing := findEnclosingFunc(file, comp.Pos())

		issues = append(issues, domain.PatternIssue{
			Category:  "style/untyped-map",
			Dominant:  fmt.Sprintf("map[string]any with %d+ keys should be a typed struct", t.MaxMapLiteralKeys),
			Violation: fmt.Sprintf("%s.%s has %d-key map[string]any literal — use a struct for type safety", pkg.Name, enclosing, keyCount),
			Locations: []domain.Location{{File: fname, Line: pos.Line}},
		})

		return true
	})

	return issues
}

func isUntypedMapType(expr ast.Expr, info *types.Info) bool {
	if expr == nil {
		return false
	}

	tv, ok := info.Types[expr]
	if !ok {
		return isUntypedMapAST(expr)
	}

	mapType, ok := tv.Type.Underlying().(*types.Map)
	if !ok {
		return false
	}

	keyType := mapType.Key()
	if keyType.String() != "string" {
		return false
	}

	elemType := mapType.Elem()
	iface, ok := elemType.Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0
}

func isUntypedMapAST(expr ast.Expr) bool {
	mt, ok := expr.(*ast.MapType)
	if !ok {
		return false
	}

	keyIdent, ok := mt.Key.(*ast.Ident)
	if !ok || keyIdent.Name != "string" {
		return false
	}

	switch v := mt.Value.(type) {
	case *ast.Ident:
		return v.Name == "any"
	case *ast.InterfaceType:
		return v.Methods == nil || len(v.Methods.List) == 0
	}
	return false
}

func findEnclosingFunc(file *ast.File, pos token.Pos) string {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Body != nil && fn.Body.Pos() <= pos && pos <= fn.Body.End() {
			return fn.Name.Name
		}
	}
	return "init"
}
