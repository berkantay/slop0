package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type ComplexityDetector struct{}

func (d *ComplexityDetector) Detect(domainPkgs []domain.Package, t domain.Thresholds) ([]domain.PatternIssue, error) {
	lr, err := loadSyntaxOnly(domainPkgs)
	if err != nil {
		return nil, fmt.Errorf("loading packages for complexity check: %w", err)
	}

	var issues []domain.PatternIssue
	for _, pkg := range lr.Pkgs {
		issues = append(issues, detectComplexityIssuesInPkg(pkg, lr.Fset, t)...)
	}
	return issues, nil
}

type complexityChecker func(*packages.Package, *token.FileSet, domain.Thresholds) []domain.PatternIssue

func detectBoolParamsWithThresholds(pkg *packages.Package, fset *token.FileSet, _ domain.Thresholds) []domain.PatternIssue {
	return detectBoolParams(pkg, fset)
}

var complexityCheckers = []complexityChecker{
	detectTooManyParams,
	detectTooManyReturns,
	detectBoolParamsWithThresholds,
	detectTooManyMethods,
	detectLongFunctions,
}

func detectComplexityIssuesInPkg(pkg *packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, check := range complexityCheckers {
		issues = append(issues, check(pkg, fset, t)...)
	}
	return issues
}

func countFields(fields *ast.FieldList) int {
	if fields == nil {
		return 0
	}
	count := 0
	for _, field := range fields.List {
		if len(field.Names) == 0 {
			count++
		} else {
			count += len(field.Names)
		}
	}
	return count
}

type fieldCheckConfig struct {
	selector func(*ast.FuncType) *ast.FieldList
	max      int
	category string
	dominant string
	label    string
}

func detectFieldCount(pkg *packages.Package, fset *token.FileSet, cfg fieldCheckConfig) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if count := countFields(cfg.selector(fn.Type)); count > cfg.max {
				pos := fset.Position(fn.Pos())
				issues = append(issues, domain.PatternIssue{
					Category:  cfg.category,
					Dominant:  cfg.dominant,
					Violation: fmt.Sprintf("%s.%s has %d %s", pkg.Name, fn.Name.Name, count, cfg.label),
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				})
			}
		}
	}
	return issues
}

func detectTooManyParams(pkg *packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	return detectFieldCount(pkg, fset, fieldCheckConfig{
		selector: func(ft *ast.FuncType) *ast.FieldList { return ft.Params },
		max:      t.MaxParams,
		category: "complexity/too-many-params",
		dominant: fmt.Sprintf("functions should have ≤%d params, use options struct for more — Go convention", t.MaxParams),
		label:    "parameters",
	})
}

func detectTooManyReturns(pkg *packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	return detectFieldCount(pkg, fset, fieldCheckConfig{
		selector: func(ft *ast.FuncType) *ast.FieldList { return ft.Results },
		max:      t.MaxReturns,
		category: "complexity/too-many-returns",
		dominant: fmt.Sprintf("functions should return ≤%d values — Go convention", t.MaxReturns),
		label:    "return values",
	})
}

func detectBoolParams(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			if issue := checkBoolParams(decl, pkg.Name, fname, fset); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	return issues
}

func checkBoolParams(decl ast.Decl, pkgName, fname string, fset *token.FileSet) *domain.PatternIssue {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Type.Params == nil || !ast.IsExported(fn.Name.Name) {
		return nil
	}

	boolCount, boolNames := countBoolParams(fn.Type.Params)
	if boolCount < 2 {
		return nil
	}

	pos := fset.Position(fn.Pos())
	return &domain.PatternIssue{
		Category:  "complexity/bool-params",
		Dominant:  "multiple bool params harm readability at call site — consider options struct or separate functions",
		Violation: fmt.Sprintf("%s.%s has %d bool params (%s)", pkgName, fn.Name.Name, boolCount, strings.Join(boolNames, ", ")),
		Locations: []domain.Location{{File: fname, Line: pos.Line}},
	}
}

func countBoolParams(params *ast.FieldList) (int, []string) {
	var count int
	var names []string
	for _, field := range params.List {
		if !isBoolType(field.Type) {
			continue
		}
		if len(field.Names) == 0 {
			count++
			names = append(names, "unnamed")
		}
		for _, name := range field.Names {
			count++
			names = append(names, name.Name)
		}
	}
	return count, names
}

func detectTooManyMethods(pkg *packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue

	typeMethods := make(map[string][]domain.Location)

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}

			recvType := receiverTypeName(fn.Recv.List[0].Type)
			if recvType == "" {
				continue
			}

			pos := fset.Position(fn.Pos())
			typeMethods[recvType] = append(typeMethods[recvType], domain.Location{File: fname, Line: pos.Line})
		}
	}

	for typeName, methods := range typeMethods {
		if len(methods) > t.MaxMethodsPerType {
			issues = append(issues, domain.PatternIssue{
				Category:  "complexity/god-type",
				Dominant:  fmt.Sprintf("types should have ≤%d methods — consider splitting responsibilities", t.MaxMethodsPerType),
				Violation: fmt.Sprintf("%s.%s has %d methods", pkg.Name, typeName, len(methods)),
				Locations: methods,
			})
		}
	}
	return issues
}

func detectLongFunctions(pkg *packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}

			lines := fset.Position(fn.Body.End()).Line - fset.Position(fn.Body.Pos()).Line
			if lines > t.FuncMaxLines {
				pos := fset.Position(fn.Pos())
				issues = append(issues, domain.PatternIssue{
					Category:  "complexity/long-function",
					Dominant:  fmt.Sprintf("functions should be ≤%d lines — extract helpers or split", t.FuncMaxLines),
					Violation: fmt.Sprintf("%s.%s is %d lines", pkg.Name, fn.Name.Name, lines),
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				})
			}
		}
	}
	return issues
}

func isBoolType(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "bool"
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	case *ast.IndexExpr:
		return receiverTypeName(e.X)
	}
	return ""
}

func (d *ComplexityDetector) DetectFromLoaded(pkgs []*packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		issues = append(issues, detectComplexityIssuesInPkg(pkg, fset, t)...)
	}
	return issues
}
