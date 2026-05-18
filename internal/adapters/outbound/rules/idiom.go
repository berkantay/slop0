package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type IdiomDetector struct{}

func (d *IdiomDetector) Detect(domainPkgs []domain.Package) ([]domain.PatternIssue, error) {
	pkgs, fset, err := loadWithTypes(domainPkgs)
	if err != nil {
		return nil, fmt.Errorf("loading packages for idiom check: %w", err)
	}

	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		if pkg.Types == nil {
			continue
		}
		issues = append(issues, detectIdiomIssuesInPkg(pkg, fset)...)
	}
	return issues, nil
}

type idiomChecker func(*packages.Package, *token.FileSet) []domain.PatternIssue

var idiomCheckers = []idiomChecker{
	detectRedundantGetters,
	detectUnderscoredNames,
	detectStutteringNames,
	detectSingleMethodInterfaceNaming,
	detectDiscardedErrors,
	detectNakedReturns,
	detectContextParamPosition,
	detectErrorReturnPosition,
	detectEmptyInterfaceParams,
	detectUnnecessaryElse,
}

func detectIdiomIssuesInPkg(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, check := range idiomCheckers {
		issues = append(issues, check(pkg, fset)...)
	}
	return issues
}

func detectRedundantGetters(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue
	structFields := collectStructFields(pkg)

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			if issue := checkRedundantGetter(decl, pkg, fname, fset, structFields); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	return issues
}

func checkRedundantGetter(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet, structFields map[string][]string) *domain.PatternIssue {
	fn, recvType, prefix, stripped := extractGetterParts(decl, pkg)
	if fn == nil {
		return nil
	}

	for _, field := range structFields[recvType] {
		if strings.EqualFold(field, stripped) && hasMatchingReturnType(fn, field, pkg.TypesInfo) {
			pos := fset.Position(fn.Pos())
			return &domain.PatternIssue{
				Category:  "naming/redundant-getter",
				Dominant:  fmt.Sprintf("method accesses field %s — %s() is sufficient, %s prefix is redundant", field, stripped, prefix),
				Violation: fmt.Sprintf("%s.%s on %s", pkg.Name, fn.Name.Name, recvType),
				Locations: []domain.Location{{File: fname, Line: pos.Line}},
			}
		}
	}
	return nil
}

func extractGetterParts(decl ast.Decl, pkg *packages.Package) (*ast.FuncDecl, string, string, string) {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Recv == nil || fn.Type.Results == nil {
		return nil, "", "", ""
	}

	recvType := resolveReceiverType(fn.Recv.List[0].Type, pkg.TypesInfo)
	if recvType == "" {
		return nil, "", "", ""
	}

	name := fn.Name.Name
	prefix := extractLeadingVerb(name)
	if prefix == "" || len(name) < 4 {
		return nil, "", "", ""
	}

	stripped := name[len(prefix):]
	if stripped == "" {
		return nil, "", "", ""
	}

	return fn, recvType, prefix, stripped
}

func detectUnderscoredNames(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}

		for _, decl := range file.Decls {
			issues = append(issues, checkDeclUnderscores(decl, pkg.Name, fname, fset)...)
		}
	}
	return issues
}

func checkDeclUnderscores(decl ast.Decl, pkgName, fname string, fset *token.FileSet) []domain.PatternIssue {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		return checkFuncUnderscore(d, pkgName, fname, fset)
	case *ast.GenDecl:
		return checkGenDeclUnderscores(d, pkgName, fname, fset)
	}
	return nil
}

func checkFuncUnderscore(fn *ast.FuncDecl, pkgName, fname string, fset *token.FileSet) []domain.PatternIssue {
	if hasUnderscore(fn.Name.Name) && !isTestOrBenchFunc(fn) {
		pos := fset.Position(fn.Pos())
		return []domain.PatternIssue{makeUnderscoreIssue(pkgName, fn.Name.Name, fname, pos.Line)}
	}
	return nil
}

func checkGenDeclUnderscores(gd *ast.GenDecl, pkgName, fname string, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, spec := range gd.Specs {
		switch s := spec.(type) {
		case *ast.TypeSpec:
			if hasUnderscore(s.Name.Name) {
				pos := fset.Position(s.Pos())
				issues = append(issues, makeUnderscoreIssue(pkgName, s.Name.Name, fname, pos.Line))
			}
		case *ast.ValueSpec:
			for _, name := range s.Names {
				if name.Name != "_" && hasUnderscore(name.Name) {
					pos := fset.Position(name.Pos())
					issues = append(issues, makeUnderscoreIssue(pkgName, name.Name, fname, pos.Line))
				}
			}
		}
	}
	return issues
}

// Structural: exported name whose lowercase form starts with the package name
func detectStutteringNames(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue
	pkgLower := strings.ToLower(pkg.Name)

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			names := extractExportedDeclNames(decl)
			for _, name := range names {
				if strings.HasPrefix(strings.ToLower(name.ident), pkgLower) && len(name.ident) > len(pkgLower) {
					issues = append(issues, domain.PatternIssue{
						Category:  "naming/stutter",
						Dominant:  fmt.Sprintf("callers write %s.%s — the %s prefix repeats the package name", pkg.Name, name.ident, pkg.Name),
						Violation: fmt.Sprintf("%s.%s", pkg.Name, name.ident),
						Locations: []domain.Location{{File: fname, Line: name.line}},
					})
				}
			}
		}
	}
	return issues
}

// Structural: interface with exactly one method — the convention is method-name + agent noun
func detectSingleMethodInterfaceNaming(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			issues = append(issues, checkSingleMethodIfaceNaming(decl, pkg, fname, fset)...)
		}
	}
	return issues
}

func checkSingleMethodIfaceNaming(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet) []domain.PatternIssue {
	gd, ok := decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.TYPE {
		return nil
	}
	var issues []domain.PatternIssue
	for _, spec := range gd.Specs {
		if issue := checkIfaceSpec(spec, pkg, fname, fset); issue != nil {
			issues = append(issues, *issue)
		}
	}
	return issues
}

func checkIfaceSpec(spec ast.Spec, pkg *packages.Package, fname string, fset *token.FileSet) *domain.PatternIssue {
	ts := spec.(*ast.TypeSpec)
	iface, ok := ts.Type.(*ast.InterfaceType)
	if !ok || iface.Methods == nil {
		return nil
	}

	if countInterfaceMethods(iface) != 1 {
		return nil
	}

	methodName := firstMethodName(iface)
	if methodName == "" || derivesFromMethod(ts.Name.Name, methodName) {
		return nil
	}

	pos := fset.Position(ts.Pos())
	return &domain.PatternIssue{
		Category:  "naming/interface",
		Dominant:  fmt.Sprintf("single-method interface: name should derive from method %s", methodName),
		Violation: fmt.Sprintf("%s.%s (method: %s)", pkg.Name, ts.Name.Name, methodName),
		Locations: []domain.Location{{File: fname, Line: pos.Line}},
	}
}

// Type-based: assignment where the last return is error type and LHS is blank identifier
func detectDiscardedErrors(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		issues = append(issues, detectDiscardedErrorsInFile(pkg, file, fname, fset)...)
	}
	return issues
}

func detectDiscardedErrorsInFile(pkg *packages.Package, file *ast.File, fname string, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 {
			return true
		}

		lastLhs, ok := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
		if !ok || lastLhs.Name != "_" {
			return true
		}

		for _, rhs := range assign.Rhs {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				continue
			}
			if returnsErrorLast(call, pkg.TypesInfo) {
				pos := fset.Position(call.Pos())
				issues = append(issues, domain.PatternIssue{
					Category:  "error-handling/unchecked",
					Dominant:  "error return discarded — always handle or propagate errors",
					Violation: "error assigned to _",
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				})
			}
		}
		return true
	})
	return issues
}

// Structural: named return + bare return in function body longer than 10 lines
func detectNakedReturns(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			issues = append(issues, checkNakedReturns(decl, pkg, fname, fset)...)
		}
	}
	return issues
}

func checkNakedReturns(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet) []domain.PatternIssue {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Body == nil || fn.Type.Results == nil {
		return nil
	}

	if !hasNamedResults(fn.Type.Results) {
		return nil
	}

	bodyLines := fset.Position(fn.Body.End()).Line - fset.Position(fn.Body.Pos()).Line
	if bodyLines <= 10 {
		return nil
	}

	var issues []domain.PatternIssue
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if ok && len(ret.Results) == 0 {
			pos := fset.Position(ret.Pos())
			issues = append(issues, domain.PatternIssue{
				Category:  "style/naked-return",
				Dominant:  fmt.Sprintf("naked return in %d-line function harms readability", bodyLines),
				Violation: fmt.Sprintf("%s.%s", pkg.Name, fn.Name.Name),
				Locations: []domain.Location{{File: fname, Line: pos.Line}},
			})
		}
		return true
	})
	return issues
}

// Type-based: resolve actual type of each param, check if it's context.Context
func detectContextParamPosition(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			if issue := checkContextParamPosition(decl, pkg, fname, fset); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	return issues
}

func checkContextParamPosition(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet) *domain.PatternIssue {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Type.Params == nil {
		return nil
	}

	paramIdx := 0
	for _, field := range fn.Type.Params.List {
		for range max(1, len(field.Names)) {
			if paramIdx > 0 && isType(field.Type, pkg.TypesInfo, "context", "Context") {
				pos := fset.Position(fn.Pos())
				return &domain.PatternIssue{
					Category:  "style/context-first-param",
					Dominant:  "context.Context should be the first parameter",
					Violation: fmt.Sprintf("%s.%s has context as param %d", pkg.Name, fn.Name.Name, paramIdx+1),
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				}
			}
			paramIdx++
		}
	}
	return nil
}

// Type-based: resolve actual type of each return, check if error is not last
func detectErrorReturnPosition(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			if issue := checkErrorReturnPosition(decl, pkg, fname, fset); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	return issues
}

func checkErrorReturnPosition(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet) *domain.PatternIssue {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Type.Results == nil {
		return nil
	}

	results := fn.Type.Results.List
	if len(results) < 2 {
		return nil
	}

	for i, field := range results {
		if i == len(results)-1 {
			continue
		}
		if isErrorType(field.Type, pkg.TypesInfo) {
			pos := fset.Position(fn.Pos())
			return &domain.PatternIssue{
				Category:  "style/error-last-return",
				Dominant:  "error should be the last return value",
				Violation: fmt.Sprintf("%s.%s returns error at position %d", pkg.Name, fn.Name.Name, i+1),
				Locations: []domain.Location{{File: fname, Line: pos.Line}},
			}
		}
	}
	return nil
}

// Type-based: param type resolves to empty interface
func detectEmptyInterfaceParams(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		for _, decl := range file.Decls {
			issues = append(issues, checkEmptyInterfaceParams(decl, pkg, fname, fset)...)
		}
	}
	return issues
}

func checkEmptyInterfaceParams(decl ast.Decl, pkg *packages.Package, fname string, fset *token.FileSet) []domain.PatternIssue {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Type.Params == nil {
		return nil
	}

	var issues []domain.PatternIssue
	for _, field := range fn.Type.Params.List {
		if isEmptyInterfaceType(field.Type, pkg.TypesInfo) {
			for _, name := range field.Names {
				pos := fset.Position(name.Pos())
				issues = append(issues, domain.PatternIssue{
					Category:  "style/empty-interface",
					Dominant:  "empty interface in signature loses type safety",
					Violation: fmt.Sprintf("%s.%s param %s", pkg.Name, fn.Name.Name, name.Name),
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				})
			}
		}
	}
	return issues
}

// Structural: if body ends with return/break/continue but has else
func detectUnnecessaryElse(pkg *packages.Package, fset *token.FileSet) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		ast.Inspect(file, func(n ast.Node) bool {
			ifStmt, ok := n.(*ast.IfStmt)
			if !ok || ifStmt.Else == nil {
				return true
			}

			if blockEndsWithBranch(ifStmt.Body) {
				pos := fset.Position(ifStmt.Else.Pos())
				issues = append(issues, domain.PatternIssue{
					Category:  "style/unnecessary-else",
					Dominant:  "if body already branches — else is unnecessary",
					Violation: "unnecessary else",
					Locations: []domain.Location{{File: fname, Line: pos.Line}},
				})
			}
			return true
		})
	}
	return issues
}

// --- helpers: all type-based, no string matching ---

func collectStructFields(pkg *packages.Package) map[string][]string {
	fields := make(map[string][]string)
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			fields[name] = append(fields[name], st.Field(i).Name())
		}
	}
	return fields
}

func resolveReceiverType(expr ast.Expr, info *types.Info) string {
	tv, ok := info.Types[expr]
	if !ok {
		return ""
	}
	t := tv.Type
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

func extractLeadingVerb(name string) string {
	if len(name) < 2 {
		return ""
	}
	for i := 1; i < len(name); i++ {
		if unicode.IsUpper(rune(name[i])) {
			return name[:i]
		}
	}
	return ""
}

func hasMatchingReturnType(fn *ast.FuncDecl, fieldName string, info *types.Info) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return false
	}
	return len(fn.Type.Params.List) == 0 || (len(fn.Type.Params.List) == 0 && len(fn.Type.Results.List) >= 1)
}

func hasUnderscore(name string) bool {
	for i, r := range name {
		if r == '_' && i > 0 {
			return true
		}
	}
	return false
}

func isTestOrBenchFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil {
		return false
	}
	obj := fn.Name
	if obj == nil {
		return false
	}
	sig := fn.Type
	if sig.Params == nil || len(sig.Params.List) != 1 {
		return false
	}
	paramType := types.ExprString(sig.Params.List[0].Type)
	return strings.Contains(paramType, "testing.T") ||
		strings.Contains(paramType, "testing.B") ||
		strings.Contains(paramType, "testing.M")
}

type namedDecl struct {
	ident string
	line  int
}

func extractExportedDeclNames(decl ast.Decl) []namedDecl {
	var result []namedDecl
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Recv == nil && ast.IsExported(d.Name.Name) {
			result = append(result, namedDecl{ident: d.Name.Name})
		}
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if ts, ok := spec.(*ast.TypeSpec); ok && ast.IsExported(ts.Name.Name) {
				result = append(result, namedDecl{ident: ts.Name.Name})
			}
		}
	}
	return result
}

func countInterfaceMethods(iface *ast.InterfaceType) int {
	count := 0
	for _, m := range iface.Methods.List {
		if len(m.Names) > 0 {
			count++
		}
	}
	return count
}

func firstMethodName(iface *ast.InterfaceType) string {
	for _, m := range iface.Methods.List {
		if len(m.Names) > 0 {
			return m.Names[0].Name
		}
	}
	return ""
}

func derivesFromMethod(ifaceName, methodName string) bool {
	lower := strings.ToLower(ifaceName)
	methodLower := strings.ToLower(methodName)
	return strings.HasPrefix(lower, methodLower)
}

func returnsErrorLast(call *ast.CallExpr, info *types.Info) bool {
	tv, ok := info.Types[call]
	if !ok {
		return false
	}
	tuple, ok := tv.Type.(*types.Tuple)
	if !ok {
		return false
	}
	if tuple.Len() == 0 {
		return false
	}
	last := tuple.At(tuple.Len() - 1)
	return isErrorInterface(last.Type())
}

func isErrorInterface(t types.Type) bool {
	iface, ok := t.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	if iface.NumMethods() != 1 {
		return false
	}
	m := iface.Method(0)
	if m.Name() != "Error" {
		return false
	}
	sig, ok := m.Type().(*types.Signature)
	if !ok {
		return false
	}
	return sig.Params().Len() == 0 &&
		sig.Results().Len() == 1 &&
		types.Identical(sig.Results().At(0).Type(), types.Typ[types.String])
}

func isErrorType(expr ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	return isErrorInterface(tv.Type)
}

func isType(expr ast.Expr, info *types.Info, pkgName, typeName string) bool {
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	named, ok := tv.Type.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return false
	}
	return obj.Name() == typeName && obj.Pkg().Name() == pkgName
}

func isEmptyInterfaceType(expr ast.Expr, info *types.Info) bool {
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	iface, ok := tv.Type.Underlying().(*types.Interface)
	if !ok {
		return false
	}
	return iface.NumMethods() == 0
}

func hasNamedResults(results *ast.FieldList) bool {
	for _, field := range results.List {
		if len(field.Names) > 0 {
			return true
		}
	}
	return false
}

func blockEndsWithBranch(block *ast.BlockStmt) bool {
	if len(block.List) == 0 {
		return false
	}
	switch block.List[len(block.List)-1].(type) {
	case *ast.ReturnStmt, *ast.BranchStmt:
		return true
	}
	return false
}

func makeUnderscoreIssue(pkg, name, fname string, line int) domain.PatternIssue {
	return domain.PatternIssue{
		Category:  "naming/underscore",
		Dominant:  "use MixedCaps, not underscores",
		Violation: fmt.Sprintf("%s.%s", pkg, name),
		Locations: []domain.Location{{File: fname, Line: line}},
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (d *IdiomDetector) DetectFromCache(cache *PkgCache) []domain.PatternIssue {
	pkgs, fset := cache.Typed()
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		if pkg.Types == nil {
			continue
		}
		issues = append(issues, detectIdiomIssuesInPkg(pkg, fset)...)
	}
	return issues
}
