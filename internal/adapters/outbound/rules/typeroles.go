package rules

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type TypeRoleClassifier struct{}

func (c *TypeRoleClassifier) Classify(domainPkgs []domain.Package) ([]domain.TypeMetrics, error) {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}

	fanIn, fanOut := computeFanInOut(pkgs)
	fieldCounts := computeFieldCounts(pkgs)
	methodCounts := computeMethodCounts(pkgs)
	implCounts := computeImplCounts(domainPkgs)
	externalDeps := computeExternalFieldDeps(pkgs)
	lcom4 := computeLCOM4(pkgs, cfg.Fset)

	var metrics []domain.TypeMetrics
	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if _, ok := named.Underlying().(*types.Struct); !ok {
				continue
			}

			key := pkg.PkgPath + "." + name
			fi := fanIn[key]
			fo := fanOut[key]
			fields := fieldCounts[key]
			methods := methodCounts[key]
			impls := implCounts[key]
			hasExtDep := externalDeps[key]
			cohesion := lcom4[key]

			role := classifyRole(roleMetrics{fi, fo, fields, methods, impls, hasExtDep})

			metrics = append(metrics, domain.TypeMetrics{
				Name:        name,
				Package:     pkg.PkgPath,
				Role:        role,
				FanIn:       fi,
				FanOut:      fo,
				FieldCount:  fields,
				MethodCount: methods,
				LCOM4:       cohesion,
			})
		}
	}

	return metrics, nil
}

type roleMetrics struct {
	fanIn, fanOut, fields, methods, impls int
	hasExtDep                             bool
}

func classifyRole(m roleMetrics) domain.TypeRole {

	if isDataHolder(m) {
		return domain.RoleDataHolder
	}
	if isRepository(m) {
		return domain.RoleRepository
	}
	if isBoundary(m) {
		return domain.RoleBoundary
	}
	if isOrchestrator(m) {
		return domain.RoleOrchestrator
	}
	if isTransformer(m) {
		return domain.RoleTransformer
	}
	return domain.RoleUnknown
}

func isDataHolder(m roleMetrics) bool {
	return m.fields >= 3 && m.fanOut <= 1 && m.impls == 0
}

func isRepository(m roleMetrics) bool {
	return m.impls > 0 && m.hasExtDep && m.fanOut <= 3
}

func isBoundary(m roleMetrics) bool {
	return m.fanIn <= 2 && m.fanOut >= 2 && m.fields >= 1 && m.impls == 0
}

func isOrchestrator(m roleMetrics) bool {
	return m.impls > 0 && m.fanOut >= 2 && !m.hasExtDep
}

func isTransformer(m roleMetrics) bool {
	return m.fields == 0 && m.fanOut <= 1 && m.methods > 0
}

func computeFanInOut(pkgs []*packages.Package) (map[string]int, map[string]int) {
	fanIn := make(map[string]int)
	fanOut := make(map[string]int)

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		computeFanInOutForPkg(pkg, fanIn, fanOut)
	}

	return fanIn, fanOut
}

func computeFanInOutForPkg(pkg *packages.Package, fanIn, fanOut map[string]int) {
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}

			recvKey := resolveTypeKey(fn.Recv.List[0].Type, pkg)
			calledTypes := collectCalledTypes(fn, pkg, recvKey)

			for target := range calledTypes {
				fanOut[recvKey]++
				fanIn[target]++
			}
		}
	}
}

func collectCalledTypes(fn *ast.FuncDecl, pkg *packages.Package, recvKey string) map[string]bool {
	calledTypes := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		tv, ok := pkg.TypesInfo.Types[sel.X]
		if !ok {
			return true
		}
		targetKey := typeKey(tv.Type, pkg.PkgPath)
		if targetKey != "" && targetKey != recvKey {
			calledTypes[targetKey] = true
		}
		return true
	})
	return calledTypes
}

func computeFieldCounts(pkgs []*packages.Package) map[string]int {
	counts := make(map[string]int)
	for _, pkg := range pkgs {
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
			counts[pkg.PkgPath+"."+name] = st.NumFields()
		}
	}
	return counts
}

func computeMethodCounts(pkgs []*packages.Package) map[string]int {
	counts := make(map[string]int)
	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			counts[pkg.PkgPath+"."+name] = named.NumMethods()
		}
	}
	return counts
}

func computeImplCounts(pkgs []domain.Package) map[string]int {
	counts := make(map[string]int)
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if t.Kind == "struct" {
				counts[pkg.Path+"."+t.Name] = len(t.Implements)
			}
		}
	}
	return counts
}

func computeExternalFieldDeps(pkgs []*packages.Package) map[string]bool {
	result := make(map[string]bool)
	projectPkgs := make(map[string]bool)
	for _, pkg := range pkgs {
		projectPkgs[pkg.PkgPath] = true
	}

	for _, pkg := range pkgs {
		computeExternalFieldDepsForPkg(pkg, projectPkgs, result)
	}
	return result
}

func computeExternalFieldDepsForPkg(pkg *packages.Package, projectPkgs map[string]bool, result map[string]bool) {
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
		if hasExternalField(st, projectPkgs) {
			result[pkg.PkgPath+"."+name] = true
		}
	}
}

func hasExternalField(st *types.Struct, projectPkgs map[string]bool) bool {
	for i := 0; i < st.NumFields(); i++ {
		fieldPkg := extractTypePackage(st.Field(i).Type())
		if fieldPkg != "" && !projectPkgs[fieldPkg] && fieldPkg != "builtin" {
			return true
		}
	}
	return false
}

type lcom4Data struct {
	methodFields map[string]map[string]map[string]bool
	methodCalls  map[string]map[string]map[string]bool
}

func computeLCOM4(pkgs []*packages.Package, fset *token.FileSet) map[string]int {
	result := make(map[string]int)

	for _, pkg := range pkgs {
		data := collectLCOM4Data(pkg)
		computeLCOM4ForPkg(data, result)
	}

	return result
}

func collectLCOM4Data(pkg *packages.Package) lcom4Data {
	data := lcom4Data{
		methodFields: make(map[string]map[string]map[string]bool),
		methodCalls:  make(map[string]map[string]map[string]bool),
	}

	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			collectMethodAccess(fn, pkg, &data)
		}
	}

	return data
}

func collectMethodAccess(fn *ast.FuncDecl, pkg *packages.Package, data *lcom4Data) {
	recvType := resolveTypeKey(fn.Recv.List[0].Type, pkg)
	methodName := fn.Name.Name

	if data.methodFields[recvType] == nil {
		data.methodFields[recvType] = make(map[string]map[string]bool)
		data.methodCalls[recvType] = make(map[string]map[string]bool)
	}
	if data.methodFields[recvType][methodName] == nil {
		data.methodFields[recvType][methodName] = make(map[string]bool)
		data.methodCalls[recvType][methodName] = make(map[string]bool)
	}

	collectReceiverFieldAccess(fn, recvType, methodName, data)
	collectReceiverMethodCalls(fn, recvType, methodName, data)
}

func collectReceiverFieldAccess(fn *ast.FuncDecl, recvType, methodName string, data *lcom4Data) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			if isReceiverIdent(ident, fn.Recv) {
				data.methodFields[recvType][methodName][sel.Sel.Name] = true
			}
		}
		return true
	})
}

func collectReceiverMethodCalls(fn *ast.FuncDecl, recvType, methodName string, data *lcom4Data) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			if isReceiverIdent(ident, fn.Recv) {
				data.methodCalls[recvType][methodName][sel.Sel.Name] = true
			}
		}
		return true
	})
}

func computeLCOM4ForPkg(data lcom4Data, result map[string]int) {
	for typeName, methods := range data.methodFields {
		if len(methods) <= 1 {
			result[typeName] = 1
			continue
		}

		adj := buildMethodAdjacency(methods, data.methodCalls[typeName])
		methodNames := make([]string, 0, len(methods))
		for m := range methods {
			methodNames = append(methodNames, m)
		}
		result[typeName] = countComponents(methodNames, adj)
	}
}

func buildMethodAdjacency(methods map[string]map[string]bool, calls map[string]map[string]bool) map[string]map[string]bool {
	adj := make(map[string]map[string]bool)
	methodNames := make([]string, 0, len(methods))
	for m := range methods {
		methodNames = append(methodNames, m)
		adj[m] = make(map[string]bool)
	}

	for i := 0; i < len(methodNames); i++ {
		for j := i + 1; j < len(methodNames); j++ {
			m1, m2 := methodNames[i], methodNames[j]
			if !sharesField(methods[m1], methods[m2]) && !callsEachOther(calls, m1, m2) {
				continue
			}
			adj[m1][m2] = true
			adj[m2][m1] = true
		}
	}

	return adj
}

func callsEachOther(calls map[string]map[string]bool, m1, m2 string) bool {
	return calls[m1][m2] || calls[m2][m1]
}

func sharesField(a, b map[string]bool) bool {
	for f := range a {
		if b[f] {
			return true
		}
	}
	return false
}

func countComponents(nodes []string, adj map[string]map[string]bool) int {
	visited := make(map[string]bool)
	components := 0

	for _, node := range nodes {
		if visited[node] {
			continue
		}
		components++
		queue := []string{node}
		visited[node] = true
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			for neighbor := range adj[curr] {
				if !visited[neighbor] {
					visited[neighbor] = true
					queue = append(queue, neighbor)
				}
			}
		}
	}

	return components
}

func isReceiverIdent(ident *ast.Ident, recv *ast.FieldList) bool {
	if recv == nil || len(recv.List) == 0 {
		return false
	}
	for _, field := range recv.List {
		for _, name := range field.Names {
			if name.Name == ident.Name {
				return true
			}
		}
	}
	return false
}

func resolveTypeKey(expr ast.Expr, pkg *packages.Package) string {
	if pkg.TypesInfo == nil {
		return ""
	}
	tv, ok := pkg.TypesInfo.Types[expr]
	if !ok {
		return ""
	}
	t := tv.Type
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if named.Obj().Pkg() != nil {
			return named.Obj().Pkg().Path() + "." + named.Obj().Name()
		}
	}
	return ""
}

func typeKey(t types.Type, selfPkg string) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if named.Obj().Pkg() != nil {
			return named.Obj().Pkg().Path() + "." + named.Obj().Name()
		}
	}
	return ""
}

func extractTypePackage(t types.Type) string {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		if named.Obj().Pkg() != nil {
			return named.Obj().Pkg().Path()
		}
	}
	return ""
}

func (c *TypeRoleClassifier) ClassifyFromLoaded(domainPkgs []domain.Package, pkgs []*packages.Package, fset *token.FileSet) []domain.TypeMetrics {
	fanIn, fanOut := computeFanInOut(pkgs)
	fieldCounts := computeFieldCounts(pkgs)
	methodCounts := computeMethodCounts(pkgs)
	implCounts := computeImplCounts(domainPkgs)
	externalDeps := computeExternalFieldDeps(pkgs)
	lcom4 := computeLCOM4(pkgs, fset)

	var metrics []domain.TypeMetrics
	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			named, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if _, ok := named.Underlying().(*types.Struct); !ok {
				continue
			}

			key := pkg.PkgPath + "." + name
			m := roleMetrics{fanIn[key], fanOut[key], fieldCounts[key], methodCounts[key], implCounts[key], externalDeps[key]}
			metrics = append(metrics, domain.TypeMetrics{
				Name:        name,
				Package:     pkg.PkgPath,
				Role:        classifyRole(m),
				FanIn:       m.fanIn,
				FanOut:      m.fanOut,
				FieldCount:  m.fields,
				MethodCount: m.methods,
				LCOM4:       lcom4[key],
			})
		}
	}
	return metrics
}
