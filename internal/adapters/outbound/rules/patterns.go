package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type DesignPatternDetector struct{}

type DetectedPattern = domain.DesignPattern
type PatternParticipant = domain.PatternParticipant

func (d *DesignPatternDetector) Detect(domainPkgs []domain.Package) ([]DetectedPattern, error) {
	detected := detectModelPatterns(domainPkgs)

	pkgs, fset, err := loadWithTypes(domainPkgs)
	if err != nil {
		return detected, nil
	}

	detected = append(detected, detectTypePatterns(pkgs, fset)...)
	return detected, nil
}

func detectModelPatterns(domainPkgs []domain.Package) []DetectedPattern {
	var detected []DetectedPattern
	detected = append(detected, detectPortAdapterFromModel(domainPkgs)...)
	detected = append(detected, detectStrategyFromModel(domainPkgs)...)
	return detected
}

type typedPatternChecker func([]*packages.Package, *token.FileSet) []DetectedPattern

var typedPatternCheckers = []typedPatternChecker{
	detectMiddlewareBySignature,
	detectDecoratorByType,
	detectSingletonByType,
	detectBuilderByChaining,
	detectFactoryByReturnType,
}

func detectTypePatterns(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
	for _, check := range typedPatternCheckers {
		detected = append(detected, check(pkgs, fset)...)
	}
	return detected
}

// Model-based: interface in pkg A, struct in pkg B implements it
func detectPortAdapterFromModel(pkgs []domain.Package) []DetectedPattern {
	ifacePkgs := collectInterfacePkgMap(pkgs)

	var detected []DetectedPattern
	for _, pkg := range pkgs {
		detected = append(detected, matchPortAdaptersInPkg(&pkg, ifacePkgs)...)
	}
	return detected
}

func collectInterfacePkgMap(pkgs []domain.Package) map[string]string {
	ifacePkgs := make(map[string]string)
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if t.Kind == "interface" && len(t.Methods) > 0 {
				ifacePkgs[t.Name] = pkg.Path
			}
		}
	}
	return ifacePkgs
}

func matchPortAdaptersInPkg(pkg *domain.Package, ifacePkgs map[string]string) []DetectedPattern {
	var detected []DetectedPattern
	for _, t := range pkg.Types {
		if t.Kind != "struct" || len(t.Implements) == 0 {
			continue
		}
		for _, ifaceName := range t.Implements {
			ifacePkg, ok := ifacePkgs[ifaceName]
			if !ok || ifacePkg == pkg.Path {
				continue
			}
			detected = append(detected, DetectedPattern{
				Name:        "interface-boundary",
				Description: fmt.Sprintf("%s.%s implements %s.%s", domain.ShortPkgName(pkg.Path), t.Name, domain.ShortPkgName(ifacePkg), ifaceName),
				Participants: []PatternParticipant{
					{Role: "port", Type: ifaceName, Package: ifacePkg},
					{Role: "adapter", Type: t.Name, Package: pkg.Path},
				},
			})
		}
	}
	return detected
}

// Model-based: interface with 2+ implementations across packages
func detectStrategyFromModel(pkgs []domain.Package) []DetectedPattern {
	implCount := make(map[string][]string)
	implPkgs := make(map[string][]string)

	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if t.Kind != "struct" || len(t.Implements) == 0 {
				continue
			}
			for _, ifaceName := range t.Implements {
				implCount[ifaceName] = append(implCount[ifaceName], t.Name)
				implPkgs[ifaceName] = append(implPkgs[ifaceName], pkg.Path)
			}
		}
	}

	var detected []DetectedPattern
	for ifaceName, impls := range implCount {
		if len(impls) < 2 {
			continue
		}
		participants := []PatternParticipant{{Role: "strategy-interface", Type: ifaceName}}
		for i, impl := range impls {
			participants = append(participants, PatternParticipant{
				Role: "implementation", Type: impl, Package: implPkgs[ifaceName][i],
			})
		}
		detected = append(detected, DetectedPattern{
			Name:         "strategy",
			Description:  fmt.Sprintf("%s with %d implementations: %s", ifaceName, len(impls), strings.Join(impls, ", ")),
			Participants: participants,
		})
	}
	return detected
}

// Type-based: function signature where input type == output type (wrapping)
func detectMiddlewareBySignature(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			detected = append(detected, detectMiddlewareInFile(pkg, file, fset)...)
		}
	}
	return detected
}

func detectMiddlewareInFile(pkg *packages.Package, file *ast.File, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
	for _, decl := range file.Decls {
		if p := checkMiddlewareSignature(decl, pkg, fset); p != nil {
			detected = append(detected, *p)
		}
	}
	return detected
}

func checkMiddlewareSignature(decl ast.Decl, pkg *packages.Package, fset *token.FileSet) *DetectedPattern {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok {
		return nil
	}

	sig := resolveFuncSignature(fn, pkg.TypesInfo)
	if sig == nil || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
		return nil
	}

	paramType := sig.Params().At(0).Type()
	resultType := sig.Results().At(0).Type()

	if !types.Identical(paramType, resultType) {
		return nil
	}

	pos := fset.Position(fn.Pos())
	return &DetectedPattern{
		Name:        "middleware",
		Description: fmt.Sprintf("%s.%s wraps %s", pkg.Name, fn.Name.Name, paramType),
		Participants: []PatternParticipant{
			{Role: "middleware", Type: fn.Name.Name, Package: pkg.PkgPath, File: pos.Filename, Line: pos.Line},
		},
	}
}

// Type-based: struct holds a field whose type is an interface,
// and the struct itself implements that same interface
func detectDecoratorByType(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
	for _, pkg := range pkgs {
		detected = append(detected, detectDecoratorsInPkg(pkg, fset)...)
	}
	return detected
}

func detectDecoratorsInPkg(pkg *packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
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
		detected = append(detected, findDecoratorFields(decoratorCandidate{st, named, obj, name, pkg, fset})...)
	}
	return detected
}

type decoratorCandidate struct {
	st    *types.Struct
	named *types.Named
	obj   types.Object
	name  string
	pkg   *packages.Package
	fset  *token.FileSet
}

func findDecoratorFields(c decoratorCandidate) []DetectedPattern {
	var detected []DetectedPattern
	ptrType := types.NewPointer(c.named)
	for i := 0; i < c.st.NumFields(); i++ {
		field := c.st.Field(i)
		fieldIface, ok := field.Type().Underlying().(*types.Interface)
		if !ok || fieldIface.NumMethods() == 0 {
			continue
		}
		if types.Implements(c.named, fieldIface) || types.Implements(ptrType, fieldIface) {
			pos := c.fset.Position(c.obj.Pos())
			detected = append(detected, DetectedPattern{
				Name:        "decorator",
				Description: fmt.Sprintf("%s.%s wraps and extends %s", c.pkg.Name, c.name, field.Name()),
				Participants: []PatternParticipant{
					{Role: "decorator", Type: c.name, Package: c.pkg.PkgPath, File: pos.Filename, Line: pos.Line},
					{Role: "decorated", Type: field.Name(), Package: c.pkg.PkgPath},
				},
			})
		}
	}
	return detected
}

// Type-based: package-level variable whose type is sync.Once
func detectSingletonByType(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			v, ok := obj.(*types.Var)
			if !ok {
				continue
			}

			if isSyncOnceType(v.Type()) {
				pos := fset.Position(obj.Pos())
				detected = append(detected, DetectedPattern{
					Name:        "singleton",
					Description: fmt.Sprintf("%s.%s uses sync.Once for initialization", pkg.Name, name),
					Participants: []PatternParticipant{
						{Role: "singleton", Type: name, Package: pkg.PkgPath, File: pos.Filename, Line: pos.Line},
					},
				})
			}
		}
	}
	return detected
}

type builderMethodInfo struct {
	name      string
	chainable bool
}

func detectBuilderByChaining(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	typeMethods := make(map[string][]builderMethodInfo)
	typePos := make(map[string]token.Position)

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		collectBuilderMethods(pkg, fset, typeMethods, typePos)
	}

	return matchBuilderPatterns(typeMethods, typePos)
}

func collectBuilderMethods(pkg *packages.Package, fset *token.FileSet, typeMethods map[string][]builderMethodInfo, typePos map[string]token.Position) {
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil {
				continue
			}

			sig := resolveFuncSignature(fn, pkg.TypesInfo)
			if sig == nil || sig.Recv() == nil {
				continue
			}

			recvType := sig.Recv().Type()
			key := recvType.String()

			if _, ok := typePos[key]; !ok {
				typePos[key] = fset.Position(fn.Pos())
			}

			typeMethods[key] = append(typeMethods[key], builderMethodInfo{
				name:      fn.Name.Name,
				chainable: isChainableReturn(sig),
			})
		}
	}
}

func isChainableReturn(sig *types.Signature) bool {
	if sig.Results().Len() < 1 {
		return false
	}
	recvType := sig.Recv().Type()
	retType := sig.Results().At(0).Type()

	if types.Identical(retType, recvType) {
		return true
	}
	if ptr, ok := retType.(*types.Pointer); ok {
		return types.Identical(ptr.Elem(), deref(recvType))
	}
	return false
}

func matchBuilderPatterns(typeMethods map[string][]builderMethodInfo, typePos map[string]token.Position) []DetectedPattern {
	var detected []DetectedPattern
	for key, methods := range typeMethods {
		var chainable []string
		for _, m := range methods {
			if m.chainable {
				chainable = append(chainable, m.name)
			}
		}
		if len(chainable) < 3 || float64(len(chainable))/float64(len(methods)) < 0.5 {
			continue
		}

		pos := typePos[key]
		parts := strings.Split(key, ".")
		typeName := strings.TrimPrefix(parts[len(parts)-1], "*")

		detected = append(detected, DetectedPattern{
			Name:        "builder",
			Description: fmt.Sprintf("%s has %d/%d chainable methods: %s", typeName, len(chainable), len(methods), strings.Join(chainable, ", ")),
			Participants: []PatternParticipant{
				{Role: "builder", Type: typeName, File: pos.Filename, Line: pos.Line},
			},
		})
	}
	return detected
}

func detectFactoryByReturnType(pkgs []*packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern

	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		detected = append(detected, detectFactoriesInPkg(pkg, fset)...)
	}
	return detected
}

func detectFactoriesInPkg(pkg *packages.Package, fset *token.FileSet) []DetectedPattern {
	var detected []DetectedPattern
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}

			sig := resolveFuncSignature(fn, pkg.TypesInfo)
			if sig == nil {
				continue
			}

			if p := matchFactoryReturn(sig, fn, pkg, fset); p != nil {
				detected = append(detected, *p)
			}
		}
	}
	return detected
}

func matchFactoryReturn(sig *types.Signature, fn *ast.FuncDecl, pkg *packages.Package, fset *token.FileSet) *DetectedPattern {
	for i := 0; i < sig.Results().Len(); i++ {
		retType := sig.Results().At(i).Type()
		if isErrorInterface(retType) {
			continue
		}
		if _, isIface := retType.Underlying().(*types.Interface); !isIface {
			continue
		}

		pos := fset.Position(fn.Pos())
		ifaceName := retType.String()
		if named, ok := retType.(*types.Named); ok {
			ifaceName = named.Obj().Name()
		}

		return &DetectedPattern{
			Name:        "factory",
			Description: fmt.Sprintf("%s.%s returns %s (interface — hides concrete type)", pkg.Name, fn.Name.Name, ifaceName),
			Participants: []PatternParticipant{
				{Role: "factory", Type: fn.Name.Name, Package: pkg.PkgPath, File: pos.Filename, Line: pos.Line},
			},
		}
	}
	return nil
}

func resolveFuncSignature(fn *ast.FuncDecl, info *types.Info) *types.Signature {
	obj := info.Defs[fn.Name]
	if obj == nil {
		return nil
	}
	sig, _ := obj.Type().(*types.Signature)
	return sig
}

func isSyncOnceType(t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == "sync" && obj.Name() == "Once"
}

func deref(t types.Type) types.Type {
	if ptr, ok := t.(*types.Pointer); ok {
		return ptr.Elem()
	}
	return t
}

func (d *DesignPatternDetector) DetectFromCache(domainPkgs []domain.Package, cache *PkgCache) ([]DetectedPattern, error) {
	detected := detectModelPatterns(domainPkgs)
	pkgs, fset := cache.Typed()
	detected = append(detected, detectTypePatterns(pkgs, fset)...)
	return detected, nil
}
