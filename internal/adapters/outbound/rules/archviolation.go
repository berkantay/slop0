package rules

import (
	"fmt"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type ArchViolationDetector struct{}

func (d *ArchViolationDetector) Detect(pkgs []domain.Package) ([]domain.LayerViolation, []domain.PatternIssue) {
	graph := buildPkgGraph(pkgs)
	layers := classifyByGraph(graph)

	var violations []domain.LayerViolation
	var issues []domain.PatternIssue

	violations = append(violations, detectInwardViolations(pkgs, layers)...)
	issues = append(issues, detectConcreteOverInterface(pkgs)...)

	return violations, issues
}

type layerKind int

const (
	layerUnknown layerKind = iota
	layerLeaf              // no project imports, only defines types (domain/model)
	layerOrchestrator      // imports leaf packages, defines interfaces or orchestrates
	layerBridge            // imports external libs AND implements interfaces (adapter)
	layerRoot              // has main(), wires everything
)

func (l layerKind) String() string {
	switch l {
	case layerLeaf:
		return "leaf"
	case layerOrchestrator:
		return "orchestrator"
	case layerBridge:
		return "bridge"
	case layerRoot:
		return "root"
	default:
		return "unknown"
	}
}

func (l layerKind) depth() int {
	switch l {
	case layerLeaf:
		return 0
	case layerOrchestrator:
		return 1
	case layerBridge:
		return 2
	case layerRoot:
		return 3
	default:
		return -1
	}
}

type pkgGraph struct {
	projectPkgs map[string]bool

	importsExternal    map[string]bool
	internalImports    map[string][]string
	importedByInternal map[string][]string

	hasInterfaces  map[string]bool
	implementsIface map[string]bool
	hasMain        map[string]bool
	hasTypes       map[string]bool

	inDegree  map[string]int
	outDegree map[string]int
}

func buildPkgGraph(pkgs []domain.Package) pkgGraph {
	g := pkgGraph{
		projectPkgs:        make(map[string]bool),
		importsExternal:    make(map[string]bool),
		internalImports:    make(map[string][]string),
		importedByInternal: make(map[string][]string),
		hasInterfaces:      make(map[string]bool),
		implementsIface:    make(map[string]bool),
		hasMain:            make(map[string]bool),
		hasTypes:           make(map[string]bool),
		inDegree:           make(map[string]int),
		outDegree:          make(map[string]int),
	}

	for _, pkg := range pkgs {
		g.projectPkgs[pkg.Path] = true
	}

	for _, pkg := range pkgs {
		populatePkgGraphEntry(&g, &pkg)
	}

	return g
}

func populatePkgGraphEntry(g *pkgGraph, pkg *domain.Package) {
	populateImports(g, pkg)
	populateTypeTraits(g, pkg)
	populateFuncTraits(g, pkg)
}

func populateImports(g *pkgGraph, pkg *domain.Package) {
	for _, imp := range pkg.Imports {
		if g.projectPkgs[imp] {
			g.internalImports[pkg.Path] = append(g.internalImports[pkg.Path], imp)
			g.importedByInternal[imp] = append(g.importedByInternal[imp], pkg.Path)
			g.outDegree[pkg.Path]++
			g.inDegree[imp]++
		} else if !isStdlib(imp) {
			g.importsExternal[pkg.Path] = true
		}
	}
}

func populateTypeTraits(g *pkgGraph, pkg *domain.Package) {
	for _, t := range pkg.Types {
		g.hasTypes[pkg.Path] = true
		if t.Kind == "interface" && len(t.Methods) > 0 {
			g.hasInterfaces[pkg.Path] = true
		}
		if len(t.Implements) > 0 {
			g.implementsIface[pkg.Path] = true
		}
	}
}

func populateFuncTraits(g *pkgGraph, pkg *domain.Package) {
	for _, fn := range pkg.Functions {
		if fn.Name == "main" {
			g.hasMain[pkg.Path] = true
		}
	}
}

func classifyByGraph(g pkgGraph) map[string]layerKind {
	layers := make(map[string]layerKind)

	for path := range g.projectPkgs {
		layers[path] = classifyPkg(path, g)
	}

	return layers
}

type pkgTraits struct {
	hasExternalDeps      bool
	hasInternalImports   bool
	isImportedByOthers   bool
	implementsInterfaces bool
	definesInterfaces    bool
	hasTypes             bool
}

func classifyPkg(path string, g pkgGraph) layerKind {
	if g.hasMain[path] {
		return layerRoot
	}

	traits := pkgTraits{
		hasExternalDeps:      g.importsExternal[path],
		hasInternalImports:   len(g.internalImports[path]) > 0,
		isImportedByOthers:   len(g.importedByInternal[path]) > 0,
		implementsInterfaces: g.implementsIface[path],
		definesInterfaces:    g.hasInterfaces[path],
		hasTypes:             g.hasTypes[path],
	}

	if traits.hasExternalDeps {
		return classifyExternalPkg(path, g, traits)
	}
	return classifyInternalPkg(traits)
}

func classifyExternalPkg(path string, g pkgGraph, t pkgTraits) layerKind {
	if t.implementsInterfaces {
		return layerBridge
	}
	if !isWidelyImported(path, g) {
		return layerBridge
	}
	return layerBridge
}

func classifyInternalPkg(t pkgTraits) layerKind {
	if !t.hasInternalImports && (t.hasTypes || t.definesInterfaces) {
		return layerLeaf
	}
	if !t.hasInternalImports && t.isImportedByOthers {
		return layerLeaf
	}
	if t.hasInternalImports {
		return layerOrchestrator
	}
	return layerUnknown
}

func isWidelyImported(path string, g pkgGraph) bool {
	return len(g.importedByInternal[path]) > 5
}

func isArchViolation(src, dst layerKind) bool {
	// Leaf should never import bridge or orchestrator
	if src == layerLeaf && (dst == layerBridge || dst == layerOrchestrator) {
		return true
	}
	// Orchestrator importing bridge is suspicious but common in wiring
	// Only flag orchestrator → root
	if src == layerOrchestrator && dst == layerRoot {
		return true
	}
	return false
}

func detectInwardViolations(pkgs []domain.Package, layers map[string]layerKind) []domain.LayerViolation {
	var violations []domain.LayerViolation

	projectPkgs := make(map[string]bool)
	for _, pkg := range pkgs {
		projectPkgs[pkg.Path] = true
	}

	for _, pkg := range pkgs {
		srcLayer := layers[pkg.Path]
		if srcLayer == layerUnknown {
			continue
		}

		for _, imp := range pkg.Imports {
			if !projectPkgs[imp] {
				continue
			}

			dstLayer := layers[imp]
			if dstLayer == layerUnknown {
				continue
			}

			if isArchViolation(srcLayer, dstLayer) {
				violations = append(violations, domain.LayerViolation{
					From:         fmt.Sprintf("%s (%s)", domain.ShortPkgName(pkg.Path), srcLayer),
					To:           fmt.Sprintf("%s (%s)", domain.ShortPkgName(imp), dstLayer),
					ExpectedPath: "dependencies should point inward: bridge → orchestrator → leaf",
					Location:     domain.Location{File: pkg.Path},
				})
			}
		}
	}

	return violations
}

func detectConcreteOverInterface(pkgs []domain.Package) []domain.PatternIssue {
	ifaceExists := collectInterfaceNames(pkgs)

	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if issue := checkConstructorReturn(fn, pkg, ifaceExists); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	return issues
}

func collectInterfaceNames(pkgs []domain.Package) map[string]bool {
	ifaceExists := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if t.Kind == "interface" {
				ifaceExists[t.Name] = true
			}
		}
	}
	return ifaceExists
}

func checkConstructorReturn(fn domain.Function, pkg domain.Package, ifaceExists map[string]bool) *domain.PatternIssue {
	if !strings.HasPrefix(fn.Name, "New") {
		return nil
	}

	concreteName := extractConcreteReturnName(fn.Signature)
	if concreteName == "" {
		return nil
	}

	for _, t := range pkg.Types {
		if t.Name != concreteName || len(t.Implements) == 0 {
			continue
		}
		for _, ifaceName := range t.Implements {
			if ifaceExists[ifaceName] {
				return &domain.PatternIssue{
					Category:  "arch/concrete-return",
					Dominant:  fmt.Sprintf("constructor returns *%s but it implements %s — consider returning the interface", concreteName, ifaceName),
					Violation: fmt.Sprintf("%s.%s returns concrete *%s", domain.ShortPkgName(pkg.Path), fn.Name, concreteName),
					Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
				}
			}
		}
	}
	return nil
}

func extractConcreteReturnName(signature string) string {
	parts := strings.SplitN(signature, ")", 2)
	if len(parts) < 2 {
		return ""
	}
	returnPart := strings.TrimSpace(parts[len(parts)-1])
	if !strings.HasPrefix(returnPart, "*") {
		return ""
	}

	concreteName := strings.TrimPrefix(returnPart, "*")
	if dotIdx := strings.LastIndex(concreteName, "."); dotIdx >= 0 {
		concreteName = concreteName[dotIdx+1:]
	}
	concreteName = strings.Split(concreteName, ",")[0]
	return strings.TrimSpace(concreteName)
}

func isStdlib(path string) bool {
	return !strings.Contains(path, ".")
}
