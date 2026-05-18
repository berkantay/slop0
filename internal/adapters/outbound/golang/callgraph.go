package golang

import (
	"fmt"
	"go/token"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/berkantay/slop0/internal/application/ports/outbound"
)

type CallGraphBuilder struct{}

func NewCallGraphBuilder() *CallGraphBuilder {
	return &CallGraphBuilder{}
}

func (b *CallGraphBuilder) Build(patterns []string) (*outbound.CallGraphResult, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages for callgraph: %w", err)
	}

	prog, allPkgs := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	targetPkgs := buildTargetSet(allPkgs)
	graph := cha.CallGraph(prog)

	return extractEdges(graph, targetPkgs), nil
}

func buildTargetSet(allPkgs []*ssa.Package) map[string]bool {
	targets := make(map[string]bool)
	for _, pkg := range allPkgs {
		if pkg != nil {
			targets[pkg.Pkg.Path()] = true
		}
	}
	return targets
}

func extractEdges(graph *callgraph.Graph, targets map[string]bool) *outbound.CallGraphResult {
	result := &outbound.CallGraphResult{
		Calls:    make(map[string][]string),
		CalledBy: make(map[string][]string),
	}

	for fn, node := range graph.Nodes {
		if fn == nil || fn.Pkg == nil || !targets[fn.Pkg.Pkg.Path()] {
			continue
		}

		callerKey := qualifiedName(fn)
		seen := make(map[string]bool)

		for _, edge := range node.Out {
			callee := edge.Callee.Func
			if callee == nil || callee.Pkg == nil || !targets[callee.Pkg.Pkg.Path()] {
				continue
			}

			calleeKey := qualifiedName(callee)
			if seen[calleeKey] {
				continue
			}
			seen[calleeKey] = true

			result.Calls[callerKey] = append(result.Calls[callerKey], calleeKey)
			result.CalledBy[calleeKey] = append(result.CalledBy[calleeKey], callerKey)
		}
	}
	return result
}

func qualifiedName(fn *ssa.Function) string {
	if fn.Pkg == nil {
		return fn.Name()
	}

	pkgPath := fn.Pkg.Pkg.Path()
	name := fn.Name()

	if recv := fn.Signature.Recv(); recv != nil {
		typeName := strings.TrimPrefix(recv.Type().String(), "*")
		parts := strings.Split(typeName, ".")
		if len(parts) > 1 {
			return pkgPath + "." + parts[len(parts)-1] + "." + name
		}
	}

	return pkgPath + "." + name
}
