package rules

import "github.com/berkantay/slop0/internal/domain"

type CircularDetector struct{}

func (d *CircularDetector) Detect(pkgs []domain.Package) ([]domain.CircularDep, error) {
	graph, pkgSet := buildImportGraph(pkgs)
	return findCycles(graph, pkgSet), nil
}

func buildImportGraph(pkgs []domain.Package) (map[string][]string, map[string]bool) {
	graph := make(map[string][]string)
	pkgSet := make(map[string]bool)
	for _, pkg := range pkgs {
		pkgSet[pkg.Path] = true
		for _, imp := range pkg.Imports {
			graph[pkg.Path] = append(graph[pkg.Path], imp)
		}
	}
	return graph, pkgSet
}

type cycleWalker struct {
	graph   map[string][]string
	pkgSet  map[string]bool
	visited map[string]bool
	inStack map[string]bool
	cycles  []domain.CircularDep
}

func findCycles(graph map[string][]string, pkgSet map[string]bool) []domain.CircularDep {
	w := &cycleWalker{
		graph:   graph,
		pkgSet:  pkgSet,
		visited: make(map[string]bool),
		inStack: make(map[string]bool),
	}
	for node := range pkgSet {
		if !w.visited[node] {
			w.walk(node, nil)
		}
	}
	return w.cycles
}

func (w *cycleWalker) walk(node string, path []string) {
	if w.inStack[node] {
		recordCycle(node, path, &w.cycles)
		return
	}
	if w.visited[node] {
		return
	}

	w.visited[node] = true
	w.inStack[node] = true
	path = append(path, node)

	for _, neighbor := range w.graph[node] {
		if w.pkgSet[neighbor] {
			w.walk(neighbor, path)
		}
	}

	w.inStack[node] = false
}

func recordCycle(node string, path []string, cycles *[]domain.CircularDep) {
	start := -1
	for i, p := range path {
		if p == node {
			start = i
			break
		}
	}
	if start >= 0 {
		chain := append([]string{}, path[start:]...)
		chain = append(chain, node)
		*cycles = append(*cycles, domain.CircularDep{Chain: chain})
	}
}
