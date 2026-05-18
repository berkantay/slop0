package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type DataFlowTracer struct{}

func (t *DataFlowTracer) Trace(pkgs []domain.Package, entries []domain.EntryPoint, boundaries []domain.ExternalDep) []domain.DataFlowPath {
	callGraph := make(map[string][]string)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			key := pkg.Path + "." + fn.Name
			callGraph[key] = fn.Calls
		}
	}

	boundaryFuncs := buildBoundaryFuncSet(pkgs, boundaries)

	var paths []domain.DataFlowPath
	for _, entry := range entries {
		chain := traceToSink(entry.Handler, callGraph, boundaryFuncs, 10)
		if len(chain) > 1 {
			paths = append(paths, domain.DataFlowPath{
				Entry: entry.Route,
				Chain: shortenChain(chain),
				Sink:  chain[len(chain)-1],
			})
		}
	}

	return paths
}

func buildBoundaryFuncSet(pkgs []domain.Package, boundaries []domain.ExternalDep) map[string]string {
	boundaryPkgs := make(map[string]string)
	for _, b := range boundaries {
		boundaryPkgs[b.UsedBy] = b.Kind
	}

	result := make(map[string]string)
	for _, pkg := range pkgs {
		kind, isBoundary := boundaryPkgs[pkg.Path]
		if !isBoundary {
			continue
		}
		for _, fn := range pkg.Functions {
			key := pkg.Path + "." + fn.Name
			result[key] = kind
		}
	}
	return result
}

type traceState struct {
	node string
	path []string
}

func traceToSink(start string, graph map[string][]string, sinks map[string]string, maxDepth int) []string {
	visited := make(map[string]bool)
	queue := []traceState{{node: start, path: []string{start}}}
	visited[start] = true

	var bestPath []string

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if len(curr.path) > maxDepth {
			continue
		}

		if _, isSink := sinks[curr.node]; isSink && len(curr.path) > 1 {
			bestPath = updateBestPath(bestPath, curr.path)
			continue
		}

		queue = expandTraceQueue(queue, curr, graph, visited)
	}

	return bestPath
}

func updateBestPath(bestPath, candidate []string) []string {
	if bestPath == nil || len(candidate) < len(bestPath) {
		result := make([]string, len(candidate))
		copy(result, candidate)
		return result
	}
	return bestPath
}

func expandTraceQueue(queue []traceState, curr traceState, graph map[string][]string, visited map[string]bool) []traceState {
	for _, next := range graph[curr.node] {
		if visited[next] {
			continue
		}
		visited[next] = true
		newPath := make([]string, len(curr.path)+1)
		copy(newPath, curr.path)
		newPath[len(curr.path)] = next
		queue = append(queue, traceState{node: next, path: newPath})
	}
	return queue
}

func shortenChain(chain []string) []string {
	short := make([]string, len(chain))
	for i, fn := range chain {
		parts := strings.Split(fn, "/")
		short[i] = parts[len(parts)-1]
	}
	return short
}
