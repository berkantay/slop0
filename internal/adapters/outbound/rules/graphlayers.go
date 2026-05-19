package rules

import (
	"sort"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

func assignLayers(graph map[string][]string, nodes []string) ([]domain.LayerAssignment, []domain.LayerSkip) {
	sccs := tarjanSCC(graph, nodes)
	condensed, sccMap := condenseGraph(graph, sccs)
	layerMap := topologicalLayers(condensed)
	assignments := buildLayerAssignments(sccs, sccMap, layerMap)
	skips := findLayerSkips(graph, sccMap, layerMap)
	return assignments, skips
}

func condenseGraph(graph map[string][]string, sccs [][]string) (map[string][]string, map[string]string) {
	nodeToSCC := make(map[string]string)
	for i, scc := range sccs {
		label := scc[0]
		if len(scc) > 1 {
			label = strings.Join(scc, "+")
		}
		_ = i
		for _, n := range scc {
			nodeToSCC[n] = label
		}
	}

	condensed := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	for node, targets := range graph {
		src := nodeToSCC[node]
		for _, t := range targets {
			dst := nodeToSCC[t]
			if src == dst {
				continue
			}
			if seen[src] == nil {
				seen[src] = make(map[string]bool)
			}
			if !seen[src][dst] {
				seen[src][dst] = true
				condensed[src] = append(condensed[src], dst)
			}
		}
	}
	return condensed, nodeToSCC
}

func topologicalLayers(dag map[string][]string) map[string]int {
	nodeSet := collectDAGNodes(dag)
	inDeg := computeInDegrees(dag, nodeSet)
	return assignLayersBFS(dag, nodeSet, inDeg)
}

func collectDAGNodes(dag map[string][]string) map[string]bool {
	nodes := make(map[string]bool)
	for n, targets := range dag {
		nodes[n] = true
		for _, t := range targets {
			nodes[t] = true
		}
	}
	return nodes
}

func computeInDegrees(dag map[string][]string, nodes map[string]bool) map[string]int {
	inDeg := make(map[string]int)
	for n := range nodes {
		inDeg[n] = 0
	}
	for _, targets := range dag {
		for _, t := range targets {
			inDeg[t]++
		}
	}
	return inDeg
}

func assignLayersBFS(dag map[string][]string, nodes map[string]bool, inDeg map[string]int) map[string]int {
	layer := make(map[string]int)
	var queue []string
	for n := range nodes {
		if inDeg[n] == 0 {
			queue = append(queue, n)
			layer[n] = 0
		}
	}

	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		for _, w := range dag[v] {
			if layer[v]+1 > layer[w] {
				layer[w] = layer[v] + 1
			}
			inDeg[w]--
			if inDeg[w] == 0 {
				queue = append(queue, w)
			}
		}
	}
	return layer
}

func buildLayerAssignments(sccs [][]string, sccMap map[string]string, layerMap map[string]int) []domain.LayerAssignment {
	var result []domain.LayerAssignment
	seen := make(map[string]bool)
	for _, scc := range sccs {
		for _, node := range scc {
			label := sccMap[node]
			if seen[node] {
				continue
			}
			seen[node] = true
			result = append(result, domain.LayerAssignment{
				Node:  node,
				Layer: layerMap[label],
			})
		}
	}
	return result
}

func findLayerSkips(graph map[string][]string, sccMap map[string]string, layerMap map[string]int) []domain.LayerSkip {
	var skips []domain.LayerSkip
	for from, targets := range graph {
		fromLabel := sccMap[from]
		fromLayer := layerMap[fromLabel]
		for _, to := range targets {
			toLabel := sccMap[to]
			toLayer := layerMap[toLabel]
			skip := toLayer - fromLayer
			if skip > 1 {
				skips = append(skips, domain.LayerSkip{
					From: from, To: to,
					FromLayer: fromLayer, ToLayer: toLayer, Skip: skip,
				})
			}
		}
	}
	return skips
}

func detectCommunities(graph map[string][]string, nodes []string) (map[string]int, float64) {
	community := initCommunities(nodes)
	undirected := makeUndirected(graph)
	degree := computeDegrees(undirected)
	m := totalEdges(degree)

	if m == 0 {
		return community, 0
	}

	improved := true
	for improved {
		improved = louvainPass(nodes, undirected, community, degree, m)
	}

	q := computeModularity(undirected, community, degree, m)
	return community, q
}

func initCommunities(nodes []string) map[string]int {
	community := make(map[string]int)
	for i, n := range nodes {
		community[n] = i
	}
	return community
}

func makeUndirected(graph map[string][]string) map[string][]string {
	undirected := make(map[string][]string)
	for node, targets := range graph {
		for _, t := range targets {
			undirected[node] = append(undirected[node], t)
			undirected[t] = append(undirected[t], node)
		}
	}
	return undirected
}

func computeDegrees(graph map[string][]string) map[string]int {
	deg := make(map[string]int)
	for n, neighbors := range graph {
		deg[n] = len(neighbors)
	}
	return deg
}

func totalEdges(degree map[string]int) float64 {
	total := 0
	for _, d := range degree {
		total += d
	}
	return float64(total) / 2
}

func louvainPass(nodes []string, graph map[string][]string, community map[string]int, degree map[string]int, m float64) bool {
	improved := false
	for _, v := range nodes {
		bestComm := community[v]
		bestDelta := 0.0

		neighbors := graph[v]
		commEdges := countCommunityEdges(neighbors, community)

		for c, kIn := range commEdges {
			delta := deltaModularity(kIn, sumTot(community, degree, c), degree[v], m)
			if delta > bestDelta {
				bestDelta = delta
				bestComm = c
			}
		}

		if bestComm != community[v] {
			community[v] = bestComm
			improved = true
		}
	}
	return improved
}

func countCommunityEdges(neighbors []string, community map[string]int) map[int]float64 {
	edges := make(map[int]float64)
	for _, n := range neighbors {
		edges[community[n]]++
	}
	return edges
}

func sumTot(community map[string]int, degree map[string]int, c int) float64 {
	total := 0.0
	for n, comm := range community {
		if comm == c {
			total += float64(degree[n])
		}
	}
	return total
}

func deltaModularity(kIn, sumTotal float64, ki int, m float64) float64 {
	kiF := float64(ki)
	return (kIn/m - (sumTotal*kiF)/(2*m*m))
}

func computeModularity(graph map[string][]string, community map[string]int, degree map[string]int, m float64) float64 {
	q := 0.0
	for node, neighbors := range graph {
		for _, n := range neighbors {
			if community[node] == community[n] {
				ki := float64(degree[node])
				kj := float64(degree[n])
				q += 1.0 - (ki*kj)/(2*m)
			}
		}
	}
	return q / (2 * m)
}

func findMisplacedCode(pkgs []domain.Package, community map[string]int) []domain.MisplacedCode {
	funcPkg := make(map[string]string)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			funcPkg[pkg.Path+"."+fn.Name] = pkg.Path
		}
	}

	commPkgs := buildCommunityPackageMap(community, funcPkg)
	var misplaced []domain.MisplacedCode

	for fn, comm := range community {
		pkg := funcPkg[fn]
		if pkg == "" {
			continue
		}
		dominantPkg := commPkgs[comm]
		if dominantPkg == "" || dominantPkg == pkg {
			continue
		}

		edgesToCurrent := countEdgesToPkg(fn, pkg, community, funcPkg)
		edgesToSuggested := countEdgesToPkg(fn, dominantPkg, community, funcPkg)

		if edgesToSuggested > edgesToCurrent && edgesToSuggested >= 3 {
			misplaced = append(misplaced, domain.MisplacedCode{
				Function:         fn,
				CurrentPackage:   pkg,
				SuggestedPackage: dominantPkg,
				EdgesToCurrent:   edgesToCurrent,
				EdgesToSuggested: edgesToSuggested,
			})
		}
	}

	return misplaced
}

func buildCommunityPackageMap(community map[string]int, funcPkg map[string]string) map[int]string {
	pkgCounts := make(map[int]map[string]int)
	for fn, comm := range community {
		pkg := funcPkg[fn]
		if pkg == "" {
			continue
		}
		if pkgCounts[comm] == nil {
			pkgCounts[comm] = make(map[string]int)
		}
		pkgCounts[comm][pkg]++
	}

	dominant := make(map[int]string)
	for comm, counts := range pkgCounts {
		bestPkg := ""
		bestCount := 0
		for pkg, count := range counts {
			if count > bestCount {
				bestCount = count
				bestPkg = pkg
			}
		}
		dominant[comm] = bestPkg
	}
	return dominant
}

func countEdgesToPkg(fn, targetPkg string, community map[string]int, funcPkg map[string]string) int {
	count := 0
	comm := community[fn]
	for other, otherComm := range community {
		if otherComm == comm && funcPkg[other] == targetPkg {
			count++
		}
	}
	return count
}

func computeHenryKafura(pkgs []domain.Package) []domain.HenryKafuraResult {
	var results []domain.HenryKafuraResult
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			fanIn := len(fn.CalledBy)
			fanOut := len(fn.Calls)
			length := estimateLength(fn)
			ifVal := float64(length) * float64(fanIn*fanOut) * float64(fanIn*fanOut)

			if ifVal > 1000 {
				results = append(results, domain.HenryKafuraResult{
					Function: pkg.Path + "." + fn.Name,
					IF:       ifVal,
					Length:   length,
					FanIn:    fanIn,
					FanOut:   fanOut,
				})
			}
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].IF > results[j].IF
	})
	if len(results) > 20 {
		results = results[:20]
	}
	return results
}

func estimateLength(fn domain.Function) int {
	if fn.Line > 0 {
		return fn.Line
	}
	return 10
}

func buildDSM(pkgs []domain.Package) ([]string, [][]int) {
	graph, names := buildPkgImportGraph(pkgs)
	order := topologicalSortPkgs(graph, names)
	return buildMatrix(order, graph)
}

func buildPkgImportGraph(pkgs []domain.Package) (map[string]map[string]int, []string) {
	graph := make(map[string]map[string]int)
	nameSet := make(map[string]bool)
	for _, pkg := range pkgs {
		nameSet[pkg.Path] = true
		for _, imp := range pkg.Imports {
			if graph[pkg.Path] == nil {
				graph[pkg.Path] = make(map[string]int)
			}
			graph[pkg.Path][imp]++
		}
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)
	return graph, names
}

func topologicalSortPkgs(graph map[string]map[string]int, names []string) []string {
	inDeg := make(map[string]int)
	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
		inDeg[n] = 0
	}
	for _, targets := range graph {
		for t := range targets {
			if nameSet[t] {
				inDeg[t]++
			}
		}
	}

	var queue []string
	for _, n := range names {
		if inDeg[n] == 0 {
			queue = append(queue, n)
		}
	}

	var order []string
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		order = append(order, v)
		for t := range graph[v] {
			if !nameSet[t] {
				continue
			}
			inDeg[t]--
			if inDeg[t] == 0 {
				queue = append(queue, t)
			}
		}
	}

	for _, n := range names {
		found := false
		for _, o := range order {
			if o == n {
				found = true
				break
			}
		}
		if !found {
			order = append(order, n)
		}
	}

	return order
}

func buildMatrix(order []string, graph map[string]map[string]int) ([]string, [][]int) {
	idx := make(map[string]int)
	for i, name := range order {
		idx[name] = i
	}

	n := len(order)
	matrix := make([][]int, n)
	for i := range matrix {
		matrix[i] = make([]int, n)
	}

	for src, targets := range graph {
		srcIdx, ok := idx[src]
		if !ok {
			continue
		}
		for dst, count := range targets {
			dstIdx, ok := idx[dst]
			if !ok {
				continue
			}
			matrix[srcIdx][dstIdx] = count
		}
	}

	shortNames := make([]string, len(order))
	for i, name := range order {
		shortNames[i] = domain.ShortPkgName(name)
	}
	return shortNames, matrix
}
