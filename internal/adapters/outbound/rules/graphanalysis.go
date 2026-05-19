package rules

import (
	"math"
	"sort"

	"github.com/berkantay/slop0/internal/domain"
)

type GraphAnalyzer struct{}

func (g *GraphAnalyzer) Analyze(pkgs []domain.Package) domain.GraphAnalysis {
	graph, nodes := buildCallGraph(pkgs)
	return domain.GraphAnalysis{
		Bottlenecks:     findBottlenecks(graph, nodes, pkgs),
		CoupledClusters: findCoupledClusters(graph, nodes),
	}
}

func buildCallGraph(pkgs []domain.Package) (map[string][]string, []string) {
	graph := make(map[string][]string)
	nodeSet := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			key := pkg.Path + "." + fn.Name
			nodeSet[key] = true
			for _, callee := range fn.Calls {
				graph[key] = append(graph[key], callee)
				nodeSet[callee] = true
			}
		}
	}
	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	return graph, nodes
}

func findBottlenecks(graph map[string][]string, nodes []string, pkgs []domain.Package) []domain.Bottleneck {
	bc := brandesBetweenness(graph, nodes)
	pr := simplePageRank(graph, nodes)
	br := blastRadii(graph, nodes)

	mean, stddev := meanStddev(bc, nodes)
	threshold := mean + 2*stddev

	var result []domain.Bottleneck
	for _, n := range nodes {
		if bc[n] > threshold && bc[n] > 0 {
			result = append(result, domain.Bottleneck{
				Function:    n,
				Betweenness: math.Round(bc[n]*10000) / 10000,
				PageRank:    math.Round(pr[n]*10000) / 10000,
				BlastRadius: br[n],
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Betweenness > result[j].Betweenness
	})
	if len(result) > 15 {
		result = result[:15]
	}
	return result
}

func brandesBetweenness(graph map[string][]string, nodes []string) map[string]float64 {
	cb := make(map[string]float64)
	for _, s := range nodes {
		brandesFromSource(s, graph, nodes, cb)
	}
	return cb
}

func brandesFromSource(s string, graph map[string][]string, nodes []string, cb map[string]float64) {
	var stack []string
	pred := make(map[string][]string)
	sigma := make(map[string]float64)
	dist := make(map[string]int)

	for _, n := range nodes {
		dist[n] = -1
	}
	sigma[s] = 1
	dist[s] = 0

	queue := []string{s}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		stack = append(stack, v)
		brandesProcessNeighbors(v, graph[v], dist, sigma, pred, &queue)
	}

	brandesBackPropagate(stack, s, pred, sigma, cb)
}

func brandesProcessNeighbors(v string, neighbors []string, dist map[string]int, sigma map[string]float64, pred map[string][]string, queue *[]string) {
	for _, w := range neighbors {
		if dist[w] < 0 {
			dist[w] = dist[v] + 1
			*queue = append(*queue, w)
		}
		if dist[w] == dist[v]+1 {
			sigma[w] += sigma[v]
			pred[w] = append(pred[w], v)
		}
	}
}

func brandesBackPropagate(stack []string, s string, pred map[string][]string, sigma map[string]float64, cb map[string]float64) {
	delta := make(map[string]float64)
	for i := len(stack) - 1; i >= 0; i-- {
		w := stack[i]
		for _, v := range pred[w] {
			if sigma[w] > 0 {
				delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
			}
		}
		if w != s {
			cb[w] += delta[w]
		}
	}
}

func simplePageRank(graph map[string][]string, nodes []string) map[string]float64 {
	n := float64(len(nodes))
	if n == 0 {
		return nil
	}
	pr := make(map[string]float64)
	for _, node := range nodes {
		pr[node] = 1.0 / n
	}
	inbound := buildInboundMap(graph)
	outDeg := buildOutDegreeMap(graph)

	for iter := 0; iter < 20; iter++ {
		newPR := make(map[string]float64)
		for _, node := range nodes {
			sum := 0.0
			for _, caller := range inbound[node] {
				if deg := outDeg[caller]; deg > 0 {
					sum += pr[caller] / float64(deg)
				}
			}
			newPR[node] = 0.15/n + 0.85*sum
		}
		pr = newPR
	}
	return pr
}

func buildInboundMap(graph map[string][]string) map[string][]string {
	inbound := make(map[string][]string)
	for node, targets := range graph {
		for _, t := range targets {
			inbound[t] = append(inbound[t], node)
		}
	}
	return inbound
}

func buildOutDegreeMap(graph map[string][]string) map[string]int {
	deg := make(map[string]int)
	for node, targets := range graph {
		deg[node] = len(targets)
	}
	return deg
}

func blastRadii(graph map[string][]string, nodes []string) map[string]int {
	reverse := make(map[string][]string)
	for node, targets := range graph {
		for _, t := range targets {
			reverse[t] = append(reverse[t], node)
		}
	}

	radius := make(map[string]int)
	for _, node := range nodes {
		radius[node] = bfsCount(node, reverse)
	}
	return radius
}

func bfsCount(start string, graph map[string][]string) int {
	visited := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, next := range graph[curr] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	return len(visited) - 1
}

func meanStddev(values map[string]float64, nodes []string) (float64, float64) {
	if len(nodes) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, n := range nodes {
		sum += values[n]
	}
	mean := sum / float64(len(nodes))

	variance := 0.0
	for _, n := range nodes {
		diff := values[n] - mean
		variance += diff * diff
	}
	variance /= float64(len(nodes))
	return mean, math.Sqrt(variance)
}

func findCoupledClusters(graph map[string][]string, nodes []string) []domain.CoupledCluster {
	sccs := tarjanSCC(graph, nodes)
	var clusters []domain.CoupledCluster
	for _, scc := range sccs {
		if len(scc) < 2 {
			continue
		}
		cut := suggestCut(scc, graph)
		clusters = append(clusters, domain.CoupledCluster{
			Nodes:        scc,
			Size:         len(scc),
			SuggestedCut: cut,
		})
	}

	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].Size > clusters[j].Size
	})
	if len(clusters) > 10 {
		clusters = clusters[:10]
	}
	return clusters
}

type tarjanState struct {
	indexCounter int
	stack        []string
	index        map[string]int
	lowlink      map[string]int
	onStack      map[string]bool
	result       [][]string
	graph        map[string][]string
}

func tarjanSCC(graph map[string][]string, nodes []string) [][]string {
	state := &tarjanState{
		index:   make(map[string]int),
		lowlink: make(map[string]int),
		onStack: make(map[string]bool),
		graph:   graph,
	}

	for _, n := range nodes {
		if _, ok := state.index[n]; !ok {
			state.strongConnect(n)
		}
	}
	return state.result
}

func (s *tarjanState) strongConnect(v string) {
	s.index[v] = s.indexCounter
	s.lowlink[v] = s.indexCounter
	s.indexCounter++
	s.stack = append(s.stack, v)
	s.onStack[v] = true

	for _, w := range s.graph[v] {
		if _, ok := s.index[w]; !ok {
			s.strongConnect(w)
			s.lowlink[v] = minInt(s.lowlink[v], s.lowlink[w])
		} else if s.onStack[w] {
			s.lowlink[v] = minInt(s.lowlink[v], s.index[w])
		}
	}

	if s.lowlink[v] == s.index[v] {
		s.popSCC(v)
	}
}

func (s *tarjanState) popSCC(v string) {
	var scc []string
	for {
		w := s.stack[len(s.stack)-1]
		s.stack = s.stack[:len(s.stack)-1]
		s.onStack[w] = false
		scc = append(scc, w)
		if w == v {
			break
		}
	}
	s.result = append(s.result, scc)
}

func suggestCut(scc []string, graph map[string][]string) string {
	sccSet := make(map[string]bool)
	for _, n := range scc {
		sccSet[n] = true
	}

	bestEdge := ""
	bestScore := 0

	for _, node := range scc {
		outCount := 0
		for _, target := range graph[node] {
			if sccSet[target] {
				outCount++
			}
		}
		if outCount > bestScore {
			bestScore = outCount
			if len(graph[node]) > 0 {
				for _, t := range graph[node] {
					if sccSet[t] {
						bestEdge = node + " → " + t
						break
					}
				}
			}
		}
	}
	return bestEdge
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
