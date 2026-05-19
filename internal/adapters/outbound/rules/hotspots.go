package rules

import (
	"math"
	"sort"

	"github.com/berkantay/slop0/internal/domain"
)

type HotspotAnalyzer struct{}

func (h *HotspotAnalyzer) Analyze(pkgs []domain.Package) []domain.Hotspot {
	fg := buildFuncGraph(pkgs)

	pagerank := computePageRank(fg.graph, fg.nodes, 0.85, 30)
	blastRadius := computeBlastRadius(fg.reverseGraph, fg.nodes)

	var hotspots []domain.Hotspot
	for _, node := range fg.nodes {
		pr := pagerank[node]
		br := blastRadius[node]
		if pr < 0.001 && br < 3 {
			continue
		}

		hotspots = append(hotspots, domain.Hotspot{
			Function:    node,
			PageRank:    math.Round(pr*10000) / 10000,
			BlastRadius: br,
		})
	}

	sort.Slice(hotspots, func(i, j int) bool {
		return hotspots[i].PageRank > hotspots[j].PageRank
	})

	if len(hotspots) > 20 {
		hotspots = hotspots[:20]
	}

	return hotspots
}

type funcGraph struct {
	graph        map[string][]string
	reverseGraph map[string][]string
	nodes        []string
}

func buildFuncGraph(pkgs []domain.Package) funcGraph {
	graph := make(map[string][]string)
	reverseGraph := make(map[string][]string)
	nodeSet := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			key := pkg.Path + "." + fn.Name
			nodeSet[key] = true

			for _, callee := range fn.Calls {
				graph[key] = append(graph[key], callee)
				reverseGraph[callee] = append(reverseGraph[callee], key)
				nodeSet[callee] = true
			}
		}
	}

	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	return funcGraph{graph: graph, reverseGraph: reverseGraph, nodes: nodes}
}

func computePageRank(graph map[string][]string, nodes []string, damping float64, iterations int) map[string]float64 {
	n := float64(len(nodes))
	if n == 0 {
		return nil
	}

	pr := make(map[string]float64)
	for _, node := range nodes {
		pr[node] = 1.0 / n
	}

	outDegree := buildOutDegree(graph)
	inbound := buildInbound(graph)

	g := &prGraph{nodes: nodes, inbound: inbound, outDegree: outDegree, damping: damping, n: n}
	for iter := 0; iter < iterations; iter++ {
		pr = g.iterate(pr)
	}

	return pr
}

type prGraph struct {
	nodes     []string
	inbound   map[string][]string
	outDegree map[string]int
	damping   float64
	n         float64
}

func buildOutDegree(graph map[string][]string) map[string]int {
	outDegree := make(map[string]int)
	for node, targets := range graph {
		outDegree[node] = len(targets)
	}
	return outDegree
}

func buildInbound(graph map[string][]string) map[string][]string {
	inbound := make(map[string][]string)
	for node, targets := range graph {
		for _, target := range targets {
			inbound[target] = append(inbound[target], node)
		}
	}
	return inbound
}

func (g *prGraph) iterate(pr map[string]float64) map[string]float64 {
	newPR := make(map[string]float64)
	for _, node := range g.nodes {
		sum := 0.0
		for _, caller := range g.inbound[node] {
			if deg := g.outDegree[caller]; deg > 0 {
				sum += pr[caller] / float64(deg)
			}
		}
		newPR[node] = (1-g.damping)/g.n + g.damping*sum
	}
	return newPR
}

func computeBlastRadius(reverseGraph map[string][]string, nodes []string) map[string]int {
	radius := make(map[string]int)

	for _, node := range nodes {
		visited := make(map[string]bool)
		queue := []string{node}
		visited[node] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			for _, caller := range reverseGraph[curr] {
				if !visited[caller] {
					visited[caller] = true
					queue = append(queue, caller)
				}
			}
		}

		radius[node] = len(visited) - 1
	}

	return radius
}
