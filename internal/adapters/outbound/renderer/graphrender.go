package renderer

import (
	"fmt"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

func (r *CompactRenderer) renderGraphAnalysis(b *strings.Builder, ga *domain.GraphAnalysis) {
	hasContent := len(ga.Bottlenecks) > 0 || len(ga.CoupledClusters) > 0 ||
		len(ga.LayerSkips) > 0 || len(ga.Misplaced) > 0 ||
		len(ga.HenryKafura) > 0 || len(ga.DSMMatrix) > 0

	if !hasContent {
		return
	}

	b.WriteString("=== GRAPH ANALYSIS ===\n\n")

	renderBottlenecks(b, ga.Bottlenecks)
	renderCoupledClusters(b, ga.CoupledClusters)
	renderLayerSkips(b, ga.LayerSkips)
	renderMisplaced(b, ga.Misplaced)
	renderHenryKafura(b, ga.HenryKafura)
	renderDSM(b, ga.DSMPackages, ga.DSMMatrix)
}

func renderBottlenecks(b *strings.Builder, bottlenecks []domain.Bottleneck) {
	if len(bottlenecks) == 0 {
		return
	}
	b.WriteString("bottlenecks (betweenness centrality):\n")
	for _, bn := range bottlenecks {
		short := shortName(bn.Function)
		fmt.Fprintf(b, "  %s  BC:%.4f  PR:%.4f  blast:%d\n", short, bn.Betweenness, bn.PageRank, bn.BlastRadius)
	}
	b.WriteString("\n")
}

func renderCoupledClusters(b *strings.Builder, clusters []domain.CoupledCluster) {
	if len(clusters) == 0 {
		return
	}
	b.WriteString("coupled clusters (strongly connected components):\n")
	for _, c := range clusters {
		shorts := make([]string, len(c.Nodes))
		for i, n := range c.Nodes {
			shorts[i] = shortName(n)
		}
		fmt.Fprintf(b, "  {%s} — %d nodes\n", strings.Join(shorts, ", "), c.Size)
		if c.SuggestedCut != "" {
			fmt.Fprintf(b, "    suggested cut: %s\n", c.SuggestedCut)
		}
	}
	b.WriteString("\n")
}

func renderLayerSkips(b *strings.Builder, skips []domain.LayerSkip) {
	if len(skips) == 0 {
		return
	}
	b.WriteString("layer skip violations:\n")
	for _, s := range skips {
		fmt.Fprintf(b, "  L%d %s → L%d %s (skip %d)\n",
			s.FromLayer, shortName(s.From), s.ToLayer, shortName(s.To), s.Skip)
	}
	b.WriteString("\n")
}

func renderMisplaced(b *strings.Builder, misplaced []domain.MisplacedCode) {
	if len(misplaced) == 0 {
		return
	}
	b.WriteString("misplaced code (community detection):\n")
	for _, m := range misplaced {
		fmt.Fprintf(b, "  %s → should be in %s (edges: %d vs %d)\n",
			shortName(m.Function), domain.ShortPkgName(m.SuggestedPackage),
			m.EdgesToSuggested, m.EdgesToCurrent)
	}
	b.WriteString("\n")
}

func renderHenryKafura(b *strings.Builder, hk []domain.HenryKafuraResult) {
	if len(hk) == 0 {
		return
	}
	b.WriteString("information flow complexity (Henry-Kafura):\n")
	for _, h := range hk {
		fmt.Fprintf(b, "  %s  IF:%.0f  len:%d  fan-in:%d  fan-out:%d\n",
			shortName(h.Function), h.IF, h.Length, h.FanIn, h.FanOut)
	}
	b.WriteString("\n")
}

func renderDSM(b *strings.Builder, packages []string, matrix [][]int) {
	if len(matrix) == 0 || len(packages) == 0 {
		return
	}

	b.WriteString("dependency structure matrix:\n")

	maxLen := 0
	for _, name := range packages {
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}
	if maxLen > 25 {
		maxLen = 25
	}

	header := fmt.Sprintf("%-*s", maxLen+2, "")
	for i := range packages {
		header += fmt.Sprintf(" %2d", i)
	}
	fmt.Fprintf(b, "  %s\n", header)

	for i, name := range packages {
		if len(name) > maxLen {
			name = name[len(name)-maxLen:]
		}
		row := fmt.Sprintf("%-*s", maxLen+2, fmt.Sprintf("%2d %s", i, name))
		backEdge := false
		for j, val := range matrix[i] {
			if val > 0 {
				row += fmt.Sprintf(" %2d", val)
				if j < i {
					backEdge = true
				}
			} else {
				row += "  ."
			}
		}
		if backEdge {
			row += " ←"
		}
		fmt.Fprintf(b, "  %s\n", row)
	}
	b.WriteString("\n")
}

func shortName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	return parts[len(parts)-1]
}
