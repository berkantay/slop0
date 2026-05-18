package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type SummaryGenerator struct{}

func (g *SummaryGenerator) Generate(report *domain.Report, pkgs []domain.Package) domain.Summary {
	s := domain.Summary{}

	s.TotalPackages = len(pkgs)

	totalFuncs := 0
	totalTypes := 0
	for _, pkg := range pkgs {
		totalFuncs += len(pkg.Functions)
		totalTypes += len(pkg.Types)
	}
	s.TotalFunctions = totalFuncs
	s.TotalTypes = totalTypes

	s.EntryPoints = summarizeEntries(report.EntryPoints)
	s.ExternalDeps = summarizeExternalDeps(report.ExternalDeps)
	s.TopHotspots = summarizeHotspots(report.Hotspots)
	s.RoleCounts = summarizeRoles(report.TypeMetrics)
	s.IssueCount = len(report.PatternIssues) + len(report.LayerViolations) + len(report.Duplications) + len(report.Circulars)
	s.PatternCount = len(report.DesignPatterns)
	s.DataFlowCount = len(report.DataFlows)

	return s
}

func summarizeEntries(entries []domain.EntryPoint) []string {
	counts := make(map[string]int)
	var routes []string
	for _, e := range entries {
		counts[e.Kind]++
		if e.Kind == "http" && len(routes) < 10 {
			routes = append(routes, e.Route)
		}
	}

	var result []string
	for kind, count := range counts {
		result = append(result, fmt.Sprintf("%d %s", count, kind))
	}
	sort.Strings(result)

	if len(routes) > 0 {
		result = append(result, "routes: "+strings.Join(routes, ", "))
	}
	return result
}

func summarizeExternalDeps(deps []domain.ExternalDep) []string {
	kinds := make(map[string][]string)
	for _, d := range deps {
		kinds[d.Kind] = appendUniqueStr(kinds[d.Kind], d.Type)
	}

	var result []string
	for kind, types := range kinds {
		result = append(result, fmt.Sprintf("%s (%s)", kind, strings.Join(types, ", ")))
	}
	sort.Strings(result)
	return result
}

func summarizeHotspots(hotspots []domain.Hotspot) []string {
	var result []string
	limit := 5
	if len(hotspots) < limit {
		limit = len(hotspots)
	}
	for _, h := range hotspots[:limit] {
		parts := strings.Split(h.Function, "/")
		short := parts[len(parts)-1]
		result = append(result, fmt.Sprintf("%s (rank:%.4f blast:%d)", short, h.PageRank, h.BlastRadius))
	}
	return result
}

func summarizeRoles(metrics []domain.TypeMetrics) map[string]int {
	counts := make(map[string]int)
	for _, m := range metrics {
		if m.Role != domain.RoleUnknown {
			counts[m.Role.String()]++
		}
	}
	return counts
}

func appendUniqueStr(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
