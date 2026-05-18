package renderer

import (
	"fmt"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type CompactRenderer struct{}

func NewCompactRenderer() *CompactRenderer {
	return &CompactRenderer{}
}

func (r *CompactRenderer) Render(report *domain.Report) (string, error) {
	var b strings.Builder

	r.renderSummary(&b, report.Summary)
	r.renderOptionalSections(&b, report)

	return b.String(), nil
}

func (r *CompactRenderer) renderOptionalSections(b *strings.Builder, report *domain.Report) {
	r.renderIfNonEmpty(b, len(report.EntryPoints), func() { r.renderEntryPoints(b, report.EntryPoints) })
	r.renderIfNonEmpty(b, len(report.ExternalDeps), func() { r.renderExternalDeps(b, report.ExternalDeps) })
	r.renderIfNonEmpty(b, len(report.DataFlows), func() { r.renderDataFlows(b, report.DataFlows) })
	r.renderIfNonEmpty(b, len(report.Packages), func() { r.renderStructure(b, report.Packages) })
	r.renderIfNonEmpty(b, len(report.DesignPatterns), func() { r.renderDesignPatterns(b, report.DesignPatterns) })
	r.renderIfNonEmpty(b, len(report.Circulars), func() { r.renderCirculars(b, report.Circulars) })
	r.renderIfNonEmpty(b, len(report.LayerViolations), func() { r.renderLayerViolations(b, report.LayerViolations) })
	r.renderIfNonEmpty(b, len(report.PatternIssues), func() { r.renderPatternIssues(b, report.PatternIssues) })
	r.renderIfNonEmpty(b, len(report.Duplications), func() { r.renderDuplications(b, report.Duplications) })
	r.renderIfNonEmpty(b, len(report.Hotspots), func() { r.renderHotspots(b, report.Hotspots) })
	r.renderIfNonEmpty(b, len(report.PkgMetrics), func() { r.renderPkgMetrics(b, report.PkgMetrics) })
	r.renderIfNonEmpty(b, len(report.TypeMetrics), func() { r.renderTypeRoles(b, report.TypeMetrics) })
}

func (r *CompactRenderer) renderIfNonEmpty(_ *strings.Builder, count int, fn func()) {
	if count > 0 {
		fn()
	}
}

func (r *CompactRenderer) renderSummary(b *strings.Builder, s domain.Summary) {
	b.WriteString("=== SUMMARY ===\n\n")
	fmt.Fprintf(b, "%d packages, %d functions, %d types\n", s.TotalPackages, s.TotalFunctions, s.TotalTypes)
	if len(s.EntryPoints) > 0 {
		fmt.Fprintf(b, "entry: %s\n", strings.Join(s.EntryPoints, " | "))
	}
	if len(s.ExternalDeps) > 0 {
		fmt.Fprintf(b, "deps: %s\n", strings.Join(s.ExternalDeps, " | "))
	}
	if len(s.RoleCounts) > 0 {
		var roles []string
		for role, count := range s.RoleCounts {
			roles = append(roles, fmt.Sprintf("%s:%d", role, count))
		}
		fmt.Fprintf(b, "roles: %s\n", strings.Join(roles, " "))
	}
	if s.IssueCount > 0 || s.PatternCount > 0 {
		fmt.Fprintf(b, "findings: %d issues, %d patterns, %d data flows\n", s.IssueCount, s.PatternCount, s.DataFlowCount)
	}
	if len(s.TopHotspots) > 0 {
		fmt.Fprintf(b, "hotspots: %s\n", strings.Join(s.TopHotspots, " | "))
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderEntryPoints(b *strings.Builder, entries []domain.EntryPoint) {
	b.WriteString("=== ENTRY POINTS ===\n\n")
	for _, e := range entries {
		fmt.Fprintf(b, "[%s] %s → %s (%s:%d)\n", e.Kind, e.Route, e.Handler, e.File, e.Line)
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderExternalDeps(b *strings.Builder, deps []domain.ExternalDep) {
	b.WriteString("=== EXTERNAL DEPENDENCIES ===\n\n")
	grouped := make(map[string][]domain.ExternalDep)
	for _, d := range deps {
		grouped[d.Kind] = append(grouped[d.Kind], d)
	}
	for kind, ds := range grouped {
		fmt.Fprintf(b, "%s:\n", kind)
		for _, d := range ds {
			fmt.Fprintf(b, "  %s.%s (used by %s)\n", domain.ShortPkgName(d.Package), d.Type, domain.ShortPkgName(d.UsedBy))
		}
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderDataFlows(b *strings.Builder, flows []domain.DataFlowPath) {
	b.WriteString("=== DATA FLOWS ===\n\n")
	for _, f := range flows {
		fmt.Fprintf(b, "%s → %s → %s\n", f.Entry, strings.Join(f.Chain[1:len(f.Chain)-1], " → "), f.Sink)
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderHotspots(b *strings.Builder, hotspots []domain.Hotspot) {
	b.WriteString("=== HOTSPOTS ===\n\n")
	for _, h := range hotspots {
		parts := strings.Split(h.Function, "/")
		short := parts[len(parts)-1]
		fmt.Fprintf(b, "%s  rank:%.4f  blast-radius:%d\n", short, h.PageRank, h.BlastRadius)
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderStructure(b *strings.Builder, pkgs []domain.Package) {
	b.WriteString("=== STRUCTURE ===\n")

	for _, pkg := range pkgs {
		r.renderPackageStructure(b, &pkg)
	}

	b.WriteString("\n")
}

func (r *CompactRenderer) renderPackageStructure(b *strings.Builder, pkg *domain.Package) {
	shortName := domain.ShortPkgName(pkg.Path)
	fmt.Fprintf(b, "\n[%s]\n", shortName)

	for _, fn := range pkg.Functions {
		renderFunction(b, &fn)
	}

	for _, t := range pkg.Types {
		r.renderType(b, &t)
	}

	for _, v := range pkg.Variables {
		renderVariable(b, &v)
	}
}

func renderFunction(b *strings.Builder, fn *domain.Function) {
	fmt.Fprintf(b, "%s\n", fn.Signature)
	if len(fn.Calls) > 0 {
		fmt.Fprintf(b, "  → %s\n", strings.Join(shortenRefs(fn.Calls), ", "))
	}
	if len(fn.CalledBy) > 0 {
		fmt.Fprintf(b, "  ← %s\n", strings.Join(shortenRefs(fn.CalledBy), ", "))
	}
	if len(fn.Uses) > 0 {
		fmt.Fprintf(b, "  uses: %s\n", strings.Join(fn.Uses, ", "))
	}
}

func renderVariable(b *strings.Builder, v *domain.Variable) {
	fmt.Fprintf(b, "%s %s\n", v.Name, v.TypeName)
	if len(v.UsedBy) > 0 {
		fmt.Fprintf(b, "  used-by: %s\n", strings.Join(v.UsedBy, ", "))
	}
}

func (r *CompactRenderer) renderType(b *strings.Builder, t *domain.Type) {
	switch t.Kind {
	case "struct":
		fields := make([]string, 0, len(t.Fields))
		for _, f := range t.Fields {
			fields = append(fields, f.Name+" "+f.Type)
		}
		fmt.Fprintf(b, "%s {%s}\n", t.Name, strings.Join(fields, ", "))
	case "interface":
		fmt.Fprintf(b, "%s interface {%s}\n", t.Name, strings.Join(t.Methods, ", "))
	default:
		fmt.Fprintf(b, "%s %s\n", t.Name, t.Kind)
	}

	if len(t.Implements) > 0 {
		fmt.Fprintf(b, "  impl %s\n", strings.Join(t.Implements, ", "))
	}
	if len(t.UsedBy) > 0 {
		fmt.Fprintf(b, "  used-by: %s\n", strings.Join(t.UsedBy, ", "))
	}
}

func (r *CompactRenderer) renderDesignPatterns(b *strings.Builder, patterns []domain.DesignPattern) {
	b.WriteString("=== DESIGN PATTERNS ===\n\n")

	grouped := make(map[string][]domain.DesignPattern)
	for _, p := range patterns {
		grouped[p.Name] = append(grouped[p.Name], p)
	}

	order := []string{"port-adapter", "strategy", "factory", "middleware", "decorator", "builder", "singleton"}
	for _, name := range order {
		group, ok := grouped[name]
		if !ok {
			continue
		}
		fmt.Fprintf(b, "%s (%d):\n", name, len(group))
		for _, p := range group {
			fmt.Fprintf(b, "  %s [%s]\n", p.Description, p.Confidence.Label())
			for _, part := range p.Participants {
				fmt.Fprintf(b, "    %s: %s (%s)\n", part.Role, part.Type, domain.ShortPkgName(part.Package))
			}
		}
		b.WriteString("\n")
	}
}

func (r *CompactRenderer) renderCirculars(b *strings.Builder, circulars []domain.CircularDep) {
	b.WriteString("=== CIRCULAR DEPENDENCIES ===\n\n")
	for _, c := range circulars {
		fmt.Fprintf(b, "%s\n", strings.Join(c.Chain, " → "))
		for _, loc := range c.Locations {
			fmt.Fprintf(b, "  %s:%d\n", loc.File, loc.Line)
		}
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderLayerViolations(b *strings.Builder, violations []domain.LayerViolation) {
	b.WriteString("=== LAYER VIOLATIONS ===\n\n")
	for _, v := range violations {
		fmt.Fprintf(b, "%s → %s\n", v.From, v.To)
		fmt.Fprintf(b, "  expected: %s\n", v.ExpectedPath)
		fmt.Fprintf(b, "  at: %s:%d\n", v.Location.File, v.Location.Line)
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderPatternIssues(b *strings.Builder, issues []domain.PatternIssue) {
	b.WriteString("=== PATTERN INCONSISTENCIES ===\n\n")
	for _, p := range issues {
		fmt.Fprintf(b, "%s [%s]:\n", p.Category, p.Confidence.Label())
		fmt.Fprintf(b, "  dominant: %s\n", p.Dominant)
		fmt.Fprintf(b, "  violation: %s\n", p.Violation)
		for _, loc := range p.Locations {
			fmt.Fprintf(b, "  at: %s:%d\n", loc.File, loc.Line)
		}
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderDuplications(b *strings.Builder, dups []domain.Duplication) {
	b.WriteString("=== DUPLICATIONS ===\n\n")
	for _, d := range dups {
		fmt.Fprintf(b, "%s ≈ %s\n", d.FuncA, d.FuncB)
		fmt.Fprintf(b, "  %s\n", d.Description)
		fmt.Fprintf(b, "  at: %s:%d, %s:%d\n", d.Locations[0].File, d.Locations[0].Line, d.Locations[1].File, d.Locations[1].Line)
	}
	b.WriteString("\n")
}


func (r *CompactRenderer) renderPkgMetrics(b *strings.Builder, metrics []domain.PackageMetrics) {
	b.WriteString("=== PACKAGE METRICS ===\n\n")
	fmt.Fprintf(b, "%-40s  Ca  Ce  I     A     D\n", "package")
	fmt.Fprintf(b, "%-40s  --  --  ----  ----  ----\n", strings.Repeat("-", 40))

	for _, m := range metrics {
		name := domain.ShortPkgName(m.Path)
		if len(name) > 40 {
			name = name[len(name)-40:]
		}

		marker := ""
		if m.Distance > 0.3 {
			if m.Abstractness < 0.3 && m.Instability < 0.3 {
				marker = " ← zone of pain (rigid)"
			} else if m.Abstractness > 0.7 && m.Instability > 0.7 {
				marker = " ← zone of uselessness"
			}
		}

		fmt.Fprintf(b, "%-40s  %2d  %2d  %.2f  %.2f  %.2f%s\n",
			name, m.Ca, m.Ce, m.Instability, m.Abstractness, m.Distance, marker)
	}
	b.WriteString("\n")
}

func (r *CompactRenderer) renderTypeRoles(b *strings.Builder, metrics []domain.TypeMetrics) {
	b.WriteString("=== TYPE ROLES ===\n\n")

	grouped := make(map[domain.TypeRole][]domain.TypeMetrics)
	for _, m := range metrics {
		if m.Role == domain.RoleUnknown {
			continue
		}
		grouped[m.Role] = append(grouped[m.Role], m)
	}

	order := []domain.TypeRole{
		domain.RoleDataHolder,
		domain.RoleOrchestrator,
		domain.RoleRepository,
		domain.RoleBoundary,
		domain.RoleTransformer,
	}

	for _, role := range order {
		types := grouped[role]
		if len(types) == 0 {
			continue
		}
		fmt.Fprintf(b, "%s (%d):\n", role, len(types))
		for _, t := range types {
			lcom := ""
			if t.LCOM4 > 1 {
				lcom = fmt.Sprintf(" LCOM4=%d (consider splitting)", t.LCOM4)
			}
			fmt.Fprintf(b, "  %s.%s  fan-in:%d fan-out:%d fields:%d methods:%d%s\n",
				domain.ShortPkgName(t.Package), t.Name, t.FanIn, t.FanOut, t.FieldCount, t.MethodCount, lcom)
		}
		b.WriteString("\n")
	}
}

func shortenRefs(refs []string) []string {
	short := make([]string, len(refs))
	for i, ref := range refs {
		parts := strings.Split(ref, "/")
		last := parts[len(parts)-1]
		short[i] = last
	}
	return short
}
