package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type CodeSmellDetector struct{}

func (d *CodeSmellDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	issues = append(issues, d.detectFeatureEnvy(pkgs)...)
	issues = append(issues, d.detectShotgunSurgery(pkgs)...)
	issues = append(issues, d.detectMiddleMan(pkgs)...)
	issues = append(issues, d.detectDataClumps(pkgs)...)
	issues = append(issues, d.detectGodPackage(pkgs)...)
	return issues
}

func (d *CodeSmellDetector) detectFeatureEnvy(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	fnPkg := buildFuncToPkgMap(pkgs)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			ownCalls, foreignCalls := countCallsByPackage(fn, pkg.Path, fnPkg)
			maxPkg, maxCount := maxForeignCalls(foreignCalls)
			if maxCount >= 3 && maxCount > ownCalls {
				issues = append(issues, domain.PatternIssue{
					Category:  "smell/feature-envy",
					Dominant:  "function calls another package more than its own",
					Violation: fmt.Sprintf("%s in %s envies %s (%d calls to %s vs %d to own package)", fn.Name, domain.ShortPkgName(pkg.Path), domain.ShortPkgName(maxPkg), maxCount, domain.ShortPkgName(maxPkg), ownCalls),
					Locations: locationFromFunc(fn),
				})
			}
		}
	}
	return issues
}

func countCallsByPackage(fn domain.Function, ownPkg string, fnPkg map[string]string) (int, map[string]int) {
	ownCalls := 0
	foreign := make(map[string]int)
	for _, callee := range fn.Calls {
		calleePkg, ok := fnPkg[callee]
		if !ok {
			calleePkg = extractPkgFromQualified(callee)
		}
		if calleePkg == ownPkg {
			ownCalls++
		} else if calleePkg != "" {
			foreign[calleePkg]++
		}
	}
	return ownCalls, foreign
}

func maxForeignCalls(foreign map[string]int) (string, int) {
	maxPkg := ""
	maxCount := 0
	for pkg, count := range foreign {
		if count > maxCount {
			maxCount = count
			maxPkg = pkg
		}
	}
	return maxPkg, maxCount
}

func (d *CodeSmellDetector) detectShotgunSurgery(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	fnPkg := buildFuncToPkgMap(pkgs)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if len(fn.CalledBy) <= 5 {
				continue
			}
			callerPkgs := uniqueCallerPackages(fn, fnPkg)
			if len(callerPkgs) >= 3 {
				issues = append(issues, domain.PatternIssue{
					Category:  "smell/shotgun-surgery",
					Dominant:  "changing this function affects many callers across packages",
					Violation: fmt.Sprintf("changing %s affects %d callers across %d packages", fn.Name, len(fn.CalledBy), len(callerPkgs)),
					Locations: locationFromFunc(fn),
				})
			}
		}
	}
	return issues
}

func uniqueCallerPackages(fn domain.Function, fnPkg map[string]string) map[string]bool {
	pkgs := make(map[string]bool)
	for _, caller := range fn.CalledBy {
		p, ok := fnPkg[caller]
		if !ok {
			p = extractPkgFromQualified(caller)
		}
		if p != "" {
			pkgs[p] = true
		}
	}
	return pkgs
}

func (d *CodeSmellDetector) detectMiddleMan(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if !isRealMiddleMan(fn, pkg.Path) {
				continue
			}
			callee := lastSegment(fn.Calls[0])
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/middle-man",
				Dominant:  "function only delegates across package boundary — callers could call target directly",
				Violation: fmt.Sprintf("%s is a middle man — %d callers all delegate through it to %s", fn.Name, len(fn.CalledBy), callee),
				Locations: locationFromFunc(fn),
			})
		}
	}
	return issues
}

func isRealMiddleMan(fn domain.Function, pkgPath string) bool {
	if isMiddleManExcluded(fn.Name) {
		return false
	}
	if len(fn.Calls) != 1 || len(fn.CalledBy) < 2 {
		return false
	}

	calleeInSamePkg := strings.HasPrefix(fn.Calls[0], pkgPath)
	callerInSamePkg := strings.HasPrefix(fn.CalledBy[0], pkgPath)

	if calleeInSamePkg && callerInSamePkg {
		return false
	}

	calleeName := lastSegment(fn.Calls[0])
	if strings.Contains(strings.ToLower(fn.Name), strings.ToLower(calleeName)) {
		return false
	}
	if strings.Contains(strings.ToLower(calleeName), strings.ToLower(fn.Name)) {
		return false
	}

	return true
}

func isMiddleManExcluded(name string) bool {
	if strings.HasPrefix(name, "New") || name == "init" || name == "main" {
		return true
	}
	return false
}

func (d *CodeSmellDetector) detectDataClumps(pkgs []domain.Package) []domain.PatternIssue {
	type sigEntry struct {
		types []string
		name  string
	}
	var entries []sigEntry
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			types := extractParamTypes(fn.Signature)
			if len(types) >= 3 {
				entries = append(entries, sigEntry{types: types, name: pkg.Path + "." + fn.Name})
			}
		}
	}

	type clumpGroup struct {
		key   string
		types []string
		funcs []string
	}

	groups := make(map[string]*clumpGroup)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			common := intersectSorted(entries[i].types, entries[j].types)
			if len(common) < 3 {
				continue
			}
			key := strings.Join(common, ",")
			g, ok := groups[key]
			if !ok {
				g = &clumpGroup{key: key, types: common}
				groups[key] = g
			}
			addUnique(&g.funcs, entries[i].name)
			addUnique(&g.funcs, entries[j].name)
		}
	}

	var issues []domain.PatternIssue
	for _, g := range groups {
		if len(g.funcs) < 4 {
			continue
		}
		issues = append(issues, domain.PatternIssue{
			Category:  "smell/data-clumps",
			Dominant:  "same parameter types appear together repeatedly — extract a struct",
			Violation: fmt.Sprintf("types [%s] appear together in %d functions — extract a struct", g.key, len(g.funcs)),
		})
	}
	return issues
}

func extractParamTypes(sig string) []string {
	if sig == "" {
		return nil
	}
	open := strings.Index(sig, "(")
	close := strings.LastIndex(sig, ")")
	if open < 0 || close < 0 || close <= open+1 {
		return nil
	}
	paramStr := sig[open+1 : close]
	parts := strings.Split(paramStr, ",")
	typeSet := make(map[string]bool)
	for _, p := range parts {
		t := extractTypeName(strings.TrimSpace(p))
		if t != "" {
			typeSet[t] = true
		}
	}
	sorted := make([]string, 0, len(typeSet))
	for t := range typeSet {
		sorted = append(sorted, t)
	}
	sort.Strings(sorted)
	return sorted
}

func extractTypeName(param string) string {
	if idx := strings.LastIndex(param, ":"); idx >= 0 {
		return normalizeTypeName(strings.TrimSpace(param[idx+1:]))
	}
	fields := strings.Fields(param)
	if len(fields) >= 2 {
		return normalizeTypeName(fields[len(fields)-1])
	}
	if len(fields) == 1 {
		return normalizeTypeName(fields[0])
	}
	return ""
}

func normalizeTypeName(t string) string {
	t = strings.TrimRight(t, ")")
	t = strings.TrimPrefix(t, "*")
	t = strings.TrimPrefix(t, "[]")
	t = strings.TrimPrefix(t, "...")
	if t == "" || t == "error" || t == "bool" || t == "string" || t == "int" || t == "float64" || t == "any" || t == "interface{}" || t == "context.Context" {
		return ""
	}
	return t
}

func intersectSorted(a, b []string) []string {
	var result []string
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			result = append(result, a[i])
			i++
			j++
		} else if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return result
}

func addUnique(slice *[]string, val string) {
	for _, s := range *slice {
		if s == val {
			return
		}
	}
	*slice = append(*slice, val)
}

func (d *CodeSmellDetector) detectGodPackage(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	fnPkg := buildFuncToPkgMap(pkgs)
	projectPkgs := buildProjectPkgSet(pkgs)

	for _, pkg := range pkgs {
		ca := countAfferentCoupling(pkg, fnPkg, projectPkgs)
		ce := countEfferentCoupling(pkg, projectPkgs)
		abstractness := computeAbstractness(pkg)

		if ca >= 5 && ce >= 5 && abstractness < 0.2 {
			pct := int(abstractness * 100)
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/god-package",
				Dominant:  "package has high coupling in both directions with low abstractness",
				Violation: fmt.Sprintf("%s is a god package — depended on by %d, depends on %d, but only %d%% abstract", domain.ShortPkgName(pkg.Path), ca, ce, pct),
				Locations: []domain.Location{{File: pkg.Path}},
			})
		}
	}
	return issues
}

func countAfferentCoupling(pkg domain.Package, fnPkg map[string]string, projectPkgs map[string]bool) int {
	callerPkgs := make(map[string]bool)
	for _, fn := range pkg.Functions {
		for _, caller := range fn.CalledBy {
			p, ok := fnPkg[caller]
			if !ok {
				p = extractPkgFromQualified(caller)
			}
			if p != "" && p != pkg.Path && projectPkgs[p] {
				callerPkgs[p] = true
			}
		}
	}
	return len(callerPkgs)
}

func countEfferentCoupling(pkg domain.Package, projectPkgs map[string]bool) int {
	count := 0
	for _, imp := range pkg.Imports {
		if projectPkgs[imp] {
			count++
		}
	}
	return count
}

func computeAbstractness(pkg domain.Package) float64 {
	total := len(pkg.Types)
	if total == 0 {
		return 0.0
	}
	ifaces := 0
	for _, t := range pkg.Types {
		if t.Kind == "interface" {
			ifaces++
		}
	}
	return float64(ifaces) / float64(total)
}

func buildFuncToPkgMap(pkgs []domain.Package) map[string]string {
	m := make(map[string]string)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			qualified := pkg.Path + "." + fn.Name
			m[qualified] = pkg.Path
		}
	}
	return m
}

func buildProjectPkgSet(pkgs []domain.Package) map[string]bool {
	s := make(map[string]bool)
	for _, pkg := range pkgs {
		s[pkg.Path] = true
	}
	return s
}

func samePkg(qualifiedPkg, fullPkgPath string) bool {
	if qualifiedPkg == fullPkgPath {
		return true
	}
	return strings.HasSuffix(fullPkgPath, qualifiedPkg) || strings.HasSuffix(qualifiedPkg, fullPkgPath)
}

func extractPkgFromQualified(name string) string {
	idx := strings.LastIndex(name, ".")
	if idx < 0 {
		return ""
	}
	return name[:idx]
}

func lastSegment(name string) string {
	idx := strings.LastIndex(name, ".")
	if idx < 0 {
		return name
	}
	return name[idx+1:]
}

func locationFromFunc(fn domain.Function) []domain.Location {
	if fn.File == "" {
		return nil
	}
	return []domain.Location{{File: fn.File, Line: fn.Line}}
}
