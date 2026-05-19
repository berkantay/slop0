package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type PatternInferrer struct{}

type errorStyle int

const (
	styleUnknown errorStyle = iota
	styleWrap               // wraps another error (preserves chain)
	styleRaw                // creates new error without wrapping
	styleSentinel           // package-level var/const of error type
)

type errorOccurrence struct {
	style errorStyle
	loc   domain.Location
}

type pkgErrorProfile struct {
	pkgPath     string
	occurrences []errorOccurrence
}

func (inf *PatternInferrer) InferErrorPatterns(domainPkgs []domain.Package, t domain.Thresholds) []domain.PatternIssue {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil
	}

	profiles := collectErrorProfiles(pkgs, cfg.Fset)
	return inferErrorViolations(profiles, t)
}

func collectErrorProfiles(pkgs []*packages.Package, fset *token.FileSet) []pkgErrorProfile {
	var profiles []pkgErrorProfile
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			continue
		}
		p := profileErrorHandling(pkg, fset)
		if len(p.occurrences) > 0 {
			profiles = append(profiles, p)
		}
	}
	return profiles
}

func profileErrorHandling(pkg *packages.Package, fset *token.FileSet) pkgErrorProfile {
	profile := pkgErrorProfile{pkgPath: pkg.PkgPath}

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			if !callReturnsError(call, pkg.TypesInfo) {
				return true
			}

			style := classifyErrorCall(call, pkg.TypesInfo)
			if style == styleUnknown {
				return true
			}

			pos := fset.Position(call.Pos())
			profile.occurrences = append(profile.occurrences, errorOccurrence{
				style: style,
				loc:   domain.Location{File: fname, Line: pos.Line},
			})

			return true
		})
	}

	return profile
}

// Type-based classification: look at what the call does structurally
func classifyErrorCall(call *ast.CallExpr, info *types.Info) errorStyle {
	sig := resolveCallSignature(call, info)
	if !sigReturnsError(sig) {
		return styleUnknown
	}

	if hasErrorArg(call, info) || hasWrappingArg(call) {
		return styleWrap
	}

	return styleRaw
}

func sigReturnsError(sig *types.Signature) bool {
	if sig == nil || sig.Results().Len() == 0 {
		return false
	}
	return isErrorInterface(sig.Results().At(sig.Results().Len() - 1).Type())
}

func hasErrorArg(call *ast.CallExpr, info *types.Info) bool {
	for _, arg := range call.Args {
		argTV, ok := info.Types[arg]
		if ok && isErrorInterface(argTV.Type) {
			return true
		}
	}
	return false
}

func hasWrappingArg(call *ast.CallExpr) bool {
	return len(call.Args) > 0 && hasWrappingDirective(call.Args[0])
}

func callReturnsError(call *ast.CallExpr, info *types.Info) bool {
	tv, ok := info.Types[call]
	if !ok {
		return false
	}

	switch t := tv.Type.(type) {
	case *types.Tuple:
		if t.Len() > 0 {
			return isErrorInterface(t.At(t.Len() - 1).Type())
		}
	default:
		return isErrorInterface(t)
	}
	return false
}

func resolveCallSignature(call *ast.CallExpr, info *types.Info) *types.Signature {
	var fnType types.Type

	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if obj, ok := info.Uses[fn]; ok {
			fnType = obj.Type()
		}
	case *ast.SelectorExpr:
		sel, ok := info.Selections[fn]
		if ok {
			fnType = sel.Type()
		} else if obj, ok := info.Uses[fn.Sel]; ok {
			fnType = obj.Type()
		}
	}

	if fnType == nil {
		return nil
	}
	sig, _ := fnType.(*types.Signature)
	return sig
}

func hasWrappingDirective(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok {
		return false
	}
	return strings.Contains(lit.Value, "%w")
}

func inferErrorViolations(profiles []pkgErrorProfile, t domain.Thresholds) []domain.PatternIssue {
	if len(profiles) < 2 {
		return nil
	}

	styleCounts, stylePkgs := aggregateErrorStyles(profiles)
	ds := findDominantStyle(styleCounts)

	if ds.total < t.PatternMinSamples || float64(ds.maxCount)/float64(ds.total) < t.PatternDominance {
		return nil
	}

	return collectErrorViolations(profiles, ds.style, stylePkgs)
}

func aggregateErrorStyles(profiles []pkgErrorProfile) (map[errorStyle]int, map[errorStyle][]string) {
	styleCounts := make(map[errorStyle]int)
	stylePkgs := make(map[errorStyle][]string)

	for _, p := range profiles {
		dominant := dominantErrorStyle(p.occurrences)
		if dominant == styleUnknown {
			continue
		}
		count := countStyle(p.occurrences, dominant)
		styleCounts[dominant] += count
		stylePkgs[dominant] = append(stylePkgs[dominant], domain.ShortPkgName(p.pkgPath))
	}
	return styleCounts, stylePkgs
}

type dominantStyleResult struct {
	style    errorStyle
	maxCount int
	total    int
}

func findDominantStyle(styleCounts map[errorStyle]int) dominantStyleResult {
	var r dominantStyleResult
	for style, count := range styleCounts {
		r.total += count
		if count > r.maxCount {
			r.maxCount = count
			r.style = style
		}
	}
	return r
}

func collectErrorViolations(profiles []pkgErrorProfile, dominantStyle errorStyle, stylePkgs map[errorStyle][]string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, p := range profiles {
		if issue := checkProfileViolation(p, dominantStyle, stylePkgs); issue != nil {
			issues = append(issues, *issue)
		}
	}
	return issues
}

func checkProfileViolation(p pkgErrorProfile, dominantStyle errorStyle, stylePkgs map[errorStyle][]string) *domain.PatternIssue {
	pkgDominant := dominantErrorStyle(p.occurrences)
	if pkgDominant == dominantStyle || pkgDominant == styleUnknown {
		return nil
	}

	count := countStyle(p.occurrences, pkgDominant)
	var locs []domain.Location
	for _, o := range p.occurrences {
		if o.style == pkgDominant {
			locs = append(locs, o.loc)
		}
	}

	return &domain.PatternIssue{
		Category:  "error-handling",
		Dominant:  fmt.Sprintf("%s (%s)", styleLabel(dominantStyle), strings.Join(stylePkgs[dominantStyle], ", ")),
		Violation: fmt.Sprintf("%s uses %s (%d occurrences)", domain.ShortPkgName(p.pkgPath), styleLabel(pkgDominant), count),
		Locations: locs,
	}
}

func dominantErrorStyle(occurrences []errorOccurrence) errorStyle {
	counts := make(map[errorStyle]int)
	for _, o := range occurrences {
		counts[o.style]++
	}
	var best errorStyle
	bestCount := 0
	for style, count := range counts {
		if count > bestCount {
			bestCount = count
			best = style
		}
	}
	return best
}

func countStyle(occurrences []errorOccurrence, style errorStyle) int {
	count := 0
	for _, o := range occurrences {
		if o.style == style {
			count++
		}
	}
	return count
}

func styleLabel(s errorStyle) string {
	switch s {
	case styleWrap:
		return "wrap"
	case styleRaw:
		return "raw"
	case styleSentinel:
		return "sentinel"
	default:
		return "unknown"
	}
}

func (inf *PatternInferrer) InferErrorPatternsFromCache(cache *PkgCache, t domain.Thresholds) []domain.PatternIssue {
	pkgs, fset := cache.Typed()
	var profiles []pkgErrorProfile
	for _, pkg := range pkgs {
		if len(pkg.Errors) > 0 {
			continue
		}
		p := profileErrorHandling(pkg, fset)
		if len(p.occurrences) > 0 {
			profiles = append(profiles, p)
		}
	}
	return inferErrorViolations(profiles, t)
}
