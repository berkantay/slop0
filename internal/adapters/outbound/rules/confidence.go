package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type ConfidenceScorer struct{}

func (s *ConfidenceScorer) ScorePatterns(patterns []domain.DesignPattern, pkgs []domain.Package) []domain.DesignPattern {
	usageSites := buildUsageSiteMap(pkgs)
	ifaceMethodCounts := buildIfaceMethodCounts(pkgs)

	for i := range patterns {
		patterns[i].Confidence = s.scorePattern(patterns[i], usageSites, ifaceMethodCounts)
	}
	return patterns
}

func (s *ConfidenceScorer) ScoreIssues(issues []domain.PatternIssue, pkgs []domain.Package) []domain.PatternIssue {
	ctx := buildIssueContext(pkgs)
	for i := range issues {
		issues[i].Confidence = s.scoreIssueDynamic(issues[i], ctx)
	}
	return issues
}

type issueContext struct {
	totalFuncs int
}

func buildIssueContext(pkgs []domain.Package) issueContext {
	ctx := issueContext{}
	for _, pkg := range pkgs {
		ctx.totalFuncs += len(pkg.Functions)
	}
	return ctx
}

func (s *ConfidenceScorer) scoreIssueDynamic(issue domain.PatternIssue, ctx issueContext) domain.Confidence {
	signals := issueSignals(issue, ctx)
	if len(signals) == 0 {
		return domain.ConfidenceMedium
	}
	return domain.Confidence(domain.NoisyOR(signals...))
}

type signalFunc func(domain.PatternIssue, issueContext) []float64

var signalDispatch = map[string]signalFunc{
	"error-handling/unchecked": func(i domain.PatternIssue, _ issueContext) []float64 { return uncheckedErrorSignals(i) },
	"error-handling":           func(i domain.PatternIssue, _ issueContext) []float64 { return errorConsistencySignals(i) },
	"naming/stutter":           func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.7, 0.5} },
	"naming/underscore":        func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.7, 0.5} },
	"naming/redundant-getter":  func(i domain.PatternIssue, _ issueContext) []float64 { return redundantGetterSignals(i) },
	"naming/interface":         func(_ domain.PatternIssue, _ issueContext) []float64 { return interfaceNamingSignals() },
	"naming":                   func(i domain.PatternIssue, c issueContext) []float64 { return namingConsistencySignals(i, c) },
	"style/context-first-param": func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.6, 0.5} },
	"style/error-last-return":   func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.6, 0.5} },
	"style/unnecessary-else":    func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.6, 0.5} },
	"style/naked-return":        func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.5, 0.4} },
	"style/empty-interface":     func(i domain.PatternIssue, _ issueContext) []float64 { return emptyInterfaceSignals(i) },
	"arch/concrete-return":      func(i domain.PatternIssue, _ issueContext) []float64 { return concreteReturnSignals(i) },
	"arch/domain-leakage":       func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.5, 0.5} },
	"arch/cross-feature":        func(_ domain.PatternIssue, _ issueContext) []float64 { return []float64{0.5, 0.4} },
}

func issueSignals(issue domain.PatternIssue, ctx issueContext) []float64 {
	if fn, ok := signalDispatch[issue.Category]; ok {
		return fn(issue, ctx)
	}
	if strings.HasPrefix(issue.Category, "complexity/") {
		return complexitySignals(issue)
	}
	return []float64{0.3}
}

func uncheckedErrorSignals(issue domain.PatternIssue) []float64 {
	base := 0.7
	if strings.Contains(strings.ToLower(issue.Violation), "close") ||
		strings.Contains(strings.ToLower(issue.Violation), "flush") {
		return []float64{base * 0.3}
	}
	return []float64{base, 0.4}
}

func errorConsistencySignals(issue domain.PatternIssue) []float64 {
	var signals []float64
	signals = append(signals, 0.4)

	if strings.Contains(issue.Violation, "1 occurrences") {
		signals = append(signals, 0.3)
	}

	if strings.Count(issue.Dominant, ",") > 5 {
		signals = append(signals, 0.3)
	}
	return signals
}

func complexitySignals(issue domain.PatternIssue) []float64 {
	signals := []float64{0.6}

	if strings.Contains(issue.Category, "cognitive") || strings.Contains(issue.Category, "cyclomatic") {
		signals = append(signals, 0.5)
	}

	if strings.Contains(issue.Category, "god-type") {
		signals = append(signals, 0.4)
	}

	if strings.Contains(issue.Violation, "7 parameters") ||
		strings.Contains(issue.Violation, "8 parameters") ||
		strings.Contains(issue.Violation, "9 parameters") {
		signals = append(signals, 0.3)
	}

	return signals
}

func redundantGetterSignals(issue domain.PatternIssue) []float64 {
	signals := []float64{0.4}
	if strings.Contains(issue.Dominant, "field") {
		signals = append(signals, 0.5)
	}
	return signals
}

func interfaceNamingSignals() []float64 {
	return []float64{0.3, 0.2}
}

func namingConsistencySignals(issue domain.PatternIssue, ctx issueContext) []float64 {
	signals := []float64{0.3}
	if strings.Contains(issue.Dominant, "usages)") {
		signals = append(signals, 0.3)
	}
	if ctx.totalFuncs > 100 {
		signals = append(signals, 0.2)
	}
	return signals
}

func emptyInterfaceSignals(issue domain.PatternIssue) []float64 {
	violation := strings.ToLower(issue.Violation)
	if strings.Contains(violation, "marshal") || strings.Contains(violation, "encode") ||
		strings.Contains(violation, "decode") || strings.Contains(violation, "json") ||
		strings.Contains(violation, "rpc") || strings.Contains(violation, "call") {
		return []float64{0.1}
	}
	return []float64{0.3, 0.2}
}

func concreteReturnSignals(issue domain.PatternIssue) []float64 {
	signals := []float64{0.2}
	if strings.Contains(issue.Violation, "adapters") || strings.Contains(issue.Violation, "clients") {
		signals = append(signals, 0.15)
	}
	return signals
}

func (s *ConfidenceScorer) scorePattern(p domain.DesignPattern, usageSites map[string]bool, ifaceMethodCounts map[string]int) domain.Confidence {
	switch p.Name {
	case "port-adapter":
		return s.scorePortAdapter(p, usageSites, ifaceMethodCounts)
	case "strategy":
		return s.scoreStrategy(p)
	case "middleware":
		return s.scoreMiddleware(p)
	case "decorator":
		return s.scoreDecorator(p)
	case "factory":
		return s.scoreFactory(p)
	case "builder":
		return s.scoreBuilder(p)
	case "singleton":
		return s.scoreSingleton(p)
	default:
		return domain.Confidence(domain.NoisyOR(0.3))
	}
}

func (s *ConfidenceScorer) scorePortAdapter(p domain.DesignPattern, usageSites map[string]bool, ifaceMethodCounts map[string]int) domain.Confidence {
	var signals []float64

	var portPkg, adapterPkg, adapterType, portType string
	for _, part := range p.Participants {
		if part.Role == "port" {
			portPkg = part.Package
			portType = part.Type
		}
		if part.Role == "adapter" {
			adapterPkg = part.Package
			adapterType = part.Type
		}
	}

	if portPkg != adapterPkg {
		signals = append(signals, 0.3)
	}

	if usageSites[adapterType+"→"+portType] {
		signals = append(signals, 0.4)
	}

	if count, ok := ifaceMethodCounts[portType]; ok && count >= 2 {
		signals = append(signals, 0.25)
	}

	if portPkg != "" && adapterPkg != "" {
		signals = append(signals, 0.15)
	}

	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreStrategy(p domain.DesignPattern) domain.Confidence {
	implCount := 0
	pkgs := make(map[string]bool)
	for _, part := range p.Participants {
		if part.Role == "implementation" {
			implCount++
			pkgs[part.Package] = true
		}
	}

	var signals []float64

	if implCount >= 3 {
		signals = append(signals, 0.4)
	} else {
		signals = append(signals, 0.25)
	}

	if len(pkgs) >= 2 {
		signals = append(signals, 0.3)
	}

	signals = append(signals, 0.2)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreMiddleware(p domain.DesignPattern) domain.Confidence {
	var signals []float64
	signals = append(signals, 0.5)
	signals = append(signals, 0.4)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreDecorator(p domain.DesignPattern) domain.Confidence {
	var signals []float64
	signals = append(signals, 0.5)
	signals = append(signals, 0.4)
	signals = append(signals, 0.3)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreFactory(p domain.DesignPattern) domain.Confidence {
	var signals []float64
	signals = append(signals, 0.5)
	signals = append(signals, 0.3)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreBuilder(p domain.DesignPattern) domain.Confidence {
	var signals []float64
	signals = append(signals, 0.5)
	signals = append(signals, 0.4)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func (s *ConfidenceScorer) scoreSingleton(p domain.DesignPattern) domain.Confidence {
	var signals []float64
	signals = append(signals, 0.6)
	signals = append(signals, 0.4)
	return domain.Confidence(domain.NoisyOR(signals...))
}

func buildUsageSiteMap(pkgs []domain.Package) map[string]bool {
	sites := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			for _, impl := range t.Implements {
				sites[t.Name+"→"+impl] = true
			}
		}
	}
	return sites
}

func buildIfaceMethodCounts(pkgs []domain.Package) map[string]int {
	counts := make(map[string]int)
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if t.Kind == "interface" {
				counts[t.Name] = len(t.Methods)
			}
		}
	}
	return counts
}
