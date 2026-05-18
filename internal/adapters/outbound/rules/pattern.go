package rules

import (
	"fmt"
	"go/ast"
	"strings"
	"unicode"

	"github.com/berkantay/slop0/internal/domain"
)

type PatternDetector struct{}

func (d *PatternDetector) Detect(pkgs []domain.Package, t domain.Thresholds) ([]domain.PatternIssue, error) {
	var issues []domain.PatternIssue

	if naming := d.detectNamingInconsistencies(pkgs, t); len(naming) > 0 {
		issues = append(issues, naming...)
	}

	return issues, nil
}

type funcRole int

const (
	roleConstructor funcRole = iota
	roleReader
	roleWriter
	rolePredicate
	roleOther
)

func (d *PatternDetector) detectNamingInconsistencies(pkgs []domain.Package, t domain.Thresholds) []domain.PatternIssue {
	roleVerbs := classifyAndGroupByRole(pkgs)
	var issues []domain.PatternIssue

	for role, verbs := range roleVerbs {
		if len(verbs) <= 1 {
			continue
		}
		issues = append(issues, checkVerbConsistency(role, verbs, t)...)
	}

	return issues
}

type verbUsage struct {
	verb  string
	count int
	locs  []domain.Location
}

func classifyAndGroupByRole(pkgs []domain.Package) map[funcRole]map[string]*verbUsage {
	roleVerbs := make(map[funcRole]map[string]*verbUsage)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			recordFuncVerb(fn, roleVerbs)
		}
	}
	return roleVerbs
}

func recordFuncVerb(fn domain.Function, roleVerbs map[funcRole]map[string]*verbUsage) {
	if !ast.IsExported(fn.Name) {
		return
	}

	verb := extractVerb(fn.Name)
	if verb == "" || len(verb) < 2 {
		return
	}

	role := classifyFuncRole(fn)
	if role == roleOther {
		return
	}

	if roleVerbs[role] == nil {
		roleVerbs[role] = make(map[string]*verbUsage)
	}

	v, ok := roleVerbs[role][verb]
	if !ok {
		v = &verbUsage{verb: verb}
		roleVerbs[role][verb] = v
	}
	v.count++
	v.locs = append(v.locs, domain.Location{File: fn.File, Line: fn.Line})
}

func classifyFuncRole(fn domain.Function) funcRole {
	sig := fn.Signature
	retPart := extractReturnPart(sig)

	hasReceiver := isMethodSignature(sig)

	if !hasReceiver && retPart != "" && !isErrorOnly(retPart) {
		return roleConstructor
	}

	if retPart == "bool" {
		return rolePredicate
	}

	if hasReceiver && returnsValues(retPart) {
		return roleReader
	}

	if hasReceiver && (retPart == "" || isErrorOnly(retPart)) {
		return roleWriter
	}

	return roleOther
}

func isMethodSignature(sig string) bool {
	return strings.HasPrefix(sig, "(")
}

func extractReturnPart(sig string) string {
	idx := strings.LastIndex(sig, ")")
	if idx < 0 || idx >= len(sig)-1 {
		return ""
	}
	return strings.TrimSpace(sig[idx+1:])
}

func isErrorOnly(ret string) bool {
	ret = strings.Trim(ret, "()")
	return strings.TrimSpace(ret) == "error"
}

func returnsValues(ret string) bool {
	if ret == "" {
		return false
	}
	ret = strings.Trim(ret, "()")
	parts := strings.Split(ret, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && p != "error" {
			return true
		}
	}
	return false
}

func checkVerbConsistency(role funcRole, verbs map[string]*verbUsage, t domain.Thresholds) []domain.PatternIssue {
	var dominant *verbUsage
	total := 0
	for _, v := range verbs {
		total += v.count
		if dominant == nil || v.count > dominant.count {
			dominant = v
		}
	}

	if total < t.PatternMinSamples || float64(dominant.count)/float64(total) < t.PatternDominance {
		return nil
	}

	var issues []domain.PatternIssue
	for _, v := range verbs {
		if v.verb == dominant.verb || v.count < 2 {
			continue
		}
		issues = append(issues, domain.PatternIssue{
			Category:  "naming",
			Dominant:  fmt.Sprintf("%s* (%d usages in %s role)", dominant.verb, dominant.count, roleLabel(role)),
			Violation: fmt.Sprintf("%s* (%d usages)", v.verb, v.count),
			Locations: v.locs,
		})
	}
	return issues
}

func roleLabel(r funcRole) string {
	switch r {
	case roleConstructor:
		return "constructor"
	case roleReader:
		return "reader"
	case roleWriter:
		return "writer"
	case rolePredicate:
		return "predicate"
	default:
		return "other"
	}
}

func extractVerb(name string) string {
	if len(name) < 2 {
		return ""
	}
	for i := 1; i < len(name); i++ {
		if unicode.IsUpper(rune(name[i])) {
			return name[:i]
		}
	}
	return ""
}
