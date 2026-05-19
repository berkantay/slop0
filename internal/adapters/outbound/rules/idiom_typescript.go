package rules

import (
	"fmt"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type TypeScriptIdiomDetector struct{}

func (d *TypeScriptIdiomDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		issues = append(issues, detectAnyType(pkg)...)
		issues = append(issues, detectNonNullAssertion(pkg)...)
		issues = append(issues, detectTSNamingIssues(pkg)...)
		issues = append(issues, detectConsoleLog(pkg)...)
	}

	return issues
}

func detectAnyType(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if strings.Contains(fn.Signature, ": any") || strings.Contains(fn.Signature, ":any") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/any-type",
				Dominant:  "avoid 'any' type — it disables type checking",
				Violation: fmt.Sprintf("%s.%s uses 'any' in signature", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	for _, t := range pkg.Types {
		for _, f := range t.Fields {
			if f.Type == "any" || strings.HasPrefix(f.Type, ": any") {
				issues = append(issues, domain.PatternIssue{
					Category:  "style/any-type",
					Dominant:  "avoid 'any' type — it disables type checking",
					Violation: fmt.Sprintf("%s.%s.%s is typed as 'any'", domain.ShortPkgName(pkg.Path), t.Name, f.Name),
					Locations: []domain.Location{{File: pkg.Path}},
				})
			}
		}
	}

	return issues
}

func detectNonNullAssertion(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if strings.Contains(fn.Signature, "!.") || strings.Contains(fn.Signature, "!)") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/non-null-assertion",
				Dominant:  "non-null assertion (!) bypasses type safety — use proper null checks",
				Violation: fmt.Sprintf("%s.%s uses non-null assertion", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	return issues
}

func detectTSNamingIssues(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, t := range pkg.Types {
		if t.Kind == "interface" && strings.HasPrefix(t.Name, "I") && len(t.Name) > 1 {
			second := rune(t.Name[1])
			if second >= 'A' && second <= 'Z' {
				issues = append(issues, domain.PatternIssue{
					Category:  "naming/interface-prefix",
					Dominant:  "TypeScript convention: don't prefix interfaces with 'I'",
					Violation: fmt.Sprintf("%s.%s — use %s instead", domain.ShortPkgName(pkg.Path), t.Name, t.Name[1:]),
					Locations: []domain.Location{{File: pkg.Path}},
				})
			}
		}
	}

	return issues
}

func detectConsoleLog(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		for _, call := range fn.Calls {
			if strings.Contains(call, "console.log") || strings.Contains(call, "console.warn") || strings.Contains(call, "console.error") {
				if !strings.Contains(fn.File, "test") && !strings.Contains(fn.File, "spec") {
					issues = append(issues, domain.PatternIssue{
						Category:  "style/console-log",
						Dominant:  "console.log in production code — use a proper logger",
						Violation: fmt.Sprintf("%s.%s calls %s", domain.ShortPkgName(pkg.Path), fn.Name, call),
						Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
					})
				}
			}
		}
	}

	return issues
}
