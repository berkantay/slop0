package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
		issues = append(issues, detectAsTypeAssertionOveruse(pkg)...)
		issues = append(issues, detectMissingReturnTypesOnExports(pkg)...)
		issues = append(issues, detectEnumUsage(pkg)...)
		issues = append(issues, detectNonNullAssertionCountPerFile(pkg)...)
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

var reAsKeyword = regexp.MustCompile(`\bas\s+`)
var reMissingReturnType = regexp.MustCompile(`^export\s+(?:function|const)\s+\w+[^:]*[{=]`)
var reEnum = regexp.MustCompile(`\benum\b`)

func detectAsTypeAssertionOveruse(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		src, err := os.ReadFile(fn.File)
		if err != nil {
			continue
		}
		content := string(src)

		// Count "as " keywords in the function's rough vicinity using signature+calls as proxy
		// Better: count per-file basis
		matches := reAsKeyword.FindAllStringIndex(content, -1)
		if len(matches) > 3 {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/as-assertion-overuse",
				Dominant:  "excessive 'as' type assertions bypass type safety — refine types instead",
				Violation: fmt.Sprintf("%s: %d 'as' assertions in %s", domain.ShortPkgName(pkg.Path), len(matches), filepath.Base(fn.File)),
				Locations: []domain.Location{{File: filepath.Base(fn.File), Line: fn.Line}},
			})
		}
		break // one check per file from this package
	}
	return issues
}

func detectMissingReturnTypesOnExports(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		src, err := os.ReadFile(fn.File)
		if err != nil {
			continue
		}

		fname := filepath.Base(fn.File)
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			if reMissingReturnType.MatchString(line) {
				// Check there's no colon after the closing paren before { or =>
				afterParams := line
				if idx := strings.LastIndex(afterParams, ")"); idx >= 0 {
					rest := afterParams[idx+1:]
					if !strings.Contains(rest, ":") {
						issues = append(issues, domain.PatternIssue{
							Category:  "style/missing-return-type",
							Dominant:  "exported function missing explicit return type — add return type annotation",
							Violation: fmt.Sprintf("%s: %s", domain.ShortPkgName(pkg.Path), strings.TrimSpace(line)),
							Locations: []domain.Location{{File: fname, Line: i + 1}},
						})
					}
				}
			}
		}
		break // one check per file from this package
	}
	return issues
}

func detectEnumUsage(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		src, err := os.ReadFile(fn.File)
		if err != nil {
			continue
		}

		fname := filepath.Base(fn.File)
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if reEnum.MatchString(trimmed) && !strings.HasPrefix(trimmed, "//") && !strings.HasPrefix(trimmed, "*") {
				issues = append(issues, domain.PatternIssue{
					Category:  "style/enum-usage",
					Dominant:  "prefer union types over enums — they are more flexible and tree-shakeable",
					Violation: fmt.Sprintf("%s: %s", domain.ShortPkgName(pkg.Path), trimmed),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
			}
		}
		break // one check per file from this package
	}
	return issues
}

func detectNonNullAssertionCountPerFile(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		src, err := os.ReadFile(fn.File)
		if err != nil {
			continue
		}

		content := string(src)
		fname := filepath.Base(fn.File)
		count := strings.Count(content, "!.") + strings.Count(content, "!)")
		if count > 5 {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/non-null-assertion-overuse",
				Dominant:  fmt.Sprintf("%d non-null assertions in file — use proper null checks or optional chaining", count),
				Violation: fmt.Sprintf("%s: %s", domain.ShortPkgName(pkg.Path), fname),
				Locations: []domain.Location{{File: fname, Line: 1}},
			})
		}
		break // one check per file from this package
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
