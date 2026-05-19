package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/berkantay/slop0/internal/domain"
)

type CodeQualityDetector struct{}

func (d *CodeQualityDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		issues = append(issues, detectMissingTests(pkg)...)

		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, analyzeFileQuality(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func analyzeFileQuality(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	fname := filepath.Base(file)
	var issues []domain.PatternIssue

	issues = append(issues, detectTodoFixme(src, fname, modPath)...)
	issues = append(issues, detectDeadBranches(src, fname, modPath)...)
	issues = append(issues, detectEmptyCatch(src, fname, modPath)...)
	issues = append(issues, detectMagicNumbers(src, fname, modPath, file)...)
	issues = append(issues, detectDeepNesting(src, fname, modPath)...)

	if isTestFile(file) {
		issues = append(issues, detectEmptyTests(src, fname, modPath, file)...)
		issues = append(issues, detectNoAssertions(src, fname, modPath, file)...)
	}

	return issues
}

func detectMissingTests(pkg domain.Package) []domain.PatternIssue {
	srcFiles := make(map[string]bool)
	testFiles := make(map[string]bool)

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		if isTestFile(fn.File) {
			testFiles[fn.File] = true
		} else {
			srcFiles[fn.File] = true
		}
	}

	if len(srcFiles) > 0 && len(testFiles) == 0 {
		return []domain.PatternIssue{{
			Category:  "test/missing-tests",
			Dominant:  "module has source files but no test files",
			Violation: fmt.Sprintf("%s: no test files", domain.ShortPkgName(pkg.Path)),
			Locations: []domain.Location{{File: pkg.Path}},
		}}
	}

	return nil
}

func detectEmptyTests(src []byte, fname, modPath, file string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	ext := filepath.Ext(file)
	lines := strings.Split(string(src), "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		isTestFunc := false

		switch ext {
		case ".go":
			isTestFunc = strings.HasPrefix(trimmed, "func Test") && strings.Contains(trimmed, "(t *testing.T)")
		case ".py":
			isTestFunc = strings.HasPrefix(trimmed, "def test_")
		case ".ts", ".tsx", ".js", ".jsx":
			isTestFunc = strings.Contains(trimmed, "it(") || strings.Contains(trimmed, "test(")
		}

		if !isTestFunc {
			continue
		}

		bodyEmpty := isNextBodyEmpty(lines, i)
		if bodyEmpty {
			issues = append(issues, domain.PatternIssue{
				Category:  "test/empty-test",
				Dominant:  "test function with empty body — remove or implement",
				Violation: fmt.Sprintf("%s: empty test at line %d", modPath, i+1),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

func detectNoAssertions(src []byte, fname, modPath, file string) []domain.PatternIssue {
	content := string(src)

	assertionPatterns := []string{
		"assert", "Assert", "expect(", "require.", "t.Error", "t.Fatal",
		"t.Fail", "should.", "toBe(", "toEqual(", "toMatch(", "toThrow(",
		"toHaveBeenCalled", "toContain(", "assertTrue", "assertEqual",
	}

	hasAssertions := false
	for _, p := range assertionPatterns {
		if strings.Contains(content, p) {
			hasAssertions = true
			break
		}
	}

	hasTestFunc := strings.Contains(content, "func Test") || strings.Contains(content, "def test_") ||
		strings.Contains(content, "it(") || strings.Contains(content, "test(") ||
		strings.Contains(content, "describe(")

	if hasTestFunc && !hasAssertions {
		return []domain.PatternIssue{{
			Category:  "test/no-assertions",
			Dominant:  "test file has no assertions — tests should verify behavior",
			Violation: fmt.Sprintf("%s: no assertions found", modPath),
			Locations: []domain.Location{{File: fname}},
		}}
	}

	return nil
}

func detectTodoFixme(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	pattern := regexp.MustCompile(`(?i)\b(TODO|FIXME|HACK|XXX)\b`)

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		if pattern.MatchString(line) && isComment(line) {
			issues = append(issues, domain.PatternIssue{
				Category:  "quality/todo-fixme",
				Dominant:  "TODO/FIXME marker — unresolved tech debt",
				Violation: fmt.Sprintf("%s: %s", modPath, strings.TrimSpace(line)),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

func detectDeadBranches(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\bif\s+(true|false)\s*[{:]`),
		regexp.MustCompile(`\bif\s+(True|False)\s*:`),
	}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, p := range patterns {
			if p.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:  "quality/dead-branch",
					Dominant:  "condition is always true/false — dead code",
					Violation: fmt.Sprintf("%s: dead branch at line %d", modPath, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
			}
		}
	}

	return issues
}

func detectEmptyCatch(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`catch\s*\([^)]*\)\s*\{\s*\}`),
		regexp.MustCompile(`except\s*.*:\s*\n\s*pass\s*$`),
	}

	content := string(src)
	for _, p := range patterns {
		locs := p.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			line := strings.Count(content[:loc[0]], "\n") + 1
			issues = append(issues, domain.PatternIssue{
				Category:  "quality/empty-catch",
				Dominant:  "empty catch/except block — handle or log the error",
				Violation: fmt.Sprintf("%s: empty catch at line %d", modPath, line),
				Locations: []domain.Location{{File: fname, Line: line}},
			})
		}
	}

	return issues
}

func detectMagicNumbers(src []byte, fname, modPath, file string) []domain.PatternIssue {
	if isTestFile(file) {
		return nil
	}

	var issues []domain.PatternIssue

	pattern := regexp.MustCompile(`\b(\d{3,})\b`)
	allowed := map[string]bool{"100": true, "200": true, "201": true, "204": true, "400": true, "401": true, "403": true, "404": true, "500": true, "1000": true, "1024": true}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "const") || strings.HasPrefix(trimmed, "#") || isComment(trimmed) {
			continue
		}

		matches := pattern.FindAllString(line, -1)
		for _, m := range matches {
			if !allowed[m] && !strings.Contains(line, "0x") {
				issues = append(issues, domain.PatternIssue{
					Category:  "quality/magic-number",
					Dominant:  "magic number — extract to named constant",
					Violation: fmt.Sprintf("%s: magic number %s at line %d", modPath, m, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

func detectDeepNesting(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	lines := strings.Split(string(src), "\n")
	maxDepth := 0
	maxLine := 0

	for i, line := range lines {
		indent := countLeadingTabs(line) + countLeadingSpaces(line)/4
		if indent > maxDepth {
			maxDepth = indent
			maxLine = i + 1
		}
	}

	if maxDepth > 5 {
		issues = append(issues, domain.PatternIssue{
			Category:  "quality/deep-nesting",
			Dominant:  fmt.Sprintf("nesting depth %d — extract to functions", maxDepth),
			Violation: fmt.Sprintf("%s: deepest nesting at line %d", modPath, maxLine),
			Locations: []domain.Location{{File: fname, Line: maxLine}},
		})
	}

	return issues
}

func isTestFile(file string) bool {
	base := filepath.Base(file)
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasPrefix(base, "test_") ||
		strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") ||
		strings.Contains(base, "_test.py")
}

func isComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*")
}

func isNextBodyEmpty(lines []string, funcLine int) bool {
	braceCount := 0
	started := false
	stmtCount := 0

	for i := funcLine; i < len(lines) && i < funcLine+10; i++ {
		line := strings.TrimSpace(lines[i])

		if strings.Contains(line, "{") {
			braceCount++
			started = true
		}
		if strings.Contains(line, "}") {
			braceCount--
		}

		if started && braceCount > 0 && line != "{" && line != "" {
			stmtCount++
		}

		if started && braceCount == 0 {
			return stmtCount <= 1
		}

		if strings.HasSuffix(line, ":") && i == funcLine {
			nextIdx := i + 1
			if nextIdx < len(lines) {
				next := strings.TrimSpace(lines[nextIdx])
				return next == "pass" || next == "..." || next == ""
			}
		}
	}

	return false
}

func countLeadingTabs(line string) int {
	count := 0
	for _, r := range line {
		if r == '\t' {
			count++
		} else {
			break
		}
	}
	return count
}

func countLeadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r == ' ' {
			count++
		} else if unicode.IsSpace(r) {
			continue
		} else {
			break
		}
	}
	return count
}
