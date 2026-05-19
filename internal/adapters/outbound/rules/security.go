package rules

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/berkantay/slop0/internal/domain"
)

type SecurityDetector struct {
	tsParser *sitter.Parser
}

func NewSecurityDetector() *SecurityDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &SecurityDetector{tsParser: parser}
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["'][^"']{8,}`),
	regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["'][^"']{8,}`),
	regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}`),
	regexp.MustCompile(`(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}`),
	regexp.MustCompile(`(?i)(private[_-]?key)\s*[:=]\s*["'][^"']{8,}`),
	regexp.MustCompile(`(?i)(client[_-]?secret)\s*[:=]\s*["'][^"']{8,}`),
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._\-]{20,}`),
	regexp.MustCompile(`(?i)ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?i)sk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
}

func (d *SecurityDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.analyzeFile(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func (d *SecurityDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	fname := filepath.Base(file)
	var issues []domain.PatternIssue

	issues = append(issues, detectHardcodedSecrets(src, fname, modPath)...)
	issues = append(issues, detectSQLInjection(src, fname, modPath)...)
	issues = append(issues, detectCommandInjection(src, fname, modPath)...)
	issues = append(issues, detectXSSSinks(src, fname, modPath, file, d.tsParser)...)
	issues = append(issues, detectInsecureDeserialization(src, fname, modPath)...)
	issues = append(issues, detectCORSWildcard(src, fname, modPath)...)
	issues = append(issues, detectNextPublicMisuse(src, fname, modPath)...)

	return issues
}

func detectHardcodedSecrets(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	if strings.Contains(fname, "test") || strings.Contains(fname, "mock") || strings.Contains(fname, "fixture") || strings.Contains(fname, "example") {
		return nil
	}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, pattern := range secretPatterns {
			if pattern.MatchString(line) {
				if isLikelyPlaceholder(line) {
					continue
				}
				issues = append(issues, domain.PatternIssue{
					Category:  "security/hardcoded-secret",
					Dominant:  "hardcoded secret — use environment variable",
					Violation: fmt.Sprintf("%s: potential secret at line %d", modPath, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}

		if containsHighEntropyString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:  "security/hardcoded-secret",
				Dominant:  "high-entropy string — possible hardcoded credential",
				Violation: fmt.Sprintf("%s: suspicious string at line %d", modPath, i+1),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

func detectSQLInjection(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	sqlPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(execute|query|raw)\s*\(\s*f["']`),
		regexp.MustCompile(`(?i)(execute|query|raw)\s*\([^)]*\+`),
		regexp.MustCompile("(?i)(execute|query|raw)\\s*\\(\\s*`[^`]*\\$\\{"),
		regexp.MustCompile(`(?i)(execute|query|raw)\s*\(\s*["'].*%s`),
		regexp.MustCompile(`(?i)\.format\s*\([^)]*\)\s*\)`),
	}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, p := range sqlPatterns {
			if p.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:  "security/sql-injection",
					Dominant:  "SQL query with string interpolation — use parameterized queries",
					Violation: fmt.Sprintf("%s: potential SQL injection at line %d", modPath, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

func detectCommandInjection(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	cmdPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)exec\s*\(\s*f["']`),
		regexp.MustCompile("(?i)exec\\s*\\(\\s*`[^`]*\\$\\{"),
		regexp.MustCompile(`(?i)(subprocess\.call|subprocess\.Popen|os\.system)\s*\(`),
		regexp.MustCompile(`(?i)shell\s*[:=]\s*True`),
		regexp.MustCompile(`(?i)child_process\.(exec|execSync)\s*\(`),
	}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, p := range cmdPatterns {
			if p.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:  "security/command-injection",
					Dominant:  "command execution with dynamic input — use parameterized commands or allowlists",
					Violation: fmt.Sprintf("%s: potential command injection at line %d", modPath, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

func detectXSSSinks(src []byte, fname, modPath, file string, parser *sitter.Parser) []domain.PatternIssue {
	if !strings.HasSuffix(file, ".tsx") && !strings.HasSuffix(file, ".jsx") && !strings.HasSuffix(file, ".ts") && !strings.HasSuffix(file, ".js") {
		return nil
	}

	var issues []domain.PatternIssue

	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil
	}

	walkTS(tree.RootNode(), func(node *sitter.Node) {
		if node.Type() == "jsx_attribute" {
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil && tsNodeText(nameNode, src) == "dangerouslySetInnerHTML" {
				issues = append(issues, domain.PatternIssue{
					Category:  "security/xss",
					Dominant:  "dangerouslySetInnerHTML — XSS risk, sanitize input",
					Violation: fmt.Sprintf("%s: dangerouslySetInnerHTML", modPath),
					Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
				})
			}
		}
	})

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		if strings.Contains(line, ".innerHTML") && strings.Contains(line, "=") {
			issues = append(issues, domain.PatternIssue{
				Category:  "security/xss",
				Dominant:  "innerHTML assignment — XSS risk, use textContent or framework rendering",
				Violation: fmt.Sprintf("%s: innerHTML assignment", modPath),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

func detectInsecureDeserialization(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)eval\s*\([^"'][^)]*\)`),
		regexp.MustCompile(`(?i)pickle\.loads?\s*\(`),
		regexp.MustCompile(`(?i)yaml\.load\s*\([^)]*\)`),
		regexp.MustCompile(`(?i)yaml\.unsafe_load\s*\(`),
		regexp.MustCompile(`(?i)marshal\.loads?\s*\(`),
	}

	yamlSafe := regexp.MustCompile(`(?i)yaml\.load\s*\([^)]*Loader\s*=`)

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, p := range patterns {
			if !p.MatchString(line) {
				continue
			}
			if strings.Contains(line, "yaml.load") && yamlSafe.MatchString(line) {
				continue
			}
			issues = append(issues, domain.PatternIssue{
				Category:  "security/insecure-deserialization",
				Dominant:  "unsafe deserialization — use safe alternatives",
				Violation: fmt.Sprintf("%s: insecure deserialization at line %d", modPath, i+1),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
			break
		}
	}

	return issues
}

func detectCORSWildcard(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)allow.?origin.*['"]\*['"]`),
		regexp.MustCompile(`(?i)cors.*origin.*['"]\*['"]`),
		regexp.MustCompile(`(?i)allow_origins.*\[.*['"]\*['"]`),
	}

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		for _, p := range patterns {
			if p.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:  "security/cors-wildcard",
					Dominant:  "CORS wildcard origin (*) — restrict to specific domains",
					Violation: fmt.Sprintf("%s: CORS wildcard at line %d", modPath, i+1),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

func detectNextPublicMisuse(src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	pattern := regexp.MustCompile(`(?i)process\.env\.NEXT_PUBLIC_[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|PRIVATE|CREDENTIAL)[A-Z_]*`)

	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		if pattern.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:  "security/next-public-secret",
				Dominant:  "NEXT_PUBLIC_ prefix exposes value to client — secrets must not use NEXT_PUBLIC_",
				Violation: fmt.Sprintf("%s: NEXT_PUBLIC_ with secret-like name at line %d", modPath, i+1),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

func isLikelyPlaceholder(line string) bool {
	placeholders := []string{
		"your_", "xxx", "placeholder", "example", "changeme", "todo",
		"<your", "INSERT", "REPLACE", "dummy", "test", "fake", "sample",
	}
	lower := strings.ToLower(line)
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func containsHighEntropyString(line string) bool {
	re := regexp.MustCompile(`["'][A-Za-z0-9+/=_\-]{40,}["']`)
	matches := re.FindAllString(line, -1)

	for _, match := range matches {
		inner := match[1 : len(match)-1]
		if shannonEntropy(inner) > 4.5 {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}
