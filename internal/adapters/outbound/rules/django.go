package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type DjangoDetector struct{}

func (d *DjangoDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	if !d.isDjango(pkgs) {
		return nil
	}

	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			if !strings.HasSuffix(fn.File, ".py") {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.analyzeFile(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func (d *DjangoDetector) isDjango(pkgs []domain.Package) bool {
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if strings.Contains(imp, "django") {
				return true
			}
		}
	}
	return false
}

func (d *DjangoDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	fname := filepath.Base(file)
	lines := strings.Split(string(src), "\n")
	var issues []domain.PatternIssue

	issues = append(issues, d.detectNPlusOneInLoop(lines, fname, modPath)...)
	issues = append(issues, d.detectRawSQLWithoutParams(lines, fname, modPath)...)
	issues = append(issues, d.detectMissingMeta(lines, fname, modPath)...)
	issues = append(issues, d.detectMissingStr(lines, fname, modPath)...)
	issues = append(issues, d.detectForeignKeyWithoutOnDelete(lines, fname, modPath)...)
	issues = append(issues, d.detectHardcodedSettings(lines, fname, modPath)...)
	issues = append(issues, d.detectAllWithoutPagination(lines, fname, modPath)...)

	return issues
}

// detectNPlusOneInLoop finds ORM calls (.filter, .get, .exclude) inside for loops.
var djangoORMCallRe = regexp.MustCompile(`\.(filter|get|exclude)\(`)

func (d *DjangoDetector) detectNPlusOneInLoop(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "for ") {
			continue
		}
		end := i + 10
		if end > len(lines) {
			end = len(lines)
		}
		for j := i + 1; j < end; j++ {
			if djangoORMCallRe.MatchString(lines[j]) {
				issues = append(issues, domain.PatternIssue{
					Category:   "django",
					Dominant:   "n+1-in-loop",
					Violation:  fmt.Sprintf("ORM query inside for loop at %s:%d — likely N+1 query; use select_related/prefetch_related", fname, j+1),
					Confidence: domain.ConfidenceHigh,
					Locations:  []domain.Location{{File: fname, Line: j + 1}},
				})
				break
			}
		}
	}

	return issues
}

// detectRawSQLWithoutParams flags raw SQL built with string interpolation.
var rawSQLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.raw\(f"`),
	regexp.MustCompile(`\.raw\(f'`),
	regexp.MustCompile(`\.raw\("[^"]*%s`),
	regexp.MustCompile(`\.raw\('[^']*%s`),
	regexp.MustCompile(`cursor\.execute\(f"`),
	regexp.MustCompile(`cursor\.execute\(f'`),
	regexp.MustCompile(`execute\("[^"]*"\s*\+`),
	regexp.MustCompile(`execute\('[^']*'\s*\+`),
}

func (d *DjangoDetector) detectRawSQLWithoutParams(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		for _, pat := range rawSQLPatterns {
			if pat.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:   "django",
					Dominant:   "raw-sql-no-params",
					Violation:  fmt.Sprintf("Raw SQL with string interpolation at %s:%d — use parameterized queries to prevent SQL injection", fname, i+1),
					Confidence: domain.ConfidenceHigh,
					Locations:  []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

var modelsModelRe = regexp.MustCompile(`class\s+\w+\(.*models\.Model`)

// detectMissingMeta flags Django models without a Meta class.
func (d *DjangoDetector) detectMissingMeta(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if !modelsModelRe.MatchString(line) {
			continue
		}
		hasMeta := false
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			// next class or top-level def means class body ended
			if j > i+1 && len(lines[j]) > 0 && lines[j][0] != ' ' && lines[j][0] != '\t' && trimmed != "" {
				break
			}
			if strings.Contains(trimmed, "class Meta") {
				hasMeta = true
				break
			}
		}
		if !hasMeta {
			issues = append(issues, domain.PatternIssue{
				Category:   "django",
				Dominant:   "missing-meta-class",
				Violation:  fmt.Sprintf("Model at %s:%d missing class Meta — add Meta with ordering, verbose_name, etc.", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectMissingStr flags Django models without __str__.
func (d *DjangoDetector) detectMissingStr(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if !modelsModelRe.MatchString(line) {
			continue
		}
		hasStr := false
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if j > i+1 && len(lines[j]) > 0 && lines[j][0] != ' ' && lines[j][0] != '\t' && trimmed != "" {
				break
			}
			if strings.Contains(trimmed, "def __str__") {
				hasStr = true
				break
			}
		}
		if !hasStr {
			issues = append(issues, domain.PatternIssue{
				Category:   "django",
				Dominant:   "missing-str-method",
				Violation:  fmt.Sprintf("Model at %s:%d missing __str__ method — add for readable admin/shell representation", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectForeignKeyWithoutOnDelete flags ForeignKey/OneToOneField without on_delete.
var fkFieldRe = regexp.MustCompile(`(ForeignKey|OneToOneField)\(`)

func (d *DjangoDetector) detectForeignKeyWithoutOnDelete(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if !fkFieldRe.MatchString(line) {
			continue
		}
		// Gather the full statement (may span multiple lines)
		stmt := line
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			stmt += lines[j]
			if strings.Contains(lines[j], ")") {
				break
			}
		}
		if !strings.Contains(stmt, "on_delete=") {
			issues = append(issues, domain.PatternIssue{
				Category:   "django",
				Dominant:   "fk-missing-on-delete",
				Violation:  fmt.Sprintf("ForeignKey/OneToOneField at %s:%d missing on_delete — required in Django 2+", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectHardcodedSettings flags hardcoded secrets in settings.py.
var hardcodedSettingsPatterns = []*regexp.Regexp{
	regexp.MustCompile(`SECRET_KEY\s*=\s*["']`),
	regexp.MustCompile(`(?i)DATABASE.*["']postgres`),
	regexp.MustCompile(`(?i)DATABASE.*["']mysql`),
	regexp.MustCompile(`(?i)PASSWORD\s*["']:\s*["'][^"']+["']`),
}

func (d *DjangoDetector) detectHardcodedSettings(lines []string, fname, modPath string) []domain.PatternIssue {
	if fname != "settings.py" {
		return nil
	}

	var issues []domain.PatternIssue

	for i, line := range lines {
		// Skip lines using env vars
		if strings.Contains(line, "os.environ") || strings.Contains(line, "env(") || strings.Contains(line, "os.getenv") {
			continue
		}
		for _, pat := range hardcodedSettingsPatterns {
			if pat.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:   "django",
					Dominant:   "hardcoded-settings",
					Violation:  fmt.Sprintf("Hardcoded sensitive setting at %s:%d — use environment variables or django-environ", fname, i+1),
					Confidence: domain.ConfidenceHigh,
					Locations:  []domain.Location{{File: fname, Line: i + 1}},
				})
				break
			}
		}
	}

	return issues
}

// detectAllWithoutPagination flags .all() calls not followed by slicing or pagination.
var allCallRe = regexp.MustCompile(`\.all\(\)`)

func (d *DjangoDetector) detectAllWithoutPagination(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if !allCallRe.MatchString(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		// Skip if followed by slicing, .first(), or paginator
		if strings.Contains(trimmed, ".all()[") || strings.Contains(trimmed, "[:") {
			continue
		}
		if strings.Contains(trimmed, ".first()") || strings.Contains(trimmed, ".last()") {
			continue
		}
		if strings.Contains(trimmed, "paginator") || strings.Contains(trimmed, "Paginator") || strings.Contains(trimmed, "paginate") {
			continue
		}
		// Check next line for pagination too
		if i+1 < len(lines) {
			next := strings.TrimSpace(lines[i+1])
			if strings.Contains(next, "paginator") || strings.Contains(next, "Paginator") || strings.Contains(next, "[:") {
				continue
			}
		}

		issues = append(issues, domain.PatternIssue{
			Category:   "django",
			Dominant:   "all-without-pagination",
			Violation:  fmt.Sprintf(".all() at %s:%d without pagination — may load entire table into memory", fname, i+1),
			Confidence: domain.ConfidenceMedium,
			Locations:  []domain.Location{{File: fname, Line: i + 1}},
		})
	}

	return issues
}
