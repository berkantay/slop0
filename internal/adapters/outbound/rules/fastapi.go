package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type FastAPIDetector struct{}

func (d *FastAPIDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	if !d.isFastAPI(pkgs) {
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

func (d *FastAPIDetector) isFastAPI(pkgs []domain.Package) bool {
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if strings.Contains(imp, "fastapi") {
				return true
			}
		}
	}
	return false
}

func (d *FastAPIDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	fname := filepath.Base(file)
	lines := strings.Split(string(src), "\n")
	var issues []domain.PatternIssue

	issues = append(issues, d.detectMissingResponseModel(lines, fname, modPath)...)
	issues = append(issues, d.detectMissingStatusCode(lines, fname, modPath)...)
	issues = append(issues, d.detectAsyncCallingSync(lines, fname, modPath)...)
	issues = append(issues, d.detectRawDictInput(lines, fname, modPath)...)
	issues = append(issues, d.detectHardcodedCORS(lines, fname, modPath)...)
	issues = append(issues, d.detectNoAPIRouter(lines, fname, modPath)...)

	return issues
}

// detectMissingResponseModel flags route decorators without response_model.
var routeDecoratorRe = regexp.MustCompile(`@(app|router)\.(get|post|put|delete|patch)\(`)

func (d *FastAPIDetector) detectMissingResponseModel(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !routeDecoratorRe.MatchString(trimmed) {
			continue
		}
		// Gather multi-line decorator
		stmt := trimmed
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			stmt += lines[j]
			if strings.Contains(lines[j], ")") {
				break
			}
		}
		if !strings.Contains(stmt, "response_model=") && !strings.Contains(stmt, "response_model =") {
			issues = append(issues, domain.PatternIssue{
				Category:   "fastapi",
				Dominant:   "missing-response-model",
				Violation:  fmt.Sprintf("Route decorator at %s:%d missing response_model — add for automatic validation and docs", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectMissingStatusCode flags POST/PUT/DELETE decorators without status_code.
var mutatingDecoratorRe = regexp.MustCompile(`@(app|router)\.(post|put|delete|patch)\(`)

func (d *FastAPIDetector) detectMissingStatusCode(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !mutatingDecoratorRe.MatchString(trimmed) {
			continue
		}
		stmt := trimmed
		for j := i + 1; j < len(lines) && j < i+5; j++ {
			stmt += lines[j]
			if strings.Contains(lines[j], ")") {
				break
			}
		}
		if !strings.Contains(stmt, "status_code=") && !strings.Contains(stmt, "status_code =") {
			issues = append(issues, domain.PatternIssue{
				Category:   "fastapi",
				Dominant:   "missing-status-code",
				Violation:  fmt.Sprintf("Mutating route at %s:%d missing status_code — POST/PUT/DELETE should declare explicit status codes", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectAsyncCallingSync flags sync blocking calls inside async functions.
var asyncDefRe = regexp.MustCompile(`^\s*async\s+def\s+`)
var syncBlockingCalls = []*regexp.Regexp{
	regexp.MustCompile(`requests\.(get|post|put|delete|patch|head)\(`),
	regexp.MustCompile(`open\(`),
	regexp.MustCompile(`time\.sleep\(`),
}

func (d *FastAPIDetector) detectAsyncCallingSync(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	inAsync := false
	asyncIndent := 0

	for i, line := range lines {
		if asyncDefRe.MatchString(line) {
			inAsync = true
			asyncIndent = lineIndent(line)
			continue
		}
		if inAsync {
			inAsync = !isAsyncFuncEnd(line, asyncIndent)
		}
		if !inAsync {
			continue
		}
		if issue, ok := matchSyncCallInAsync(line, fname, i); ok {
			issues = append(issues, issue)
		}
	}

	return issues
}

func lineIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

func isAsyncFuncEnd(line string, asyncIndent int) bool {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) == 0 {
		return false
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "@") {
		return false
	}
	if lineIndent(line) > asyncIndent {
		return false
	}
	return strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "async def ") || strings.HasPrefix(trimmed, "class ")
}

func matchSyncCallInAsync(line, fname string, idx int) (domain.PatternIssue, bool) {
	for _, pat := range syncBlockingCalls {
		if pat.MatchString(line) {
			return domain.PatternIssue{
				Category:   "fastapi",
				Dominant:   "async-calling-sync",
				Violation:  fmt.Sprintf("Sync blocking call in async function at %s:%d — use async alternatives or run_in_executor", fname, idx+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: idx + 1}},
			}, true
		}
	}
	return domain.PatternIssue{}, false
}

// detectRawDictInput flags function params typed as dict/Dict instead of Pydantic models.
var rawDictParamRe = regexp.MustCompile(`def\s+\w+\([^)]*:\s*(dict|Dict)\b`)

func (d *FastAPIDetector) detectRawDictInput(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if rawDictParamRe.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:   "fastapi",
				Dominant:   "raw-dict-input",
				Violation:  fmt.Sprintf("Function param typed as dict at %s:%d — use a Pydantic model for validation and documentation", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectHardcodedCORS flags allow_origins=["*"].
var corsWildcardRe = regexp.MustCompile(`allow_origins\s*=\s*\[["']\*["']\]`)

func (d *FastAPIDetector) detectHardcodedCORS(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if corsWildcardRe.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:   "fastapi",
				Dominant:   "hardcoded-cors-wildcard",
				Violation:  fmt.Sprintf("CORS allow_origins=['*'] at %s:%d — restrict to specific origins in production", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectNoAPIRouter flags files with 3+ route decorators all on app instead of router.
var appRouteRe = regexp.MustCompile(`@app\.(get|post|put|delete|patch)\(`)
var routerRouteRe = regexp.MustCompile(`@router\.(get|post|put|delete|patch)\(`)

func (d *FastAPIDetector) detectNoAPIRouter(lines []string, fname, modPath string) []domain.PatternIssue {
	appCount := 0
	routerCount := 0

	for _, line := range lines {
		if appRouteRe.MatchString(line) {
			appCount++
		}
		if routerRouteRe.MatchString(line) {
			routerCount++
		}
	}

	if appCount >= 3 && routerCount == 0 {
		return []domain.PatternIssue{{
			Category:   "fastapi",
			Dominant:   "no-api-router",
			Violation:  fmt.Sprintf("%s has %d route decorators on app — use APIRouter for better organization", fname, appCount),
			Confidence: domain.ConfidenceMedium,
			Locations:  []domain.Location{{File: fname, Line: 1}},
		}}
	}

	return nil
}
