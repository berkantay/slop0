package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type NestJSDetector struct{}

func (d *NestJSDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	if !d.isNestJS(pkgs) {
		return nil
	}

	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			if !strings.HasSuffix(fn.File, ".ts") {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.analyzeFile(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func (d *NestJSDetector) isNestJS(pkgs []domain.Package) bool {
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if strings.Contains(imp, "@nestjs") {
				return true
			}
		}
	}
	return false
}

func (d *NestJSDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	fname := filepath.Base(file)
	lines := strings.Split(string(src), "\n")
	var issues []domain.PatternIssue

	issues = append(issues, d.detectNoDTOForBody(lines, fname, modPath)...)
	issues = append(issues, d.detectLogicInController(lines, fname, modPath, file)...)
	issues = append(issues, d.detectMissingInjectable(lines, fname, modPath, file)...)
	issues = append(issues, d.detectProcessEnv(lines, fname, modPath, file)...)
	issues = append(issues, d.detectAnyInDTO(lines, fname, modPath, file)...)
	issues = append(issues, d.detectMissingApiTags(lines, fname, modPath)...)

	return issues
}

// detectNoDTOForBody flags @Body() with type `any` or no type annotation.
var bodyAnyRe = regexp.MustCompile(`@Body\(\)\s+\w+\s*:\s*any\b`)
var bodyNoTypeRe = regexp.MustCompile(`@Body\(\)\s+(\w+)\s*[,)]`)

func (d *NestJSDetector) detectNoDTOForBody(lines []string, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for i, line := range lines {
		if bodyAnyRe.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:   "nestjs",
				Dominant:   "no-dto-for-body",
				Violation:  fmt.Sprintf("@Body() typed as any at %s:%d — use a DTO class with class-validator decorators", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		} else if bodyNoTypeRe.MatchString(line) && !strings.Contains(line, ":") {
			issues = append(issues, domain.PatternIssue{
				Category:   "nestjs",
				Dominant:   "no-dto-for-body",
				Violation:  fmt.Sprintf("@Body() without type annotation at %s:%d — use a DTO class for validation", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectLogicInController flags controller methods with >20 lines.
var tsMethodRe = regexp.MustCompile(`^\s+(async\s+)?\w+\(`)
var tsClassEndRe = regexp.MustCompile(`^}`)

var controllerMethodNameRe = regexp.MustCompile(`^\s+(?:async\s+)?(\w+)\(`)

type methodTracker struct {
	start      int
	name       string
	braceDepth int
	active     bool
}

func (d *NestJSDetector) detectLogicInController(lines []string, fname, modPath string, file string) []domain.PatternIssue {
	if !strings.HasSuffix(file, ".controller.ts") {
		return nil
	}
	return scanControllerMethods(lines, fname)
}

func scanControllerMethods(lines []string, fname string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	var mt methodTracker

	for i, line := range lines {
		if !mt.active {
			mt = tryStartTracking(lines, i)
			continue
		}
		mt.braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
		if mt.braceDepth > 0 {
			continue
		}
		if issue, ok := checkMethodLength(mt.name, fname, mt.start, i); ok {
			issues = append(issues, issue)
		}
		mt.active = false
	}

	return issues
}

func tryStartTracking(lines []string, i int) methodTracker {
	name, ok := tryStartMethod(lines, i)
	if !ok {
		return methodTracker{}
	}
	return methodTracker{
		start:      i,
		name:       name,
		braceDepth: strings.Count(lines[i], "{") - strings.Count(lines[i], "}"),
		active:     true,
	}
}

func tryStartMethod(lines []string, i int) (string, bool) {
	m := controllerMethodNameRe.FindStringSubmatch(lines[i])
	if m == nil {
		return "", false
	}
	if strings.Contains(lines[i], "{") || (i+1 < len(lines) && strings.Contains(lines[i+1], "{")) {
		return m[1], true
	}
	return "", false
}

func checkMethodLength(methodName, fname string, start, end int) (domain.PatternIssue, bool) {
	methodLen := end - start + 1
	if methodLen <= 20 {
		return domain.PatternIssue{}, false
	}
	return domain.PatternIssue{
		Category:   "nestjs",
		Dominant:   "logic-in-controller",
		Violation:  fmt.Sprintf("Controller method %s at %s:%d is %d lines — extract business logic to a service", methodName, fname, start+1, methodLen),
		Confidence: domain.ConfidenceMedium,
		Locations:  []domain.Location{{File: fname, Line: start + 1}},
	}, true
}

// detectMissingInjectable flags service files with export class but no @Injectable().
var exportClassRe = regexp.MustCompile(`export\s+class\s+`)
var injectableRe = regexp.MustCompile(`@Injectable\(`)

func (d *NestJSDetector) detectMissingInjectable(lines []string, fname, modPath string, file string) []domain.PatternIssue {
	if !strings.HasSuffix(file, ".service.ts") {
		return nil
	}

	content := strings.Join(lines, "\n")
	if !exportClassRe.MatchString(content) {
		return nil
	}
	if injectableRe.MatchString(content) {
		return nil
	}

	// Find the line of the export class
	for i, line := range lines {
		if exportClassRe.MatchString(line) {
			return []domain.PatternIssue{{
				Category:   "nestjs",
				Dominant:   "missing-injectable",
				Violation:  fmt.Sprintf("Service class at %s:%d missing @Injectable() decorator — required for NestJS DI", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			}}
		}
	}

	return nil
}

// detectProcessEnv flags process.env usage in service/controller files.
var processEnvRe = regexp.MustCompile(`process\.env\.`)

func (d *NestJSDetector) detectProcessEnv(lines []string, fname, modPath string, file string) []domain.PatternIssue {
	if !strings.HasSuffix(file, ".service.ts") && !strings.HasSuffix(file, ".controller.ts") {
		return nil
	}

	var issues []domain.PatternIssue

	for i, line := range lines {
		if processEnvRe.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:   "nestjs",
				Dominant:   "process-env-usage",
				Violation:  fmt.Sprintf("process.env at %s:%d — use ConfigService for testable, type-safe configuration", fname, i+1),
				Confidence: domain.ConfidenceMedium,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectAnyInDTO flags `any` type in DTO files.
var anyTypeRe = regexp.MustCompile(`:\s*any\b`)

func (d *NestJSDetector) detectAnyInDTO(lines []string, fname, modPath string, file string) []domain.PatternIssue {
	if !strings.HasSuffix(file, ".dto.ts") {
		return nil
	}

	var issues []domain.PatternIssue

	for i, line := range lines {
		if anyTypeRe.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:   "nestjs",
				Dominant:   "any-in-dto",
				Violation:  fmt.Sprintf("Property typed as any in DTO at %s:%d — use specific types for validation", fname, i+1),
				Confidence: domain.ConfidenceHigh,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}

	return issues
}

// detectMissingApiTags flags @Controller() without @ApiTags() in the same file.
var controllerDecoratorRe = regexp.MustCompile(`@Controller\(`)
var apiTagsRe = regexp.MustCompile(`@ApiTags\(`)

func (d *NestJSDetector) detectMissingApiTags(lines []string, fname, modPath string) []domain.PatternIssue {
	content := strings.Join(lines, "\n")
	if !controllerDecoratorRe.MatchString(content) {
		return nil
	}
	if apiTagsRe.MatchString(content) {
		return nil
	}

	for i, line := range lines {
		if controllerDecoratorRe.MatchString(line) {
			return []domain.PatternIssue{{
				Category:   "nestjs",
				Dominant:   "missing-api-tags",
				Violation:  fmt.Sprintf("@Controller at %s:%d without @ApiTags — add for Swagger documentation grouping", fname, i+1),
				Confidence: domain.ConfidenceLow,
				Locations:  []domain.Location{{File: fname, Line: i + 1}},
			}}
		}
	}

	return nil
}
