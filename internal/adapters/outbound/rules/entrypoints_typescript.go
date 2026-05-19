package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type TypeScriptEntryPointDetector struct{}

func (d *TypeScriptEntryPointDetector) Detect(pkgs []domain.Package) []domain.EntryPoint {
	var entries []domain.EntryPoint

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			entries = append(entries, detectTSEntryInFunc(fn)...)
		}
	}

	return entries
}

func detectTSEntryInFunc(fn domain.Function) []domain.EntryPoint {
	var entries []domain.EntryPoint

	for _, decorator := range fn.Uses {
		if ep := classifyTSDecorator(decorator, fn); ep != nil {
			entries = append(entries, *ep)
		}
	}

	for _, call := range fn.Calls {
		if ep := classifyTSRouteCall(call, fn); ep != nil {
			entries = append(entries, *ep)
		}
	}

	return entries
}

func classifyTSDecorator(decorator string, fn domain.Function) *domain.EntryPoint {
	httpMethods := []string{"Get", "Post", "Put", "Delete", "Patch", "Head", "Options"}

	for _, method := range httpMethods {
		if strings.Contains(decorator, method+"(") {
			route := extractTSRouteFromDecorator(decorator)
			return &domain.EntryPoint{
				Kind:    "http",
				Route:   strings.ToUpper(method) + " " + route,
				Handler: fn.Package + "." + fn.Name,
				File:    fn.File,
				Line:    fn.Line,
			}
		}
	}

	if strings.Contains(decorator, "Controller(") {
		route := extractTSRouteFromDecorator(decorator)
		return &domain.EntryPoint{
			Kind:    "http",
			Route:   "GROUP " + route,
			Handler: fn.Package + "." + fn.Name,
			File:    fn.File,
			Line:    fn.Line,
		}
	}

	return nil
}

func classifyTSRouteCall(call string, fn domain.Function) *domain.EntryPoint {
	methods := map[string]string{
		".get(":     "GET",
		".post(":    "POST",
		".put(":     "PUT",
		".delete(":  "DELETE",
		".patch(":   "PATCH",
		".use(":     "MIDDLEWARE",
		".route(":   "ALL",
		".all(":     "ALL",
	}

	lower := strings.ToLower(call)
	for pattern, method := range methods {
		if strings.Contains(lower, pattern) {
			return &domain.EntryPoint{
				Kind:    "http",
				Route:   method + " " + fn.Name,
				Handler: fn.Package + "." + fn.Name,
				File:    fn.File,
				Line:    fn.Line,
			}
		}
	}

	return nil
}

func extractTSRouteFromDecorator(decorator string) string {
	start := strings.Index(decorator, `"`)
	if start < 0 {
		start = strings.Index(decorator, `'`)
	}
	if start < 0 {
		start = strings.Index(decorator, "`")
	}
	if start < 0 {
		return "/"
	}

	rest := decorator[start+1:]
	end := strings.IndexAny(rest, `"'\`+"`")
	if end < 0 {
		return "/"
	}

	return rest[:end]
}
