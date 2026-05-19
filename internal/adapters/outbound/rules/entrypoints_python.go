package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/berkantay/slop0/internal/domain"
)

type PythonEntryPointDetector struct {
	parser *sitter.Parser
}

func NewPythonEntryPointDetector() *PythonEntryPointDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	return &PythonEntryPointDetector{parser: parser}
}

func (d *PythonEntryPointDetector) Detect(pkgs []domain.Package) []domain.EntryPoint {
	var entries []domain.EntryPoint

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" {
				continue
			}
			entries = append(entries, detectPythonEntryInFunc(fn)...)
		}
	}

	for _, pkg := range pkgs {
		entries = append(entries, detectDjangoURLPatterns(pkg, d.parser)...)
	}

	return entries
}

func detectPythonEntryInFunc(fn domain.Function) []domain.EntryPoint {
	var entries []domain.EntryPoint

	for _, decorator := range fn.Uses {
		if ep := classifyPythonDecorator(decorator, fn); ep != nil {
			entries = append(entries, *ep)
		}
	}

	return entries
}

func classifyPythonDecorator(decorator string, fn domain.Function) *domain.EntryPoint {
	if ep := classifyHTTPDecorator(decorator, fn); ep != nil {
		return ep
	}
	if ep := classifyTaskDecorator(decorator, fn); ep != nil {
		return ep
	}
	return classifyCLIDecorator(decorator, fn)
}

func classifyHTTPDecorator(decorator string, fn domain.Function) *domain.EntryPoint {
	httpMethods := []string{"get", "post", "put", "delete", "patch", "head", "options"}

	for _, method := range httpMethods {
		patterns := []string{
			"app." + method + "(",
			"router." + method + "(",
			"blueprint." + method + "(",
			"bp." + method + "(",
		}
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(decorator), pattern) {
				route := extractRouteFromDecorator(decorator)
				return &domain.EntryPoint{
					Kind:    "http",
					Route:   strings.ToUpper(method) + " " + route,
					Handler: fn.Package + "." + fn.Name,
					File:    fn.File,
					Line:    fn.Line,
				}
			}
		}
	}

	if strings.Contains(decorator, "app.route(") || strings.Contains(decorator, "blueprint.route(") || strings.Contains(decorator, "bp.route(") {
		route := extractRouteFromDecorator(decorator)
		return &domain.EntryPoint{
			Kind:    "http",
			Route:   "ALL " + route,
			Handler: fn.Package + "." + fn.Name,
			File:    fn.File,
			Line:    fn.Line,
		}
	}

	return nil
}

func classifyTaskDecorator(decorator string, fn domain.Function) *domain.EntryPoint {
	taskPatterns := []string{
		"app.task", "shared_task", "celery.task",
		"dramatiq.actor", "huey.task",
	}

	for _, pattern := range taskPatterns {
		if strings.Contains(decorator, pattern) {
			return &domain.EntryPoint{
				Kind:    "task",
				Route:   "task " + fn.Name,
				Handler: fn.Package + "." + fn.Name,
				File:    fn.File,
				Line:    fn.Line,
			}
		}
	}

	return nil
}

func classifyCLIDecorator(decorator string, fn domain.Function) *domain.EntryPoint {
	cliPatterns := []string{
		"cli.command", "app.command", "group.command",
		"click.command", "typer.command",
	}

	for _, pattern := range cliPatterns {
		if strings.Contains(decorator, pattern) {
			return &domain.EntryPoint{
				Kind:    "cli",
				Route:   "cli " + fn.Name,
				Handler: fn.Package + "." + fn.Name,
				File:    fn.File,
				Line:    fn.Line,
			}
		}
	}

	return nil
}

func extractRouteFromDecorator(decorator string) string {
	start := strings.Index(decorator, `"`)
	if start < 0 {
		start = strings.Index(decorator, `'`)
	}
	if start < 0 {
		return "?"
	}

	rest := decorator[start+1:]
	end := strings.IndexAny(rest, `"'`)
	if end < 0 {
		return "?"
	}

	return rest[:end]
}

func detectDjangoURLPatterns(pkg domain.Package, parser *sitter.Parser) []domain.EntryPoint {
	var entries []domain.EntryPoint
	entries = append(entries, detectDjangoURLsFromFunctions(pkg, parser)...)
	entries = append(entries, detectDjangoURLsFromVariables(pkg, parser)...)
	return entries
}

func detectDjangoURLsFromFunctions(pkg domain.Package, parser *sitter.Parser) []domain.EntryPoint {
	for _, fn := range pkg.Functions {
		if routes := parseDjangoURLFile(fn.File, parser); routes != nil {
			return routes
		}
	}
	return nil
}

func detectDjangoURLsFromVariables(pkg domain.Package, parser *sitter.Parser) []domain.EntryPoint {
	for _, v := range pkg.Variables {
		if v.Name != "urlpatterns" {
			continue
		}
		for _, fn := range pkg.Functions {
			if routes := parseDjangoURLFile(fn.File, parser); routes != nil {
				return routes
			}
		}
	}
	return nil
}

func parseDjangoURLFile(file string, parser *sitter.Parser) []domain.EntryPoint {
	if !strings.HasSuffix(file, "urls.py") {
		return nil
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil
	}
	return extractDjangoRoutes(tree.RootNode(), src, file)
}

func extractDjangoRoutes(root *sitter.Node, src []byte, file string) []domain.EntryPoint {
	var entries []domain.EntryPoint
	fname := filepath.Base(file)

	findCallsNamed(root, src, func(callNode *sitter.Node, funcName string) {
		if funcName != "path" && funcName != "re_path" {
			return
		}

		args := callNode.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() < 2 {
			return
		}

		routeArg := args.NamedChild(0)
		route := strings.Trim(nodeTextPy(routeArg, src), `"'`)

		viewArg := args.NamedChild(1)
		handler := nodeTextPy(viewArg, src)

		entries = append(entries, domain.EntryPoint{
			Kind:    "http",
			Route:   "ALL /" + route,
			Handler: handler,
			File:    fname,
			Line:    int(callNode.StartPoint().Row) + 1,
		})
	})

	return entries
}

func findCallsNamed(node *sitter.Node, src []byte, callback func(*sitter.Node, string)) {
	if node.Type() == "call" {
		fn := node.ChildByFieldName("function")
		if fn != nil {
			name := nodeTextPy(fn, src)
			callback(node, name)
		}
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		findCallsNamed(node.NamedChild(i), src, callback)
	}
}

func nodeTextPy(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return string(src[node.StartByte():node.EndByte()])
}
