package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/berkantay/slop0/internal/domain"
)

type NextJSDetector struct {
	parser *sitter.Parser
}

func NewNextJSDetector() *NextJSDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &NextJSDetector{parser: parser}
}

func (d *NextJSDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	if !isNextJSProject(pkgs) {
		return nil
	}

	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	routeDirs := collectRouteDirs(pkgs)
	issues = append(issues, detectMissingErrorBoundaries(routeDirs)...)
	issues = append(issues, detectMissingLoadingUI(routeDirs, pkgs)...)
	issues = append(issues, detectMissingNotFound(routeDirs)...)
	issues = append(issues, detectMissingMetadata(pkgs, d.parser)...)

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

func (d *NextJSDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	tree, err := d.parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil
	}

	root := tree.RootNode()
	fname := filepath.Base(file)
	var issues []domain.PatternIssue

	issues = append(issues, detectMissingNextImage(root, src, fname, modPath)...)
	issues = append(issues, detectMissingNextLink(root, src, fname, modPath)...)
	issues = append(issues, detectUseClientTooHigh(root, src, fname, modPath, file)...)
	issues = append(issues, detectFetchInUseEffect(root, src, fname, modPath, file)...)
	issues = append(issues, detectDynamicInRootLayout(root, src, fname, modPath, file)...)
	issues = append(issues, detectRouteHandlerFromServer(root, src, fname, modPath, file)...)

	return issues
}

func detectMissingNextImage(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	hasNextImageImport := fileContainsImport(root, src, "next/image")

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "jsx_self_closing_element" && node.Type() != "jsx_opening_element" {
			return
		}
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil || tsNodeText(nameNode, src) != "img" {
			return
		}
		if hasNextImageImport {
			return
		}
		issues = append(issues, domain.PatternIssue{
			Category:  "nextjs/no-img-element",
			Dominant:  "use next/image — automatic optimization, lazy loading, prevents layout shift",
			Violation: fmt.Sprintf("%s: <img> tag", modPath),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func detectMissingNextLink(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "jsx_self_closing_element" && node.Type() != "jsx_opening_element" {
			return
		}
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil || tsNodeText(nameNode, src) != "a" {
			return
		}
		href := findJSXAttributeValue(node, src, "href")
		if href != "" && strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
			issues = append(issues, domain.PatternIssue{
				Category:  "nextjs/no-html-link",
				Dominant:  "use next/link for internal navigation — enables client-side transitions and prefetching",
				Violation: fmt.Sprintf("%s: <a href=\"%s\">", modPath, href),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectUseClientTooHigh(root *sitter.Node, src []byte, fname, modPath, file string) []domain.PatternIssue {
	if !hasDirective(root, src, "use client") {
		return nil
	}

	hasHooks := hasHookCalls(root, src)
	hasEvents := hasEventHandlers(root, src)
	hasBrowser := hasBrowserAPIs(root, src)

	if !hasHooks && !hasEvents && !hasBrowser {
		return []domain.PatternIssue{{
			Category:  "nextjs/unnecessary-use-client",
			Dominant:  "\"use client\" without hooks, events, or browser APIs — can be a server component for smaller JS bundle",
			Violation: fmt.Sprintf("%s: unnecessary \"use client\"", modPath),
			Locations: []domain.Location{{File: fname, Line: 1}},
		}}
	}

	return nil
}

func detectFetchInUseEffect(root *sitter.Node, src []byte, fname, modPath, file string) []domain.PatternIssue {
	if !isAppRouterFile(file) {
		return nil
	}
	if hasDirective(root, src, "use client") {
		return nil
	}

	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if !isUseEffectCall(node, src) {
			return
		}
		body := findEffectBody(node)
		if body == nil {
			return
		}
		if containsFetchCall(body, src) {
			issues = append(issues, domain.PatternIssue{
				Category:  "nextjs/fetch-in-effect",
				Dominant:  "fetch in useEffect in app/ — use server component data fetching instead",
				Violation: fmt.Sprintf("%s: fetch inside useEffect", modPath),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectDynamicInRootLayout(root *sitter.Node, src []byte, fname, modPath, file string) []domain.PatternIssue {
	base := filepath.Base(file)
	if base != "layout.tsx" && base != "layout.ts" {
		return nil
	}

	dir := filepath.Dir(file)
	if filepath.Base(dir) != "app" {
		return nil
	}

	dynamicAPIs := []string{"cookies", "headers", "searchParams"}
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}
		fn := node.ChildByFieldName("function")
		if fn == nil {
			return
		}
		name := tsNodeText(fn, src)
		for _, api := range dynamicAPIs {
			if name == api {
				issues = append(issues, domain.PatternIssue{
					Category:  "nextjs/dynamic-in-root-layout",
					Dominant:  fmt.Sprintf("%s() in root layout opts entire app into dynamic rendering", api),
					Violation: fmt.Sprintf("%s: %s() in root layout", modPath, api),
					Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
				})
			}
		}
	})

	return issues
}

func detectRouteHandlerFromServer(root *sitter.Node, src []byte, fname, modPath, file string) []domain.PatternIssue {
	if hasDirective(root, src, "use client") || !isAppRouterFile(file) {
		return nil
	}

	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if issue, ok := checkFetchToAPIRoute(node, src, fname, modPath); ok {
			issues = append(issues, issue)
		}
	})

	return issues
}

func checkFetchToAPIRoute(node *sitter.Node, src []byte, fname, modPath string) (domain.PatternIssue, bool) {
	if node.Type() != "call_expression" {
		return domain.PatternIssue{}, false
	}
	fn := node.ChildByFieldName("function")
	if fn == nil || tsNodeText(fn, src) != "fetch" {
		return domain.PatternIssue{}, false
	}
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return domain.PatternIssue{}, false
	}
	url := tsNodeText(args.NamedChild(0), src)
	if !strings.Contains(url, "/api/") {
		return domain.PatternIssue{}, false
	}
	return domain.PatternIssue{
		Category:  "nextjs/server-fetch-api-route",
		Dominant:  "server component fetching own API route — call the function directly instead of HTTP roundtrip",
		Violation: fmt.Sprintf("%s: fetch to %s", modPath, strings.Trim(url, "\"'`")),
		Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
	}, true
}

func detectMissingErrorBoundaries(routeDirs map[string][]string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for dir, files := range routeDirs {
		hasPage := containsFile(files, "page.tsx") || containsFile(files, "page.ts")
		hasError := containsFile(files, "error.tsx") || containsFile(files, "error.ts")

		if hasPage && !hasError {
			issues = append(issues, domain.PatternIssue{
				Category:  "nextjs/missing-error-boundary",
				Dominant:  "route has page but no error.tsx — unhandled errors will crash the route",
				Violation: fmt.Sprintf("missing error.tsx in %s", domain.ShortPkgName(dir)),
				Locations: []domain.Location{{File: dir}},
			})
		}
	}

	return issues
}

func detectMissingLoadingUI(routeDirs map[string][]string, pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	asyncRoutes := findAsyncRoutes(pkgs)

	for dir, files := range routeDirs {
		hasPage := containsFile(files, "page.tsx") || containsFile(files, "page.ts")
		hasLoading := containsFile(files, "loading.tsx") || containsFile(files, "loading.ts")

		if hasPage && !hasLoading && asyncRoutes[dir] {
			issues = append(issues, domain.PatternIssue{
				Category:  "nextjs/missing-loading-ui",
				Dominant:  "async route without loading.tsx — users see blank screen during data fetch",
				Violation: fmt.Sprintf("missing loading.tsx in %s", domain.ShortPkgName(dir)),
				Locations: []domain.Location{{File: dir}},
			})
		}
	}

	return issues
}

func detectMissingNotFound(routeDirs map[string][]string) []domain.PatternIssue {
	for dir, files := range routeDirs {
		if filepath.Base(dir) == "app" {
			hasNotFound := containsFile(files, "not-found.tsx") || containsFile(files, "not-found.ts") ||
				containsFile(files, "global-not-found.tsx") || containsFile(files, "global-not-found.ts")
			if !hasNotFound {
				return []domain.PatternIssue{{
					Category:  "nextjs/missing-not-found",
					Dominant:  "missing not-found.tsx in app root — unmatched routes show generic error",
					Violation: "missing app/not-found.tsx",
					Locations: []domain.Location{{File: dir}},
				}}
			}
		}
	}
	return nil
}

func detectMissingMetadata(pkgs []domain.Package, parser *sitter.Parser) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		if issue, ok := checkPkgForMissingMetadata(pkg, parser); ok {
			issues = append(issues, issue)
		}
	}

	return issues
}

func checkPkgForMissingMetadata(pkg domain.Package, parser *sitter.Parser) (domain.PatternIssue, bool) {
	for _, fn := range pkg.Functions {
		if !isPageFile(fn.File) {
			continue
		}
		hasMeta, err := fileHasMetadataExport(fn.File, parser)
		if err {
			continue
		}
		if !hasMeta {
			return domain.PatternIssue{
				Category:  "nextjs/missing-metadata",
				Dominant:  "page without metadata export — hurts SEO",
				Violation: fmt.Sprintf("%s: no metadata or generateMetadata export", pkg.Path),
				Locations: []domain.Location{{File: fn.File, Line: 1}},
			}, true
		}
		break
	}
	return domain.PatternIssue{}, false
}

func isPageFile(file string) bool {
	base := filepath.Base(file)
	return base == "page.tsx" || base == "page.ts"
}

func fileHasMetadataExport(file string, parser *sitter.Parser) (bool, bool) {
	src, readErr := os.ReadFile(file)
	if readErr != nil {
		return false, true
	}
	tree, parseErr := parser.ParseCtx(context.Background(), nil, src)
	if parseErr != nil {
		return false, true
	}
	hasMetadata := false
	walkTS(tree.RootNode(), func(node *sitter.Node) {
		if node.Type() == "export_statement" {
			text := tsNodeText(node, src)
			if strings.Contains(text, "metadata") || strings.Contains(text, "generateMetadata") {
				hasMetadata = true
			}
		}
	})
	return hasMetadata, false
}

func collectRouteDirs(pkgs []domain.Package) map[string][]string {
	dirs := make(map[string][]string)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" {
				continue
			}
			dir := filepath.Dir(fn.File)
			base := filepath.Base(fn.File)
			dirs[dir] = appendUniqueS(dirs[dir], base)
		}
	}

	return dirs
}

func findAsyncRoutes(pkgs []domain.Package) map[string]bool {
	async := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			base := filepath.Base(fn.File)
			if base == "page.tsx" || base == "page.ts" {
				if strings.Contains(fn.Signature, "async") || strings.Contains(fn.Signature, "Promise") {
					async[filepath.Dir(fn.File)] = true
				}
			}
		}
	}
	return async
}

func hasDirective(root *sitter.Node, src []byte, directive string) bool {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		child := root.NamedChild(i)
		if child.Type() == "expression_statement" {
			text := strings.TrimSpace(tsNodeText(child, src))
			text = strings.TrimSuffix(text, ";")
			if text == `"`+directive+`"` || text == `'`+directive+`'` {
				return true
			}
		}
	}
	return false
}

func hasHookCalls(root *sitter.Node, src []byte) bool {
	found := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "call_expression" {
			fn := node.ChildByFieldName("function")
			if fn != nil && strings.HasPrefix(tsNodeText(fn, src), "use") {
				found = true
			}
		}
	})
	return found
}

func hasEventHandlers(root *sitter.Node, src []byte) bool {
	found := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "jsx_attribute" {
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil && strings.HasPrefix(tsNodeText(nameNode, src), "on") {
				found = true
			}
		}
	})
	return found
}

func hasBrowserAPIs(root *sitter.Node, src []byte) bool {
	browserObjects := map[string]bool{
		"window": true, "document": true, "navigator": true,
		"localStorage": true, "sessionStorage": true, "location": true,
	}
	found := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "member_expression" {
			obj := node.ChildByFieldName("object")
			if obj != nil && browserObjects[tsNodeText(obj, src)] {
				found = true
			}
		}
	})
	return found
}

func containsFetchCall(body *sitter.Node, src []byte) bool {
	found := false
	walkTS(body, func(node *sitter.Node) {
		if node.Type() == "call_expression" {
			fn := node.ChildByFieldName("function")
			if fn != nil && tsNodeText(fn, src) == "fetch" {
				found = true
			}
		}
	})
	return found
}

func fileContainsImport(root *sitter.Node, src []byte, module string) bool {
	found := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "import_statement" && strings.Contains(tsNodeText(node, src), module) {
			found = true
		}
	})
	return found
}

func isAppRouterFile(file string) bool {
	return strings.Contains(file, "/app/") || strings.Contains(file, "\\app\\")
}

func containsFile(files []string, name string) bool {
	for _, f := range files {
		if f == name {
			return true
		}
	}
	return false
}

func appendUniqueS(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func isNextJSProject(pkgs []domain.Package) bool {
	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if strings.Contains(imp, "next/") || strings.Contains(imp, "\"next\"") {
				return true
			}
		}
		if strings.Contains(pkg.Path, "app/") || strings.Contains(pkg.Path, "pages/") {
			return true
		}
	}
	return false
}

func findJSXAttributeValue(element *sitter.Node, src []byte, attrName string) string {
	for i := 0; i < int(element.NamedChildCount()); i++ {
		child := element.NamedChild(i)
		if child.Type() != "jsx_attribute" {
			continue
		}
		nameNode := child.ChildByFieldName("name")
		if nameNode == nil || tsNodeText(nameNode, src) != attrName {
			continue
		}
		for j := 0; j < int(child.NamedChildCount()); j++ {
			val := child.NamedChild(j)
			if val.Type() == "string" || val.Type() == "template_string" {
				return strings.Trim(tsNodeText(val, src), `"'`+"`")
			}
		}
	}
	return ""
}
