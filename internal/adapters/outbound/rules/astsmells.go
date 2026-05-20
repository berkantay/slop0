package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/berkantay/slop0/internal/domain"
)

type ASTSmellDetector struct {
	parser *sitter.Parser
}

func NewASTSmellDetector() *ASTSmellDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &ASTSmellDetector{parser: parser}
}

func (d *ASTSmellDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	issues = append(issues, d.detectFileSmells(pkgs)...)
	issues = append(issues, detectDeadExports(pkgs)...)
	issues = append(issues, detectDuplicatedTypes(pkgs)...)
	return issues
}

func (d *ASTSmellDetector) detectFileSmells(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.analyzeOneFile(fn.File, pkg.Path)...)
		}
	}
	return issues
}

func (d *ASTSmellDetector) analyzeOneFile(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	var issues []domain.PatternIssue
	ext := filepath.Ext(file)

	if ext == ".tsx" || ext == ".ts" {
		tree, parseErr := d.parser.ParseCtx(context.Background(), nil, src)
		if parseErr != nil {
			return nil
		}
		root := tree.RootNode()
		fname := filepath.Base(file)
		issues = append(issues, detectPropDrilling(root, src, fname, modPath)...)
		issues = append(issues, detectMissingRouteErrorHandling(root, src, fname, modPath, file)...)
	}

	issues = append(issues, detectNPlusOneRegex(src, filepath.Base(file), modPath)...)
	return issues
}

func detectPropDrilling(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	walkTS(root, func(node *sitter.Node) {
		if !isFunctionWithJSX(node, src) {
			return
		}
		params := extractDestructuredParams(node, src)
		if len(params) == 0 {
			return
		}
		body := node.ChildByFieldName("body")
		if body == nil {
			return
		}
		drilled := findDrilledParams(body, src, params)
		for _, p := range drilled {
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/prop-drilling",
				Dominant:  "prop passed directly to child without being used — consider context or composition",
				Violation: fmt.Sprintf("%s: prop '%s' is drilled through", modPath, p),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})
	return issues
}

func isFunctionWithJSX(node *sitter.Node, src []byte) bool {
	t := node.Type()
	if t != "function_declaration" && t != "arrow_function" && t != "variable_declarator" {
		return false
	}
	return subtreeHasJSX(node)
}

func subtreeHasJSX(node *sitter.Node) bool {
	if node.Type() == "jsx_element" || node.Type() == "jsx_self_closing_element" {
		return true
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if subtreeHasJSX(node.NamedChild(i)) {
			return true
		}
	}
	return false
}

func extractDestructuredParams(fnNode *sitter.Node, src []byte) []string {
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	walkTS(params, func(n *sitter.Node) {
		if n.Type() == "shorthand_property_identifier_pattern" || n.Type() == "shorthand_property_identifier" {
			names = append(names, tsNodeText(n, src))
		}
	})
	return names
}

func findDrilledParams(body *sitter.Node, src []byte, params []string) []string {
	jsxAttrUses := make(map[string]bool)
	otherUses := make(map[string]bool)
	collectParamUsage(body, src, params, jsxAttrUses, otherUses)

	var drilled []string
	for _, p := range params {
		if jsxAttrUses[p] && !otherUses[p] {
			drilled = append(drilled, p)
		}
	}
	return drilled
}

func collectParamUsage(node *sitter.Node, src []byte, params []string, jsxUses, otherUses map[string]bool) {
	paramSet := make(map[string]bool, len(params))
	for _, p := range params {
		paramSet[p] = true
	}
	walkParamUsage(node, src, paramSet, jsxUses, otherUses, false)
}

func walkParamUsage(node *sitter.Node, src []byte, paramSet, jsxUses, otherUses map[string]bool, inJSXAttr bool) {
	if node.Type() == "identifier" {
		name := tsNodeText(node, src)
		if paramSet[name] {
			if inJSXAttr {
				jsxUses[name] = true
			} else {
				otherUses[name] = true
			}
		}
	}

	nextInAttr := inJSXAttr
	if node.Type() == "jsx_attribute" {
		nextInAttr = true
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		walkParamUsage(node.NamedChild(i), src, paramSet, jsxUses, otherUses, nextInAttr)
	}
}

var routeHandlerNames = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
}

func detectMissingRouteErrorHandling(root *sitter.Node, src []byte, fname, modPath, file string) []domain.PatternIssue {
	if !isAPIRouteFile(file) {
		return nil
	}
	var issues []domain.PatternIssue
	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "export_statement" {
			return
		}
		walkTS(node, func(fn *sitter.Node) {
			if fn.Type() != "function_declaration" {
				return
			}
			nameNode := fn.ChildByFieldName("name")
			if nameNode == nil {
				return
			}
			name := tsNodeText(nameNode, src)
			if !routeHandlerNames[name] {
				return
			}
			body := fn.ChildByFieldName("body")
			if body == nil {
				return
			}
			if !bodyHasTryStatement(body) {
				issues = append(issues, domain.PatternIssue{
					Category:  "smell/route-no-try-catch",
					Dominant:  "API route handler without try-catch — unhandled errors return 500 with no useful response",
					Violation: fmt.Sprintf("%s: %s handler has no error handling", modPath, name),
					Locations: []domain.Location{{File: fname, Line: int(fn.StartPoint().Row) + 1}},
				})
			}
		})
	})
	return issues
}

func isAPIRouteFile(file string) bool {
	base := filepath.Base(file)
	if base != "route.ts" && base != "route.tsx" {
		return false
	}
	return strings.Contains(file, "/api/") || strings.Contains(file, "\\api\\")
}

func bodyHasTryStatement(body *sitter.Node) bool {
	found := false
	walkTS(body, func(n *sitter.Node) {
		if n.Type() == "try_statement" {
			found = true
		}
	})
	return found
}

var (
	loopStartRe = regexp.MustCompile(`(?m)^\s*(?:for\s*[\(\{]|while\s*[\(\{]|\.forEach\s*\(|\.map\s*\()`)
	asyncCallRe = regexp.MustCompile(`(?:await\s+|\.query\s*\(|\.find\s*\(|\.get\s*\(|fetch\s*\()`)
)

func detectNPlusOneRegex(src []byte, fname, modPath string) []domain.PatternIssue {
	lines := strings.Split(string(src), "\n")
	var issues []domain.PatternIssue

	for i, line := range lines {
		if !loopStartRe.MatchString(line) {
			continue
		}
		end := findLoopEnd(lines, i)
		if found, matchLine := scanBlockForAsyncCall(lines, i+1, end); found {
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/n-plus-one",
				Dominant:  "async/database call inside loop — batch the operation to avoid N+1",
				Violation: fmt.Sprintf("%s: loop at line %d, async call at line %d", modPath, i+1, matchLine+1),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}
	return issues
}

func findLoopEnd(lines []string, start int) int {
	depth := 0
	for i := start; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if depth <= 0 && i > start {
			return i
		}
	}
	limit := start + 30
	if limit > len(lines)-1 {
		limit = len(lines) - 1
	}
	return limit
}

func scanBlockForAsyncCall(lines []string, from, to int) (bool, int) {
	for i := from; i <= to && i < len(lines); i++ {
		if asyncCallRe.MatchString(lines[i]) {
			return true, i
		}
	}
	return false, 0
}

func detectDeadExports(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	issues = append(issues, detectDeadFuncExports(pkgs)...)
	issues = append(issues, detectDeadTypeExports(pkgs)...)
	return issues
}

func detectDeadFuncExports(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if len(fn.CalledBy) > 0 {
				continue
			}
			if !isExportedName(fn.Name, fn.File) {
				continue
			}
			if isEntryOrTestFunc(fn.Name) {
				continue
			}
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/dead-export",
				Dominant:  "exported function never called from other packages — consider removing or unexporting",
				Violation: fmt.Sprintf("%s.%s", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}
	return issues
}

func detectDeadTypeExports(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if len(t.UsedBy) > 0 {
				continue
			}
			if !isExportedTypeName(t.Name) {
				continue
			}
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/dead-export",
				Dominant:  "exported type never used by other packages — consider removing or unexporting",
				Violation: fmt.Sprintf("%s.%s", domain.ShortPkgName(pkg.Path), t.Name),
			})
		}
	}
	return issues
}

func isExportedName(name, file string) bool {
	if file == "" {
		return len(name) > 0 && unicode.IsUpper(rune(name[0]))
	}
	ext := filepath.Ext(file)
	if ext == ".ts" || ext == ".tsx" || ext == ".py" {
		return true
	}
	return len(name) > 0 && unicode.IsUpper(rune(name[0]))
}

func isExportedTypeName(name string) bool {
	return len(name) > 0 && unicode.IsUpper(rune(name[0]))
}

func isEntryOrTestFunc(name string) bool {
	if name == "main" || name == "init" || name == "Main" {
		return true
	}
	if strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Benchmark") {
		return true
	}
	lower := strings.ToLower(name)
	return strings.Contains(lower, "handler") || strings.Contains(lower, "serve")
}

func detectDuplicatedTypes(pkgs []domain.Package) []domain.PatternIssue {
	type typeRef struct {
		pkg    string
		name   string
		fields []string
	}

	var types []typeRef
	for _, pkg := range pkgs {
		for _, t := range pkg.Types {
			if len(t.Fields) < 3 {
				continue
			}
			fields := make([]string, len(t.Fields))
			for i, f := range t.Fields {
				fields[i] = f.Name
			}
			sort.Strings(fields)
			types = append(types, typeRef{pkg: pkg.Path, name: t.Name, fields: fields})
		}
	}

	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for i := 0; i < len(types); i++ {
		for j := i + 1; j < len(types); j++ {
			if types[i].pkg == types[j].pkg {
				continue
			}
			overlap := countFieldOverlap(types[i].fields, types[j].fields)
			if overlap < 3 {
				continue
			}
			key := types[i].name + "|" + types[j].name
			if seen[key] {
				continue
			}
			seen[key] = true
			issues = append(issues, domain.PatternIssue{
				Category:  "smell/duplicated-types",
				Dominant:  fmt.Sprintf("%d shared fields — consider extracting a common type", overlap),
				Violation: fmt.Sprintf("%s.%s and %s.%s", domain.ShortPkgName(types[i].pkg), types[i].name, domain.ShortPkgName(types[j].pkg), types[j].name),
			})
		}
	}
	return issues
}

func countFieldOverlap(a, b []string) int {
	set := make(map[string]bool, len(a))
	for _, f := range a {
		set[f] = true
	}
	count := 0
	for _, f := range b {
		if set[f] {
			count++
		}
	}
	return count
}
