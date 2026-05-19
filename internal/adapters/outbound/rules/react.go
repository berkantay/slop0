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

type ReactDetector struct {
	parser *sitter.Parser
}

func NewReactDetector() *ReactDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &ReactDetector{parser: parser}
}

func (d *ReactDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			if !strings.HasSuffix(fn.File, ".tsx") && !strings.HasSuffix(fn.File, ".jsx") && !strings.HasSuffix(fn.File, ".ts") {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.analyzeFile(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func (d *ReactDetector) analyzeFile(file, modPath string) []domain.PatternIssue {
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

	issues = append(issues, detectUseEffectDerivedState(root, src, fname, modPath)...)
	issues = append(issues, detectUseEffectChains(root, src, fname, modPath)...)
	issues = append(issues, detectInlineFunctionsInJSX(root, src, fname, modPath)...)
	issues = append(issues, detectObjectLiteralsInJSX(root, src, fname, modPath)...)
	issues = append(issues, detectIndexAsKey(root, src, fname, modPath)...)
	issues = append(issues, detectMissingQueryInvalidation(root, src, fname, modPath)...)
	issues = append(issues, detectHardcodedURLs(root, src, fname, modPath)...)
	issues = append(issues, detectDirectDOMManipulation(root, src, fname, modPath)...)
	issues = append(issues, detectBarrelImports(root, src, fname, modPath)...)

	return issues
}

func detectUseEffectDerivedState(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	stateSetters := collectStateSetters(root, src)
	if len(stateSetters) == 0 {
		return nil
	}

	walkTS(root, func(node *sitter.Node) {
		if !isUseEffectCall(node, src) {
			return
		}

		body := findEffectBody(node)
		if body == nil {
			return
		}

		setterCalls := findSetterCallsInBody(body, src, stateSetters)
		if len(setterCalls) == 0 {
			return
		}

		stmtCount := countStatements(body)
		if stmtCount > len(setterCalls) {
			return
		}

		issues = append(issues, domain.PatternIssue{
			Category:  "react/derived-state-in-effect",
			Dominant:  "useEffect that only sets state from props/state — compute during render instead",
			Violation: fmt.Sprintf("%s: useEffect only calls %s", modPath, strings.Join(setterCalls, ", ")),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func detectUseEffectChains(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	type effectInfo struct {
		setsState []string
		deps      []string
		line      int
	}

	var effects []effectInfo

	walkTS(root, func(node *sitter.Node) {
		if !isUseEffectCall(node, src) {
			return
		}

		body := findEffectBody(node)
		deps := findEffectDeps(node, src)
		if body == nil {
			return
		}

		stateSetters := collectStateSetters(root, src)
		setters := findSetterCallsInBody(body, src, stateSetters)

		effects = append(effects, effectInfo{
			setsState: setters,
			deps:      deps,
			line:      int(node.StartPoint().Row) + 1,
		})
	})

	for i, eff := range effects {
		for j, other := range effects {
			if i == j {
				continue
			}
			for _, setter := range eff.setsState {
				stateVar := setterToStateVar(setter)
				for _, dep := range other.deps {
					if dep == stateVar {
						issues = append(issues, domain.PatternIssue{
							Category:  "react/effect-chain",
							Dominant:  "useEffect sets state that triggers another useEffect — combine or restructure",
							Violation: fmt.Sprintf("%s: effect at line %d sets %s → triggers effect at line %d", modPath, eff.line, stateVar, other.line),
							Locations: []domain.Location{{File: fname, Line: eff.line}},
						})
					}
				}
			}
		}
	}

	return issues
}

func detectInlineFunctionsInJSX(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "jsx_attribute" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		attrName := tsNodeText(nameNode, src)
		if !strings.HasPrefix(attrName, "on") {
			return
		}

		value := findJSXAttrValue(node)
		if value == nil {
			return
		}

		if hasInlineFunction(value) {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/inline-function-jsx",
				Dominant:  "inline function in JSX prop creates new reference every render — extract to useCallback or variable",
				Violation: fmt.Sprintf("%s: %s has inline function", modPath, attrName),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectObjectLiteralsInJSX(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "jsx_attribute" {
			return
		}

		nameNode := node.ChildByFieldName("name")
		if nameNode == nil {
			return
		}
		attrName := tsNodeText(nameNode, src)
		if attrName == "key" {
			return
		}

		value := findJSXAttrValue(node)
		if value == nil {
			return
		}

		if hasObjectOrArrayLiteral(value) {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/object-literal-jsx",
				Dominant:  "object/array literal in JSX prop creates new reference every render — extract to useMemo or constant",
				Violation: fmt.Sprintf("%s: %s has inline object/array", modPath, attrName),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectIndexAsKey(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}

		fn := node.ChildByFieldName("function")
		if fn == nil || fn.Type() != "member_expression" {
			return
		}

		prop := fn.ChildByFieldName("property")
		if prop == nil || tsNodeText(prop, src) != "map" {
			return
		}

		args := node.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() == 0 {
			return
		}

		callback := args.NamedChild(0)
		if callback == nil {
			return
		}

		indexParam := findMapIndexParam(callback, src)
		if indexParam == "" {
			return
		}

		if hasKeyWithValue(callback, src, indexParam) {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/index-as-key",
				Dominant:  "using array index as key causes bugs with reordering — use a stable unique identifier",
				Violation: fmt.Sprintf("%s: .map() uses index as key", modPath),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectMissingQueryInvalidation(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}

		fn := node.ChildByFieldName("function")
		if fn == nil || tsNodeText(fn, src) != "useMutation" {
			return
		}

		fullText := tsNodeText(node, src)
		if strings.Contains(fullText, "invalidateQueries") || strings.Contains(fullText, "invalidate") {
			return
		}

		issues = append(issues, domain.PatternIssue{
			Category:  "react/missing-query-invalidation",
			Dominant:  "useMutation without invalidateQueries — stale data after mutation",
			Violation: fmt.Sprintf("%s: useMutation missing cache invalidation", modPath),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func detectHardcodedURLs(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "string" && node.Type() != "template_string" {
			return
		}

		text := tsNodeText(node, src)
		if !strings.Contains(text, "http://") && !strings.Contains(text, "https://") {
			return
		}

		if strings.Contains(text, "localhost") || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "example.com") {
			return
		}

		issues = append(issues, domain.PatternIssue{
			Category:  "style/hardcoded-url",
			Dominant:  "hardcoded URL — use environment variable or config",
			Violation: fmt.Sprintf("%s: hardcoded URL", modPath),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func detectDirectDOMManipulation(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	domMethods := map[string]bool{
		"querySelector": true, "querySelectorAll": true,
		"getElementById": true, "getElementsByClassName": true,
		"getElementsByTagName": true, "createElement": true,
		"appendChild": true, "removeChild": true, "insertBefore": true,
	}

	domProps := map[string]bool{
		"innerHTML": true, "outerHTML": true, "innerText": true, "textContent": true,
	}

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "member_expression" {
			return
		}

		obj := node.ChildByFieldName("object")
		prop := node.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return
		}

		objText := tsNodeText(obj, src)
		propText := tsNodeText(prop, src)

		if objText == "document" && domMethods[propText] {
			issues = append(issues, makeDOMIssue(modPath, propText, fname, node))
		}

		if domProps[propText] {
			parent := node.Parent()
			if parent != nil && parent.Type() == "assignment_expression" {
				issues = append(issues, makeDOMIssue(modPath, propText, fname, node))
			}
		}
	})

	return issues
}

func detectBarrelImports(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	barrelPackages := map[string]bool{
		"lodash": true, "ramda": true, "date-fns": true,
		"@mui/material": true, "@mui/icons-material": true,
		"rxjs": true, "rxjs/operators": true,
	}

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "import_statement" {
			return
		}

		source := node.ChildByFieldName("source")
		if source == nil {
			return
		}

		mod := strings.Trim(tsNodeText(source, src), `"'`)
		if !barrelPackages[mod] {
			return
		}

		issues = append(issues, domain.PatternIssue{
			Category:  "perf/barrel-import",
			Dominant:  fmt.Sprintf("importing from '%s' barrel — use deep imports for smaller bundles", mod),
			Violation: fmt.Sprintf("%s: barrel import from %s", modPath, mod),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func makeDOMIssue(modPath, method, fname string, node *sitter.Node) domain.PatternIssue {
	return domain.PatternIssue{
		Category:  "react/direct-dom",
		Dominant:  "direct DOM manipulation — use React refs or state instead",
		Violation: fmt.Sprintf("%s: uses %s", modPath, method),
		Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
	}
}

func collectStateSetters(root *sitter.Node, src []byte) map[string]string {
	setters := make(map[string]string)

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}
		fn := node.ChildByFieldName("function")
		if fn == nil || tsNodeText(fn, src) != "useState" {
			return
		}

		parent := node.Parent()
		if parent == nil {
			return
		}

		if parent.Type() == "variable_declarator" {
			nameNode := parent.ChildByFieldName("name")
			if nameNode != nil && nameNode.Type() == "array_pattern" {
				if nameNode.NamedChildCount() >= 2 {
					stateVar := tsNodeText(nameNode.NamedChild(0), src)
					setter := tsNodeText(nameNode.NamedChild(1), src)
					setters[setter] = stateVar
				}
			}
		}
	})

	return setters
}

func findEffectBody(node *sitter.Node) *sitter.Node {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return nil
	}
	callback := args.NamedChild(0)
	if callback == nil {
		return nil
	}
	return callback.ChildByFieldName("body")
}

func findEffectDeps(node *sitter.Node, src []byte) []string {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() < 2 {
		return nil
	}

	depsArray := args.NamedChild(1)
	if depsArray == nil || depsArray.Type() != "array" {
		return nil
	}

	var deps []string
	for i := 0; i < int(depsArray.NamedChildCount()); i++ {
		dep := tsNodeText(depsArray.NamedChild(i), src)
		deps = append(deps, dep)
	}
	return deps
}

func findSetterCallsInBody(body *sitter.Node, src []byte, setters map[string]string) []string {
	var found []string
	walkTS(body, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}
		fn := node.ChildByFieldName("function")
		if fn == nil {
			return
		}
		name := tsNodeText(fn, src)
		if _, ok := setters[name]; ok {
			found = append(found, name)
		}
	})
	return found
}

func setterToStateVar(setter string) string {
	if strings.HasPrefix(setter, "set") && len(setter) > 3 {
		rest := setter[3:]
		return strings.ToLower(rest[:1]) + rest[1:]
	}
	return setter
}

func countStatements(body *sitter.Node) int {
	if body == nil {
		return 0
	}
	return int(body.NamedChildCount())
}

func isUseEffectCall(node *sitter.Node, src []byte) bool {
	if node.Type() != "call_expression" {
		return false
	}
	fn := node.ChildByFieldName("function")
	return fn != nil && tsNodeText(fn, src) == "useEffect"
}

func findJSXAttrValue(attr *sitter.Node) *sitter.Node {
	for i := 0; i < int(attr.NamedChildCount()); i++ {
		child := attr.NamedChild(i)
		if child.Type() == "jsx_expression" {
			return child
		}
	}
	return nil
}

func hasInlineFunction(node *sitter.Node) bool {
	found := false
	walkTS(node, func(n *sitter.Node) {
		if n.Type() == "arrow_function" || n.Type() == "function" {
			found = true
		}
	})
	return found
}

func hasObjectOrArrayLiteral(node *sitter.Node) bool {
	found := false
	walkTS(node, func(n *sitter.Node) {
		if n.Type() == "object" || n.Type() == "array" {
			found = true
		}
	})
	return found
}

func findMapIndexParam(callback *sitter.Node, src []byte) string {
	params := callback.ChildByFieldName("parameters")
	if params == nil {
		params = callback.ChildByFieldName("parameter")
	}
	if params == nil {
		return ""
	}
	if params.NamedChildCount() >= 2 {
		return tsNodeText(params.NamedChild(1), src)
	}
	return ""
}

func hasKeyWithValue(callback *sitter.Node, src []byte, indexParam string) bool {
	found := false
	walkTS(callback, func(node *sitter.Node) {
		if node.Type() != "jsx_attribute" {
			return
		}
		nameNode := node.ChildByFieldName("name")
		if nameNode == nil || tsNodeText(nameNode, src) != "key" {
			return
		}
		value := findJSXAttrValue(node)
		if value != nil && strings.Contains(tsNodeText(value, src), indexParam) {
			found = true
		}
	})
	return found
}

func tsNodeText(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return string(src[node.StartByte():node.EndByte()])
}

func walkTS(node *sitter.Node, fn func(*sitter.Node)) {
	fn(node)
	for i := 0; i < int(node.NamedChildCount()); i++ {
		walkTS(node.NamedChild(i), fn)
	}
}
