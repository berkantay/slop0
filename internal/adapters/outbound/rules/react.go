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

	issues = append(issues, detectGodComponent(root, src, fname, modPath)...)
	issues = append(issues, detectTooManyUseState(root, src, fname, modPath)...)
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

type effectInfo struct {
	setsState []string
	deps      []string
	line      int
}

func detectUseEffectChains(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	effects := collectEffectInfos(root, src)
	return findEffectChainIssues(effects, fname, modPath)
}

func collectEffectInfos(root *sitter.Node, src []byte) []effectInfo {
	var effects []effectInfo
	stateSetters := collectStateSetters(root, src)

	walkTS(root, func(node *sitter.Node) {
		if !isUseEffectCall(node, src) {
			return
		}
		body := findEffectBody(node)
		if body == nil {
			return
		}
		effects = append(effects, effectInfo{
			setsState: findSetterCallsInBody(body, src, stateSetters),
			deps:      findEffectDeps(node, src),
			line:      int(node.StartPoint().Row) + 1,
		})
	})

	return effects
}

func findEffectChainIssues(effects []effectInfo, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for i, eff := range effects {
		for j, other := range effects {
			if i == j {
				continue
			}
			issues = append(issues, matchEffectChain(eff, other, fname, modPath)...)
		}
	}
	return issues
}

func matchEffectChain(eff, other effectInfo, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
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
		if issue, ok := checkMapCallForIndexKey(node, src, fname, modPath); ok {
			issues = append(issues, issue)
		}
	})

	return issues
}

func checkMapCallForIndexKey(node *sitter.Node, src []byte, fname, modPath string) (domain.PatternIssue, bool) {
	if node.Type() != "call_expression" {
		return domain.PatternIssue{}, false
	}
	fn := node.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_expression" {
		return domain.PatternIssue{}, false
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil || tsNodeText(prop, src) != "map" {
		return domain.PatternIssue{}, false
	}
	callback := extractMapCallback(node)
	if callback == nil {
		return domain.PatternIssue{}, false
	}
	indexParam := findMapIndexParam(callback, src)
	if indexParam == "" || !hasKeyWithValue(callback, src, indexParam) {
		return domain.PatternIssue{}, false
	}
	return domain.PatternIssue{
		Category:  "react/index-as-key",
		Dominant:  "using array index as key causes bugs with reordering — use a stable unique identifier",
		Violation: fmt.Sprintf("%s: .map() uses index as key", modPath),
		Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
	}, true
}

func extractMapCallback(node *sitter.Node) *sitter.Node {
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return nil
	}
	return args.NamedChild(0)
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

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "import_statement" {
			return
		}

		source := node.ChildByFieldName("source")
		if source == nil {
			return
		}

		mod := strings.Trim(tsNodeText(source, src), `"'`)
		if isRelativeImport(mod) || hasSubpath(mod) {
			return
		}

		namedCount := countNamedImports(node)
		if namedCount > 5 {
			issues = append(issues, domain.PatternIssue{
				Category:  "perf/barrel-import",
				Dominant:  fmt.Sprintf("importing %d named exports from '%s' — use deep/subpath imports for smaller bundles", namedCount, mod),
				Violation: fmt.Sprintf("%s: %d imports from %s", modPath, namedCount, mod),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func isRelativeImport(mod string) bool {
	return strings.HasPrefix(mod, ".") || strings.HasPrefix(mod, "/")
}

func hasSubpath(mod string) bool {
	if strings.HasPrefix(mod, "@") {
		parts := strings.SplitN(mod, "/", 3)
		return len(parts) > 2
	}
	return strings.Contains(mod, "/")
}

func countNamedImports(importNode *sitter.Node) int {
	count := 0
	walkTS(importNode, func(node *sitter.Node) {
		if node.Type() == "import_specifier" {
			count++
		}
	})
	return count
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
		if s, v, ok := extractUseStatePair(node, src); ok {
			setters[s] = v
		}
	})

	return setters
}

func extractUseStatePair(node *sitter.Node, src []byte) (setter, stateVar string, ok bool) {
	if node.Type() != "call_expression" {
		return "", "", false
	}
	fn := node.ChildByFieldName("function")
	if fn == nil || tsNodeText(fn, src) != "useState" {
		return "", "", false
	}
	parent := node.Parent()
	if parent == nil || parent.Type() != "variable_declarator" {
		return "", "", false
	}
	nameNode := parent.ChildByFieldName("name")
	if nameNode == nil || nameNode.Type() != "array_pattern" || nameNode.NamedChildCount() < 2 {
		return "", "", false
	}
	return tsNodeText(nameNode.NamedChild(1), src), tsNodeText(nameNode.NamedChild(0), src), true
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

func detectGodComponent(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "function_declaration" && node.Type() != "arrow_function" {
			return
		}

		jsxCount := countJSXElements(node)
		hookCount := countHookCalls(node, src)

		if jsxCount > 50 {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/god-component",
				Dominant:  "component has too many JSX elements — split into smaller components",
				Violation: fmt.Sprintf("%s: %d JSX elements", modPath, jsxCount),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}

		if hookCount > 8 {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/god-component",
				Dominant:  "component uses too many hooks — split responsibilities",
				Violation: fmt.Sprintf("%s: %d hook calls", modPath, hookCount),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectTooManyUseState(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if !isComponentLikeNode(node) {
			return
		}
		body := node.ChildByFieldName("body")
		if body == nil {
			return
		}
		count := countUseStateCalls(body, src)
		if count >= 5 {
			issues = append(issues, domain.PatternIssue{
				Category:  "react/too-many-usestate",
				Dominant:  fmt.Sprintf("%d useState calls — consider useReducer for related state", count),
				Violation: fmt.Sprintf("%s: %d useState in one component", modPath, count),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func isComponentLikeNode(node *sitter.Node) bool {
	t := node.Type()
	return t == "function_declaration" || t == "arrow_function" || t == "variable_declarator"
}

func countUseStateCalls(body *sitter.Node, src []byte) int {
	count := 0
	walkTS(body, func(n *sitter.Node) {
		if n.Type() == "call_expression" {
			fn := n.ChildByFieldName("function")
			if fn != nil && tsNodeText(fn, src) == "useState" {
				count++
			}
		}
	})
	return count
}

func countJSXElements(node *sitter.Node) int {
	count := 0
	walkTS(node, func(n *sitter.Node) {
		if n.Type() == "jsx_element" || n.Type() == "jsx_self_closing_element" {
			count++
		}
	})
	return count
}

func countHookCalls(node *sitter.Node, src []byte) int {
	count := 0
	walkTS(node, func(n *sitter.Node) {
		if n.Type() == "call_expression" {
			fn := n.ChildByFieldName("function")
			if fn != nil && strings.HasPrefix(tsNodeText(fn, src), "use") {
				count++
			}
		}
	})
	return count
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
