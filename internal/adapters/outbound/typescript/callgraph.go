package typescript

import (
	"context"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/berkantay/slop0/internal/application/ports/outbound"
)

type CallGraphBuilder struct {
	parser *sitter.Parser
}

func NewCallGraphBuilder() *CallGraphBuilder {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &CallGraphBuilder{parser: parser}
}

func (b *CallGraphBuilder) Build(patterns []string) (*outbound.CallGraphResult, error) {
	dir := "."
	if len(patterns) > 0 {
		dir = strings.TrimSuffix(patterns[0], "/...")
		if dir == "" {
			dir = "."
		}
	}

	files, err := CollectTSFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("collecting typescript files for callgraph: %w", err)
	}

	result := &outbound.CallGraphResult{
		Calls:    make(map[string][]string),
		CalledBy: make(map[string][]string),
	}

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		tree, err := b.parser.ParseCtx(context.Background(), nil, src)
		if err != nil {
			continue
		}

		modPath := FileToModulePath(file, dir)
		extractTSCalls(tree.RootNode(), src, modPath, result)
	}

	return result, nil
}

func extractTSCalls(root *sitter.Node, src []byte, modPath string, result *outbound.CallGraphResult) {
	walkTSFunctions(root, src, modPath, "", result)
}

func walkTSFunctions(node *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		processTSNode(child, src, modPath, className, result)
	}
}

func processTSNode(node *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	switch node.Type() {
	case "function_declaration":
		name := nodeText(node.ChildByFieldName("name"), src)
		callerKey := modPath + "." + name
		collectTSCallsInBody(node.ChildByFieldName("body"), src, modPath, callerKey, result)

	case "class_declaration":
		clsName := nodeText(node.ChildByFieldName("name"), src)
		body := node.ChildByFieldName("body")
		if body != nil {
			walkTSMethods(body, src, modPath, clsName, result)
		}

	case "method_definition":
		name := nodeText(node.ChildByFieldName("name"), src)
		callerKey := buildTSQualifiedName(modPath, className, name)
		collectTSCallsInBody(node.ChildByFieldName("body"), src, modPath, callerKey, result)

	case "lexical_declaration":
		extractArrowCalls(node, src, modPath, result)

	case "export_statement":
		walkTSFunctions(node, src, modPath, className, result)
	}
}

func walkTSMethods(body *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		if child.Type() == "method_definition" {
			processTSNode(child, src, modPath, className, result)
		}
	}
}

func extractArrowCalls(node *sitter.Node, src []byte, modPath string, result *outbound.CallGraphResult) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() != "variable_declarator" {
			continue
		}
		name := nodeText(child.ChildByFieldName("name"), src)
		value := child.ChildByFieldName("value")
		if value != nil && isArrowOrFunction(value) {
			callerKey := modPath + "." + name
			body := value.ChildByFieldName("body")
			collectTSCallsInBody(body, src, modPath, callerKey, result)
		}
	}
}

func collectTSCallsInBody(body *sitter.Node, src []byte, modPath, callerKey string, result *outbound.CallGraphResult) {
	if body == nil {
		return
	}
	seen := make(map[string]bool)
	findTSCallsRecursive(body, src, modPath, callerKey, seen, result)
}

func findTSCallsRecursive(node *sitter.Node, src []byte, modPath, callerKey string, seen map[string]bool, result *outbound.CallGraphResult) {
	if node.Type() == "call_expression" {
		recordTSCall(node, src, modPath, callerKey, seen, result)
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		findTSCallsRecursive(node.NamedChild(i), src, modPath, callerKey, seen, result)
	}
}

func recordTSCall(node *sitter.Node, src []byte, modPath, callerKey string, seen map[string]bool, result *outbound.CallGraphResult) {
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return
	}

	calleeKey := resolveTSCallee(fn, src, modPath)
	if calleeKey == "" || calleeKey == callerKey || seen[calleeKey] {
		return
	}
	seen[calleeKey] = true

	result.Calls[callerKey] = append(result.Calls[callerKey], calleeKey)
	result.CalledBy[calleeKey] = append(result.CalledBy[calleeKey], callerKey)
}

func resolveTSCallee(fn *sitter.Node, src []byte, modPath string) string {
	switch fn.Type() {
	case "identifier":
		name := nodeText(fn, src)
		if isTSBuiltin(name) {
			return ""
		}
		return modPath + "." + name
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		objText := nodeText(obj, src)
		propText := nodeText(prop, src)
		if objText == "this" {
			return modPath + "." + propText
		}
		return objText + "." + propText
	}
	return ""
}

func buildTSQualifiedName(modPath, className, funcName string) string {
	if className != "" {
		return modPath + "." + className + "." + funcName
	}
	return modPath + "." + funcName
}

func isTSBuiltin(name string) bool {
	builtins := map[string]bool{
		"console": true, "require": true, "parseInt": true, "parseFloat": true,
		"isNaN": true, "isFinite": true, "setTimeout": true, "setInterval": true,
		"clearTimeout": true, "clearInterval": true, "Promise": true,
		"Array": true, "Object": true, "String": true, "Number": true,
		"Boolean": true, "Map": true, "Set": true, "JSON": true,
		"Error": true, "TypeError": true, "Date": true, "Math": true,
		"RegExp": true, "Symbol": true, "undefined": true,
	}
	return builtins[name]
}
