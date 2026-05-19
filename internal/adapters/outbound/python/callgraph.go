package python

import (
	"context"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/berkantay/slop0/internal/application/ports/outbound"
)

type CallGraphBuilder struct {
	parser *sitter.Parser
}

func NewCallGraphBuilder() *CallGraphBuilder {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
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

	files, err := CollectPythonFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("collecting python files for callgraph: %w", err)
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
		extractCalls(tree.RootNode(), src, modPath, result)
	}

	return result, nil
}

func extractCalls(root *sitter.Node, src []byte, modPath string, result *outbound.CallGraphResult) {
	walkFunctions(root, src, modPath, "", result)
}

func walkFunctions(node *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		processNode(child, src, modPath, className, result)
	}
}

func processNode(node *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	switch node.Type() {
	case "function_definition":
		processFuncDef(node, src, modPath, className, result)
	case "class_definition":
		processClassDef(node, src, modPath, result)
	case "decorated_definition":
		def := findDefinition(node)
		if def != nil {
			processNode(def, src, modPath, className, result)
		}
	}
}

func processFuncDef(node *sitter.Node, src []byte, modPath, className string, result *outbound.CallGraphResult) {
	funcName := nodeText(node.ChildByFieldName("name"), src)
	callerKey := buildQualifiedName(modPath, className, funcName)

	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}

	seen := make(map[string]bool)
	collectCallsInBody(body, src, modPath, callerKey, seen, result)
}

func processClassDef(node *sitter.Node, src []byte, modPath string, result *outbound.CallGraphResult) {
	clsName := nodeText(node.ChildByFieldName("name"), src)
	body := node.ChildByFieldName("body")
	if body != nil {
		walkFunctions(body, src, modPath, clsName, result)
	}
}

func collectCallsInBody(node *sitter.Node, src []byte, modPath, callerKey string, seen map[string]bool, result *outbound.CallGraphResult) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		findCallsRecursive(child, src, modPath, callerKey, seen, result)
	}
}

func findCallsRecursive(node *sitter.Node, src []byte, modPath, callerKey string, seen map[string]bool, result *outbound.CallGraphResult) {
	if node.Type() == "call" {
		recordCall(node, src, modPath, callerKey, seen, result)
	}

	for i := 0; i < int(node.NamedChildCount()); i++ {
		findCallsRecursive(node.NamedChild(i), src, modPath, callerKey, seen, result)
	}
}

func recordCall(node *sitter.Node, src []byte, modPath, callerKey string, seen map[string]bool, result *outbound.CallGraphResult) {
	fn := node.ChildByFieldName("function")
	if fn == nil {
		return
	}

	calleeKey := resolveCallee(fn, src, modPath)
	if calleeKey == "" || calleeKey == callerKey || seen[calleeKey] {
		return
	}
	seen[calleeKey] = true

	result.Calls[callerKey] = append(result.Calls[callerKey], calleeKey)
	result.CalledBy[calleeKey] = append(result.CalledBy[calleeKey], callerKey)
}

func resolveCallee(fn *sitter.Node, src []byte, modPath string) string {
	switch fn.Type() {
	case "identifier":
		name := nodeText(fn, src)
		if isBuiltin(name) {
			return ""
		}
		return modPath + "." + name
	case "attribute":
		return resolveAttributeCallee(fn, src, modPath)
	}
	return ""
}

func resolveAttributeCallee(fn *sitter.Node, src []byte, modPath string) string {
	obj := fn.ChildByFieldName("object")
	attr := fn.ChildByFieldName("attribute")
	if obj == nil || attr == nil {
		return ""
	}

	objText := nodeText(obj, src)
	attrText := nodeText(attr, src)

	if objText == "self" {
		return modPath + "." + attrText
	}

	return objText + "." + attrText
}

func buildQualifiedName(modPath, className, funcName string) string {
	if className != "" {
		return modPath + "." + className + "." + funcName
	}
	return modPath + "." + funcName
}

func isBuiltin(name string) bool {
	builtins := map[string]bool{
		"print": true, "len": true, "range": true, "str": true, "int": true,
		"float": true, "bool": true, "list": true, "dict": true, "set": true,
		"tuple": true, "type": true, "isinstance": true, "issubclass": true,
		"super": true, "enumerate": true, "zip": true, "map": true, "filter": true,
		"sorted": true, "reversed": true, "any": true, "all": true, "min": true,
		"max": true, "sum": true, "abs": true, "round": true, "hasattr": true,
		"getattr": true, "setattr": true, "delattr": true, "property": true,
		"staticmethod": true, "classmethod": true, "open": true, "repr": true,
	}
	return builtins[name]
}
