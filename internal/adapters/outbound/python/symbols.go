package python

import (
	"context"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/berkantay/slop0/internal/domain"
)

type SymbolExtractor struct {
	parser *sitter.Parser
}

func NewSymbolExtractor() *SymbolExtractor {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	return &SymbolExtractor{parser: parser}
}

func (e *SymbolExtractor) Extract(patterns []string) ([]domain.Package, error) {
	dir := "."
	if len(patterns) > 0 {
		dir = strings.TrimSuffix(patterns[0], "/...")
		if dir == "" {
			dir = "."
		}
	}

	files, err := CollectPythonFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("collecting python files: %w", err)
	}

	pkgMap := make(map[string]*domain.Package)

	for _, file := range files {
		modPath := FileToModulePath(file, dir)
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		tree, err := e.parser.ParseCtx(context.Background(), nil, src)
		if err != nil {
			continue
		}

		root := tree.RootNode()
		pkg := getOrCreatePkg(pkgMap, modPath)
		extractModule(root, src, file, modPath, pkg)
	}

	result := make([]domain.Package, 0, len(pkgMap))
	for _, pkg := range pkgMap {
		result = append(result, *pkg)
	}
	return result, nil
}

func getOrCreatePkg(pkgMap map[string]*domain.Package, modPath string) *domain.Package {
	if pkg, ok := pkgMap[modPath]; ok {
		return pkg
	}
	pkg := &domain.Package{Path: modPath}
	pkgMap[modPath] = pkg
	return pkg
}

func extractModule(root *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		child := root.NamedChild(i)
		extractTopLevel(child, src, file, modPath, pkg)
	}
}

func extractTopLevel(node *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	switch node.Type() {
	case "function_definition":
		pkg.Functions = append(pkg.Functions, extractFunction(node, src, file, modPath))
	case "class_definition":
		pkg.Types = append(pkg.Types, extractClass(node, src, file, modPath))
	case "decorated_definition":
		extractDecorated(node, src, file, modPath, pkg)
	case "import_statement":
		pkg.Imports = append(pkg.Imports, extractImport(node, src))
	case "import_from_statement":
		pkg.Imports = append(pkg.Imports, extractFromImport(node, src))
	case "expression_statement":
		if v := extractAssignment(node, src, file); v != nil {
			pkg.Variables = append(pkg.Variables, *v)
		}
	}
}

func extractFunction(node *sitter.Node, src []byte, file, modPath string) domain.Function {
	name := nodeText(node.ChildByFieldName("name"), src)
	params := nodeText(node.ChildByFieldName("parameters"), src)
	retType := ""
	if rt := node.ChildByFieldName("return_type"); rt != nil {
		retType = " → " + nodeText(rt, src)
	}

	return domain.Function{
		Name:      name,
		Signature: name + params + retType,
		Package:   modPath,
		File:      file,
		Line:      int(node.StartPoint().Row) + 1,
	}
}

func extractClass(node *sitter.Node, src []byte, file, modPath string) domain.Type {
	name := nodeText(node.ChildByFieldName("name"), src)

	t := domain.Type{
		Name: name,
		Kind: "class",
	}

	if supers := node.ChildByFieldName("superclasses"); supers != nil {
		t.Implements = extractSuperclasses(supers, src)
	}

	body := node.ChildByFieldName("body")
	if body != nil {
		extractClassBody(body, src, file, modPath, &t)
	}

	return t
}

func extractSuperclasses(node *sitter.Node, src []byte) []string {
	var supers []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		text := nodeText(child, src)
		if text != "" && text != "object" {
			supers = append(supers, text)
		}
	}
	return supers
}

func extractClassBody(body *sitter.Node, src []byte, file, modPath string, t *domain.Type) {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		switch child.Type() {
		case "function_definition":
			methodName := nodeText(child.ChildByFieldName("name"), src)
			t.Methods = append(t.Methods, methodName)
			if methodName == "__init__" {
				t.Fields = append(t.Fields, extractInitFields(child, src)...)
			}
		case "decorated_definition":
			def := findDefinition(child)
			if def != nil && def.Type() == "function_definition" {
				methodName := nodeText(def.ChildByFieldName("name"), src)
				t.Methods = append(t.Methods, methodName)
			}
		}
	}
}

func extractInitFields(initNode *sitter.Node, src []byte) []domain.Field {
	var fields []domain.Field
	body := initNode.ChildByFieldName("body")
	if body == nil {
		return fields
	}

	walkForSelfAssignments(body, src, &fields)
	return fields
}

func walkForSelfAssignments(node *sitter.Node, src []byte, fields *[]domain.Field) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "expression_statement" {
			assign := child.NamedChild(0)
			if assign != nil && assign.Type() == "assignment" {
				left := assign.ChildByFieldName("left")
				if left != nil && left.Type() == "attribute" {
					obj := left.ChildByFieldName("object")
					attr := left.ChildByFieldName("attribute")
					if obj != nil && nodeText(obj, src) == "self" && attr != nil {
						fieldName := nodeText(attr, src)
						typeHint := inferFieldType(assign, src)
						*fields = append(*fields, domain.Field{
							Name: fieldName,
							Type: typeHint,
						})
					}
				}
			}
		}
	}
}

func inferFieldType(assign *sitter.Node, src []byte) string {
	right := assign.ChildByFieldName("right")
	if right == nil {
		return ""
	}
	switch right.Type() {
	case "string", "concatenated_string":
		return "str"
	case "integer":
		return "int"
	case "float":
		return "float"
	case "true", "false":
		return "bool"
	case "list":
		return "list"
	case "dictionary":
		return "dict"
	case "none":
		return "None"
	case "call":
		fn := right.ChildByFieldName("function")
		if fn != nil {
			return nodeText(fn, src)
		}
	}
	return ""
}

func extractDecorated(node *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	def := findDefinition(node)
	if def == nil {
		return
	}

	decorators := extractDecorators(node, src)

	switch def.Type() {
	case "function_definition":
		fn := extractFunction(def, src, file, modPath)
		if len(decorators) > 0 {
			fn.Uses = decorators
		}
		pkg.Functions = append(pkg.Functions, fn)
	case "class_definition":
		t := extractClass(def, src, file, modPath)
		if len(decorators) > 0 {
			t.UsedBy = decorators
		}
		pkg.Types = append(pkg.Types, t)
	}
}

func extractDecorators(node *sitter.Node, src []byte) []string {
	var decorators []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "decorator" {
			text := nodeText(child, src)
			text = strings.TrimPrefix(text, "@")
			decorators = append(decorators, text)
		}
	}
	return decorators
}

func findDefinition(decorated *sitter.Node) *sitter.Node {
	for i := 0; i < int(decorated.NamedChildCount()); i++ {
		child := decorated.NamedChild(i)
		if child.Type() == "function_definition" || child.Type() == "class_definition" {
			return child
		}
	}
	return nil
}

func extractImport(node *sitter.Node, src []byte) string {
	return strings.TrimPrefix(nodeText(node, src), "import ")
}

func extractFromImport(node *sitter.Node, src []byte) string {
	return nodeText(node, src)
}

func extractAssignment(node *sitter.Node, src []byte, file string) *domain.Variable {
	if node.NamedChildCount() == 0 {
		return nil
	}
	assign := node.NamedChild(0)
	if assign == nil || assign.Type() != "assignment" {
		return nil
	}

	left := assign.ChildByFieldName("left")
	if left == nil || left.Type() != "identifier" {
		return nil
	}

	name := nodeText(left, src)
	if strings.HasPrefix(name, "_") && name != "__all__" {
		return nil
	}

	typeName := inferFieldType(assign, src)
	return &domain.Variable{
		Name:     name,
		TypeName: typeName,
	}
}

func nodeText(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return string(src[node.StartByte():node.EndByte()])
}
