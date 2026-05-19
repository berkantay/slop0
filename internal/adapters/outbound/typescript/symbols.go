package typescript

import (
	"context"
	"fmt"
	"os"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/berkantay/slop0/internal/domain"
)

type SymbolExtractor struct {
	parser *sitter.Parser
}

func NewSymbolExtractor() *SymbolExtractor {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
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

	files, err := CollectTSFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("collecting typescript files: %w", err)
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

		pkg := getOrCreatePkg(pkgMap, modPath)
		extractTSModule(tree.RootNode(), src, file, modPath, pkg)
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

func extractTSModule(root *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	for i := 0; i < int(root.NamedChildCount()); i++ {
		child := root.NamedChild(i)
		extractTSTopLevel(child, src, file, modPath, pkg)
	}
}

func extractTSTopLevel(node *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	switch node.Type() {
	case "function_declaration":
		pkg.Functions = append(pkg.Functions, extractTSFunction(node, src, file, modPath))
	case "class_declaration":
		pkg.Types = append(pkg.Types, extractTSClass(node, src, file, modPath))
	case "interface_declaration":
		pkg.Types = append(pkg.Types, extractTSInterface(node, src, file))
	case "type_alias_declaration":
		pkg.Types = append(pkg.Types, extractTypeAlias(node, src))
	case "export_statement":
		extractExportStatement(node, src, file, modPath, pkg)
	case "lexical_declaration":
		extractLexicalDecl(node, src, file, modPath, pkg)
	case "import_statement":
		pkg.Imports = append(pkg.Imports, nodeText(node, src))
	case "enum_declaration":
		pkg.Types = append(pkg.Types, extractEnum(node, src))
	}
}

func extractTSFunction(node *sitter.Node, src []byte, file, modPath string) domain.Function {
	name := nodeText(node.ChildByFieldName("name"), src)
	params := nodeText(node.ChildByFieldName("parameters"), src)
	retType := extractReturnType(node, src)

	return domain.Function{
		Name:      name,
		Signature: name + params + retType,
		Package:   modPath,
		File:      file,
		Line:      int(node.StartPoint().Row) + 1,
	}
}

func extractTSClass(node *sitter.Node, src []byte, file, modPath string) domain.Type {
	name := nodeText(node.ChildByFieldName("name"), src)

	t := domain.Type{
		Name: name,
		Kind: "class",
	}

	if heritage := findChildByType(node, "class_heritage"); heritage != nil {
		t.Implements = extractHeritage(heritage, src)
	}

	body := node.ChildByFieldName("body")
	if body != nil {
		extractClassBody(body, src, &t)
	}

	return t
}

func extractClassBody(body *sitter.Node, src []byte, t *domain.Type) {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		switch child.Type() {
		case "method_definition":
			name := nodeText(child.ChildByFieldName("name"), src)
			t.Methods = append(t.Methods, name)
		case "public_field_definition", "property_declaration":
			name := nodeText(child.ChildByFieldName("name"), src)
			typeNode := child.ChildByFieldName("type")
			fieldType := ""
			if typeNode != nil {
				fieldType = nodeText(typeNode, src)
			}
			t.Fields = append(t.Fields, domain.Field{Name: name, Type: fieldType})
		}
	}
}

func extractTSInterface(node *sitter.Node, src []byte, file string) domain.Type {
	name := nodeText(node.ChildByFieldName("name"), src)

	t := domain.Type{
		Name: name,
		Kind: "interface",
	}

	if extends := findChildByType(node, "extends_type_clause"); extends != nil {
		t.Implements = extractTypeList(extends, src)
	}

	body := node.ChildByFieldName("body")
	if body != nil {
		extractInterfaceBody(body, src, &t)
	}

	return t
}

func extractInterfaceBody(body *sitter.Node, src []byte, t *domain.Type) {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		child := body.NamedChild(i)
		if child.Type() == "method_signature" || child.Type() == "property_signature" {
			name := nodeText(child.ChildByFieldName("name"), src)
			if name != "" {
				t.Methods = append(t.Methods, name)
			}
		}
	}
}

func extractTypeAlias(node *sitter.Node, src []byte) domain.Type {
	name := nodeText(node.ChildByFieldName("name"), src)
	return domain.Type{Name: name, Kind: "alias"}
}

func extractEnum(node *sitter.Node, src []byte) domain.Type {
	name := nodeText(node.ChildByFieldName("name"), src)
	t := domain.Type{Name: name, Kind: "enum"}

	body := node.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.NamedChildCount()); i++ {
			child := body.NamedChild(i)
			if child.Type() == "enum_member" || child.Type() == "property_identifier" {
				memberName := nodeText(child.ChildByFieldName("name"), src)
				if memberName == "" {
					memberName = nodeText(child, src)
				}
				t.Fields = append(t.Fields, domain.Field{Name: memberName})
			}
		}
	}
	return t
}

func extractExportStatement(node *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		extractTSTopLevel(child, src, file, modPath, pkg)
	}
}

func extractLexicalDecl(node *sitter.Node, src []byte, file, modPath string, pkg *domain.Package) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() != "variable_declarator" {
			continue
		}

		name := nodeText(child.ChildByFieldName("name"), src)
		value := child.ChildByFieldName("value")

		if value != nil && isArrowOrFunction(value) {
			fn := extractArrowFunction(name, value, src, file, modPath)
			pkg.Functions = append(pkg.Functions, fn)
		} else {
			typeNode := child.ChildByFieldName("type")
			typeName := ""
			if typeNode != nil {
				typeName = nodeText(typeNode, src)
			}
			pkg.Variables = append(pkg.Variables, domain.Variable{
				Name:     name,
				TypeName: typeName,
			})
		}
	}
}

func extractArrowFunction(name string, value *sitter.Node, src []byte, file, modPath string) domain.Function {
	params := ""
	retType := ""

	if p := value.ChildByFieldName("parameters"); p != nil {
		params = nodeText(p, src)
	} else if p := value.ChildByFieldName("parameter"); p != nil {
		params = "(" + nodeText(p, src) + ")"
	}

	retType = extractReturnType(value, src)

	return domain.Function{
		Name:      name,
		Signature: name + params + retType,
		Package:   modPath,
		File:      file,
		Line:      int(value.StartPoint().Row) + 1,
	}
}

func extractReturnType(node *sitter.Node, src []byte) string {
	rt := node.ChildByFieldName("return_type")
	if rt == nil {
		return ""
	}
	text := nodeText(rt, src)
	if strings.HasPrefix(text, ":") {
		text = strings.TrimPrefix(text, ":")
		text = strings.TrimSpace(text)
	}
	return ": " + text
}

func extractHeritage(node *sitter.Node, src []byte) []string {
	var result []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		text := nodeText(child, src)
		text = strings.TrimPrefix(text, "extends ")
		text = strings.TrimPrefix(text, "implements ")
		for _, part := range strings.Split(text, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
	}
	return result
}

func extractTypeList(node *sitter.Node, src []byte) []string {
	var result []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		text := strings.TrimSpace(nodeText(child, src))
		if text != "" {
			result = append(result, text)
		}
	}
	return result
}

func isArrowOrFunction(node *sitter.Node) bool {
	return node.Type() == "arrow_function" || node.Type() == "function"
}

func findChildByType(node *sitter.Node, typeName string) *sitter.Node {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == typeName {
			return child
		}
	}
	return nil
}

func nodeText(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return string(src[node.StartByte():node.EndByte()])
}
