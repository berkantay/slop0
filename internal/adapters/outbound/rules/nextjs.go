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

	return issues
}

func detectMissingNextImage(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	hasNextImageImport := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "import_statement" {
			text := tsNodeText(node, src)
			if strings.Contains(text, "next/image") {
				hasNextImageImport = true
			}
		}
	})

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
			Dominant:  "use next/image instead of <img> — automatic optimization, lazy loading, responsive sizing",
			Violation: fmt.Sprintf("%s: <img> tag found", modPath),
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
		if href == "" {
			return
		}

		if strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") {
			issues = append(issues, domain.PatternIssue{
				Category:  "nextjs/no-html-link",
				Dominant:  "use next/link instead of <a> for internal navigation — enables client-side transitions",
				Violation: fmt.Sprintf("%s: <a href=\"%s\"> should use <Link>", modPath, href),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectUseClientTooHigh(root *sitter.Node, src []byte, fname, modPath string, file string) []domain.PatternIssue {
	hasUseClient := false
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "expression_statement" {
			text := strings.TrimSpace(tsNodeText(node, src))
			if text == `"use client"` || text == `'use client'` || text == `"use client";` || text == `'use client';` {
				hasUseClient = true
			}
		}
	})

	if !hasUseClient {
		return nil
	}

	hasHooks := false
	hasEventHandlers := false
	hasBrowserAPIs := false

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "call_expression" {
			return
		}
		fn := node.ChildByFieldName("function")
		if fn == nil {
			return
		}
		name := tsNodeText(fn, src)
		if strings.HasPrefix(name, "use") {
			hasHooks = true
		}
	})

	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "jsx_attribute" {
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil {
				attr := tsNodeText(nameNode, src)
				if strings.HasPrefix(attr, "on") {
					hasEventHandlers = true
				}
			}
		}
	})

	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "member_expression" {
			obj := node.ChildByFieldName("object")
			if obj != nil {
				name := tsNodeText(obj, src)
				if name == "window" || name == "document" || name == "navigator" || name == "localStorage" || name == "sessionStorage" {
					hasBrowserAPIs = true
				}
			}
		}
	})

	if !hasHooks && !hasEventHandlers && !hasBrowserAPIs {
		base := filepath.Base(file)
		isLayoutOrPage := base == "layout.tsx" || base == "layout.ts" || base == "page.tsx" || base == "page.ts"

		return []domain.PatternIssue{{
			Category:  "nextjs/unnecessary-use-client",
			Dominant:  "\"use client\" without hooks, event handlers, or browser APIs — can be a server component",
			Violation: fmt.Sprintf("%s: \"use client\" may be unnecessary%s", modPath, conditionalSuffix(isLayoutOrPage, " (layout/page file)")),
			Locations: []domain.Location{{File: fname, Line: 1}},
		}}
	}

	return nil
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
				return strings.Trim(tsNodeText(val, src), `"'\`+"`")
			}
		}
	}
	return ""
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

func conditionalSuffix(cond bool, suffix string) string {
	if cond {
		return suffix
	}
	return ""
}
