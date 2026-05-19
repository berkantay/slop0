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

type TypeScriptIdiomDetector struct {
	parser *sitter.Parser
}

func NewTypeScriptIdiomDetector() *TypeScriptIdiomDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(typescript.GetLanguage())
	return &TypeScriptIdiomDetector{parser: parser}
}

func (d *TypeScriptIdiomDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		issues = append(issues, detectAnyType(pkg)...)
		issues = append(issues, detectNonNullAssertion(pkg)...)
		issues = append(issues, detectTSNamingIssues(pkg)...)
		issues = append(issues, detectConsoleLog(pkg)...)
	}

	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			seen[fn.File] = true
			issues = append(issues, d.detectFileIssuesTS(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func (d *TypeScriptIdiomDetector) detectFileIssuesTS(file, modPath string) []domain.PatternIssue {
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

	issues = append(issues, detectAsAssertionByAST(root, src, fname, modPath)...)
	issues = append(issues, detectEnumByAST(root, src, fname, modPath)...)
	issues = append(issues, detectMissingReturnTypeByAST(root, src, fname, modPath)...)
	issues = append(issues, detectNonNullCountByAST(root, src, fname, modPath)...)

	return issues
}

func detectAsAssertionByAST(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	count := 0
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "as_expression" {
			count++
		}
	})

	if count > 3 {
		return []domain.PatternIssue{{
			Category:  "style/as-assertion-overuse",
			Dominant:  "excessive 'as' type assertions bypass type safety — refine types instead",
			Violation: fmt.Sprintf("%s: %d 'as' assertions in %s", modPath, count, fname),
			Locations: []domain.Location{{File: fname, Line: 1}},
		}}
	}
	return nil
}

func detectEnumByAST(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "enum_declaration" {
			name := ""
			nameNode := node.ChildByFieldName("name")
			if nameNode != nil {
				name = tsNodeText(nameNode, src)
			}
			issues = append(issues, domain.PatternIssue{
				Category:  "style/enum-usage",
				Dominant:  "prefer union types over enums — more flexible and tree-shakeable",
				Violation: fmt.Sprintf("%s: enum %s", modPath, name),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})
	return issues
}

func detectMissingReturnTypeByAST(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTS(root, func(node *sitter.Node) {
		if node.Type() != "export_statement" {
			return
		}

		walkTS(node, func(child *sitter.Node) {
			if child.Type() == "function_declaration" {
				if child.ChildByFieldName("return_type") == nil {
					name := tsNodeText(child.ChildByFieldName("name"), src)
					issues = append(issues, domain.PatternIssue{
						Category:  "style/missing-return-type",
						Dominant:  "exported function missing return type annotation",
						Violation: fmt.Sprintf("%s: export function %s", modPath, name),
						Locations: []domain.Location{{File: fname, Line: int(child.StartPoint().Row) + 1}},
					})
				}
			}
		})
	})

	return issues
}

func detectNonNullCountByAST(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	count := 0
	walkTS(root, func(node *sitter.Node) {
		if node.Type() == "non_null_expression" {
			count++
		}
	})

	if count > 5 {
		return []domain.PatternIssue{{
			Category:  "style/non-null-assertion-overuse",
			Dominant:  fmt.Sprintf("%d non-null assertions — use proper null checks or optional chaining", count),
			Violation: fmt.Sprintf("%s: %s", modPath, fname),
			Locations: []domain.Location{{File: fname, Line: 1}},
		}}
	}
	return nil
}

func detectAnyType(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if strings.Contains(fn.Signature, ": any") || strings.Contains(fn.Signature, ":any") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/any-type",
				Dominant:  "avoid 'any' type — it disables type checking",
				Violation: fmt.Sprintf("%s.%s uses 'any' in signature", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	for _, t := range pkg.Types {
		for _, f := range t.Fields {
			if f.Type == "any" || strings.HasPrefix(f.Type, ": any") {
				issues = append(issues, domain.PatternIssue{
					Category:  "style/any-type",
					Dominant:  "avoid 'any' type — it disables type checking",
					Violation: fmt.Sprintf("%s.%s.%s is typed as 'any'", domain.ShortPkgName(pkg.Path), t.Name, f.Name),
					Locations: []domain.Location{{File: pkg.Path}},
				})
			}
		}
	}

	return issues
}

func detectNonNullAssertion(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if strings.Contains(fn.Signature, "!.") || strings.Contains(fn.Signature, "!)") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/non-null-assertion",
				Dominant:  "non-null assertion (!) bypasses type safety — use proper null checks",
				Violation: fmt.Sprintf("%s.%s uses non-null assertion", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	return issues
}

func detectTSNamingIssues(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, t := range pkg.Types {
		if t.Kind == "interface" && len(t.Name) > 1 && t.Name[0] == 'I' {
			second := rune(t.Name[1])
			if second >= 'A' && second <= 'Z' {
				issues = append(issues, domain.PatternIssue{
					Category:  "naming/interface-prefix",
					Dominant:  "TypeScript convention: don't prefix interfaces with 'I'",
					Violation: fmt.Sprintf("%s.%s — use %s instead", domain.ShortPkgName(pkg.Path), t.Name, t.Name[1:]),
					Locations: []domain.Location{{File: pkg.Path}},
				})
			}
		}
	}

	return issues
}

func detectConsoleLog(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		for _, call := range fn.Calls {
			if !isConsolePrint(call) {
				continue
			}
			if strings.Contains(fn.File, "test") || strings.Contains(fn.File, "spec") {
				continue
			}
			issues = append(issues, domain.PatternIssue{
				Category:  "style/console-log",
				Dominant:  "console.log in production code — use a proper logger",
				Violation: fmt.Sprintf("%s.%s calls %s", domain.ShortPkgName(pkg.Path), fn.Name, call),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	return issues
}

func isConsolePrint(call string) bool {
	return strings.Contains(call, "console.log") ||
		strings.Contains(call, "console.warn") ||
		strings.Contains(call, "console.error")
}
