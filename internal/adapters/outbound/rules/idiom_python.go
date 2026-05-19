package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/berkantay/slop0/internal/domain"
)

type PythonIdiomDetector struct {
	parser *sitter.Parser
}

func NewPythonIdiomDetector() *PythonIdiomDetector {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	return &PythonIdiomDetector{parser: parser}
}

func (d *PythonIdiomDetector) Detect(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		issues = append(issues, detectPEP8Naming(pkg)...)
		issues = append(issues, detectStarImports(pkg)...)
		issues = append(issues, detectAssertInProduction(pkg)...)
	}

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" {
				continue
			}
			issues = append(issues, d.detectFileIssues(fn.File, pkg.Path)...)
		}
	}

	return issues
}

func detectPEP8Naming(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if hasCamelCase(fn.Name) && fn.Name != "__init__" {
			issues = append(issues, domain.PatternIssue{
				Category:  "naming/pep8-function",
				Dominant:  "PEP 8: function names should be snake_case",
				Violation: fmt.Sprintf("%s.%s uses camelCase", domain.ShortPkgName(pkg.Path), fn.Name),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}

	for _, t := range pkg.Types {
		if t.Kind == "class" && hasUnderscore(t.Name) && !strings.HasPrefix(t.Name, "_") {
			issues = append(issues, domain.PatternIssue{
				Category:  "naming/pep8-class",
				Dominant:  "PEP 8: class names should be CamelCase",
				Violation: fmt.Sprintf("%s.%s uses snake_case", domain.ShortPkgName(pkg.Path), t.Name),
				Locations: []domain.Location{{File: pkg.Path}},
			})
		}
	}

	return issues
}

func detectStarImports(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, imp := range pkg.Imports {
		if strings.Contains(imp, "import *") || strings.HasSuffix(imp, " *") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/star-import",
				Dominant:  "avoid star imports — they pollute namespace and hide dependencies",
				Violation: fmt.Sprintf("%s: %s", domain.ShortPkgName(pkg.Path), imp),
				Locations: []domain.Location{{File: pkg.Path}},
			})
		}
	}

	return issues
}

func (d *PythonIdiomDetector) detectFileIssues(file, modPath string) []domain.PatternIssue {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil
	}

	tree, err := d.parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil
	}

	var issues []domain.PatternIssue
	fname := filepath.Base(file)
	root := tree.RootNode()

	issues = append(issues, detectBareExcept(root, src, fname, modPath)...)
	issues = append(issues, detectMutableDefaults(root, src, fname, modPath)...)
	issues = append(issues, detectGlobalStatement(root, src, fname, modPath)...)
	issues = append(issues, detectMissingTypeHints(root, src, fname, modPath)...)
	issues = append(issues, detectTypeVsIsinstance(root, src, fname, modPath)...)
	issues = append(issues, detectMutableClassAttr(root, src, fname, modPath)...)
	issues = append(issues, detectMissingContextManager(root, src, fname, modPath)...)
	issues = append(issues, detectIsForValue(root, src, fname, modPath)...)

	return issues
}

func detectBareExcept(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTreeSitter(root, func(node *sitter.Node) {
		if node.Type() != "except_clause" {
			return
		}
		if node.NamedChildCount() == 1 {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/bare-except",
				Dominant:  "bare except catches all exceptions including KeyboardInterrupt — specify exception type",
				Violation: fmt.Sprintf("%s in %s", modPath, fname),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectMutableDefaults(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTreeSitter(root, func(node *sitter.Node) {
		if node.Type() != "default_parameter" && node.Type() != "typed_default_parameter" {
			return
		}

		value := node.ChildByFieldName("value")
		if value == nil {
			return
		}

		if isMutableLiteral(value) {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/mutable-default",
				Dominant:  "mutable default argument is shared across calls — use None and create inside function",
				Violation: fmt.Sprintf("%s: %s", modPath, nodeTextPy(node, src)),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func detectGlobalStatement(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTreeSitter(root, func(node *sitter.Node) {
		if node.Type() != "global_statement" {
			return
		}
		issues = append(issues, domain.PatternIssue{
			Category:  "style/global-statement",
			Dominant:  "global statement makes code harder to reason about — pass values as parameters",
			Violation: fmt.Sprintf("%s: %s", modPath, nodeTextPy(node, src)),
			Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
		})
	})

	return issues
}

func detectMissingTypeHints(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTreeSitter(root, func(node *sitter.Node) {
		if node.Type() != "function_definition" {
			return
		}

		name := nodeTextPy(node.ChildByFieldName("name"), src)
		if strings.HasPrefix(name, "_") && name != "__init__" {
			return
		}

		if node.ChildByFieldName("return_type") == nil && name != "__init__" {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/missing-type-hint",
				Dominant:  "public function missing return type annotation",
				Violation: fmt.Sprintf("%s.%s", modPath, name),
				Locations: []domain.Location{{File: fname, Line: int(node.StartPoint().Row) + 1}},
			})
		}
	})

	return issues
}

func isMutableLiteral(node *sitter.Node) bool {
	switch node.Type() {
	case "list", "dictionary", "set":
		return true
	}
	return false
}

func hasCamelCase(name string) bool {
	if strings.HasPrefix(name, "_") {
		return false
	}
	hasLower := false
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) && hasLower {
			return true
		}
		if unicode.IsLower(r) {
			hasLower = true
		}
	}
	return false
}

func walkTreeSitter(node *sitter.Node, fn func(*sitter.Node)) {
	fn(node)
	for i := 0; i < int(node.NamedChildCount()); i++ {
		walkTreeSitter(node.NamedChild(i), fn)
	}
}

// --- Python extra detectors ---

var reTypeVsIsinstance = regexp.MustCompile(`type\s*\([^)]+\)\s*(==|is)\s*`)

func detectTypeVsIsinstance(_ *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		if reTypeVsIsinstance.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/type-vs-isinstance",
				Dominant:  "use isinstance() instead of type() comparison — it respects inheritance",
				Violation: fmt.Sprintf("%s: %s", modPath, strings.TrimSpace(line)),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}
	return issues
}

func detectMutableClassAttr(root *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue

	walkTreeSitter(root, func(node *sitter.Node) {
		if node.Type() != "class_definition" {
			return
		}
		body := node.ChildByFieldName("body")
		if body == nil {
			return
		}

		for i := 0; i < int(body.NamedChildCount()); i++ {
			child := body.NamedChild(i)
			if child.Type() != "expression_statement" {
				continue
			}
			if child.NamedChildCount() == 0 {
				continue
			}
			assign := child.NamedChild(0)
			if assign.Type() != "assignment" {
				continue
			}
			value := assign.ChildByFieldName("value")
			if value == nil {
				continue
			}
			switch value.Type() {
			case "list", "dictionary", "set":
				issues = append(issues, domain.PatternIssue{
					Category:  "style/mutable-class-attr",
					Dominant:  "mutable class attribute is shared across all instances — initialize in __init__",
					Violation: fmt.Sprintf("%s: %s", modPath, nodeTextPy(assign, src)),
					Locations: []domain.Location{{File: fname, Line: int(assign.StartPoint().Row) + 1}},
				})
			}
			if value.Type() == "call" {
				fn := value.ChildByFieldName("function")
				if fn != nil && nodeTextPy(fn, src) == "set" {
					issues = append(issues, domain.PatternIssue{
						Category:  "style/mutable-class-attr",
						Dominant:  "mutable class attribute is shared across all instances — initialize in __init__",
						Violation: fmt.Sprintf("%s: %s", modPath, nodeTextPy(assign, src)),
						Locations: []domain.Location{{File: fname, Line: int(assign.StartPoint().Row) + 1}},
					})
				}
			}
		}
	})

	return issues
}

var reOpenCall = regexp.MustCompile(`\bopen\s*\(`)

func detectMissingContextManager(_ *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if reOpenCall.MatchString(trimmed) && !strings.HasPrefix(trimmed, "with ") && !strings.HasPrefix(trimmed, "#") {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/missing-context-manager",
				Dominant:  "open() without 'with' statement — use context manager to ensure file is closed",
				Violation: fmt.Sprintf("%s: %s", modPath, trimmed),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}
	return issues
}

var reIsForValue = regexp.MustCompile(`\bis\b(?:\s+not)?\s+(?:"[^"]*"|'[^']*'|\d+)`)
var reIsNone = regexp.MustCompile(`\bis\s+None\b`)
var reIsNotNone = regexp.MustCompile(`\bis\s+not\s+None\b`)

func detectIsForValue(_ *sitter.Node, src []byte, fname, modPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	lines := strings.Split(string(src), "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if reIsForValue.MatchString(line) && !reIsNone.MatchString(line) {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/is-for-value",
				Dominant:  "'is' compares identity, not value — use '==' for string/number comparison",
				Violation: fmt.Sprintf("%s: %s", modPath, trimmed),
				Locations: []domain.Location{{File: fname, Line: i + 1}},
			})
		}
	}
	return issues
}

var reAssert = regexp.MustCompile(`^\s*assert\b`)

func detectAssertInProduction(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, fn := range pkg.Functions {
		if fn.File == "" {
			continue
		}
		fname := filepath.Base(fn.File)
		if strings.Contains(fname, "test") || strings.Contains(fname, "spec") || strings.HasPrefix(fname, "test_") || strings.HasSuffix(fname, "_test.py") {
			continue
		}

		src, err := os.ReadFile(fn.File)
		if err != nil {
			continue
		}
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			if reAssert.MatchString(line) {
				issues = append(issues, domain.PatternIssue{
					Category:  "style/assert-in-production",
					Dominant:  "assert can be stripped with -O flag — use proper error handling in production code",
					Violation: fmt.Sprintf("%s: %s", domain.ShortPkgName(pkg.Path), strings.TrimSpace(line)),
					Locations: []domain.Location{{File: fname, Line: i + 1}},
				})
			}
		}
	}
	return issues
}
