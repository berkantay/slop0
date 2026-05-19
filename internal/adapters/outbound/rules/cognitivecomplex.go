package rules

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type CognitiveComplexityDetector struct{}

func (d *CognitiveComplexityDetector) Detect(domainPkgs []domain.Package, t domain.Thresholds) ([]domain.PatternIssue, error) {
	lr, err := loadSyntaxOnly(domainPkgs)
	if err != nil {
		return nil, err
	}

	var issues []domain.PatternIssue
	for _, pkg := range lr.Pkgs {
		for _, file := range pkg.Syntax {
			fname := filepath.Base(lr.Fset.File(file.Pos()).Name())
			issues = append(issues, detectCogCycInFile(pkg, file, fname, lr.Fset, t)...)
		}
	}
	return issues, nil
}

func detectCogCycInFile(pkg *packages.Package, file *ast.File, fname string, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		issues = append(issues, checkCognitiveComplexity(pkg, fn, fname, fset, t)...)
		issues = append(issues, checkCyclomaticComplexity(pkg, fn, fname, fset, t)...)
	}
	return issues
}

func checkCognitiveComplexity(pkg *packages.Package, fn *ast.FuncDecl, fname string, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	cognitive := computeCognitive(fn.Body)
	if cognitive <= t.MaxCognitiveComplexity {
		return nil
	}
	pos := fset.Position(fn.Pos())
	return []domain.PatternIssue{{
		Category:   "complexity/cognitive",
		Dominant:   fmt.Sprintf("cognitive complexity should be ≤%d — hard to understand", t.MaxCognitiveComplexity),
		Violation:  fmt.Sprintf("%s.%s has cognitive complexity %d", pkg.Name, fn.Name.Name, cognitive),
		Confidence: domain.Confidence(0.9),
		Locations:  []domain.Location{{File: fname, Line: pos.Line}},
	}}
}

func checkCyclomaticComplexity(pkg *packages.Package, fn *ast.FuncDecl, fname string, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	cyclomatic := computeCyclomatic(fn.Body)
	if cyclomatic <= t.MaxCyclomaticComplexity {
		return nil
	}
	pos := fset.Position(fn.Pos())
	return []domain.PatternIssue{{
		Category:   "complexity/cyclomatic",
		Dominant:   fmt.Sprintf("cyclomatic complexity should be ≤%d — hard to test", t.MaxCyclomaticComplexity),
		Violation:  fmt.Sprintf("%s.%s has cyclomatic complexity %d", pkg.Name, fn.Name.Name, cyclomatic),
		Confidence: domain.Confidence(0.9),
		Locations:  []domain.Location{{File: fname, Line: pos.Line}},
	}}
}

// Cognitive complexity: measures how hard code is to understand.
// Increments for: breaks in linear flow (if, else, switch, for, select, goto, break-to-label, continue-to-label)
// Nesting penalty: each level of nesting adds extra weight
// Switch counts as 1 regardless of case count
// Boolean sequences (&&, ||) in conditions add cognitive load
func computeCognitive(body *ast.BlockStmt) int {
	score := 0
	walkCognitive(body, 0, &score)
	return score
}

func walkCognitive(node ast.Node, nesting int, score *int) {
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		return scoreCognitiveNode(n, nesting, score)
	})
}

func scoreCognitiveNode(n ast.Node, nesting int, score *int) bool {
	switch stmt := n.(type) {
	case *ast.IfStmt:
		scoreIfStmt(stmt, nesting, score)
		return false
	case *ast.ForStmt:
		scoreForStmt(stmt, nesting, score)
		return false
	case *ast.RangeStmt:
		scoreNestingBlock(stmt.Body, nesting, score)
		return false
	case *ast.SwitchStmt:
		scoreNestingBlock(stmt.Body, nesting, score)
		return false
	case *ast.TypeSwitchStmt:
		scoreNestingBlock(stmt.Body, nesting, score)
		return false
	case *ast.SelectStmt:
		scoreNestingBlock(stmt.Body, nesting, score)
		return false
	case *ast.BranchStmt:
		scoreBranchStmt(stmt, score)
	case *ast.GoStmt:
		*score += 1 + nesting
	case *ast.FuncLit:
		scoreFuncLit(stmt, nesting, score)
		return false
	}
	return true
}

func scoreBranchStmt(stmt *ast.BranchStmt, score *int) {
	if stmt.Label != nil {
		*score += 1
	}
}

func scoreFuncLit(stmt *ast.FuncLit, nesting int, score *int) {
	*score += 1 + nesting
	if stmt.Body != nil {
		walkCognitiveBlock(stmt.Body, nesting+1, score)
	}
}

func scoreIfStmt(stmt *ast.IfStmt, nesting int, score *int) {
	*score += 1 + nesting
	if stmt.Init != nil {
		walkCognitive(stmt.Init, nesting, score)
	}
	countBoolOps(stmt.Cond, score)
	walkCognitiveBlock(stmt.Body, nesting+1, score)
	scoreElse(stmt.Else, nesting, score)
}

func scoreElse(els ast.Stmt, nesting int, score *int) {
	if els == nil {
		return
	}
	*score += 1
	switch e := els.(type) {
	case *ast.BlockStmt:
		walkCognitiveBlock(e, nesting+1, score)
	case *ast.IfStmt:
		walkCognitive(e, nesting, score)
	}
}

func scoreForStmt(stmt *ast.ForStmt, nesting int, score *int) {
	*score += 1 + nesting
	if stmt.Cond != nil {
		countBoolOps(stmt.Cond, score)
	}
	walkCognitiveBlock(stmt.Body, nesting+1, score)
}

func scoreNestingBlock(body *ast.BlockStmt, nesting int, score *int) {
	*score += 1 + nesting
	walkCognitiveBlock(body, nesting+1, score)
}

func walkCognitiveBlock(block *ast.BlockStmt, nesting int, score *int) {
	for _, stmt := range block.List {
		walkCognitive(stmt, nesting, score)
	}
}

// Count boolean operators (&&, ||) that add cognitive load.
// Sequences of the same operator count as 1, switching operators adds 1.
func countBoolOps(expr ast.Expr, score *int) {
	var lastOp token.Token
	ast.Inspect(expr, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if bin.Op == token.LAND || bin.Op == token.LOR {
			if bin.Op != lastOp {
				*score += 1
				lastOp = bin.Op
			}
		}
		return true
	})
}

// Cyclomatic complexity: E - N + 2P, computed incrementally.
// Base 1, +1 for each decision point: if, for, case, &&, ||, select case
func computeCyclomatic(body *ast.BlockStmt) int {
	complexity := 1

	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.IfStmt:
			complexity++
			countBoolOpsCyclomatic(stmt.Cond, &complexity)
		case *ast.ForStmt:
			complexity++
			if stmt.Cond != nil {
				countBoolOpsCyclomatic(stmt.Cond, &complexity)
			}
		case *ast.RangeStmt:
			complexity++
		case *ast.CaseClause:
			if stmt.List != nil {
				complexity++
			}
		case *ast.CommClause:
			if stmt.Comm != nil {
				complexity++
			}
		}
		return true
	})

	return complexity
}

func countBoolOpsCyclomatic(expr ast.Expr, complexity *int) {
	ast.Inspect(expr, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if bin.Op == token.LAND || bin.Op == token.LOR {
			*complexity++
		}
		return true
	})
}

func (d *CognitiveComplexityDetector) DetectFromLoaded(pkgs []*packages.Package, fset *token.FileSet, t domain.Thresholds) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			fname := filepath.Base(fset.File(file.Pos()).Name())
			issues = append(issues, detectCogCycInFile(pkg, file, fname, fset, t)...)
		}
	}
	return issues
}
