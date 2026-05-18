package rules

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type DuplicationDetector struct{}

func (d *DuplicationDetector) Detect(pkgs []domain.Package, t domain.Thresholds) ([]domain.Duplication, error) {
	dups := d.detectByCallGraph(pkgs, t)
	astDups := d.detectByAST(pkgs, t)
	dups = mergeDuplications(dups, astDups)
	return dups, nil
}

type funcInfo struct {
	qualName string
	fn       domain.Function
}

func (d *DuplicationDetector) detectByCallGraph(pkgs []domain.Package, t domain.Thresholds) []domain.Duplication {
	hashToFuncs := buildCallGraphHashMap(pkgs, t.DupCallGraphMinCalls)

	var dups []domain.Duplication
	for _, funcs := range hashToFuncs {
		if len(funcs) < 2 {
			continue
		}
		dups = append(dups, findCallGraphDups(funcs, t.DupSimilarity)...)
	}
	return dups
}

func buildCallGraphHashMap(pkgs []domain.Package, minCalls int) map[string][]funcInfo {
	hashToFuncs := make(map[string][]funcInfo)
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if len(fn.Calls) < minCalls {
				continue
			}
			hash := callGraphHash(fn.Calls)
			qualName := pkg.Path + "." + fn.Name
			hashToFuncs[hash] = append(hashToFuncs[hash], funcInfo{qualName: qualName, fn: fn})
		}
	}
	return hashToFuncs
}

func findCallGraphDups(funcs []funcInfo, minSimilarity float64) []domain.Duplication {
	var dups []domain.Duplication
	for i := 0; i < len(funcs); i++ {
		for j := i + 1; j < len(funcs); j++ {
			if dup := compareCallGraphPair(funcs[i], funcs[j], minSimilarity); dup != nil {
				dups = append(dups, *dup)
			}
		}
	}
	return dups
}

func compareCallGraphPair(a, b funcInfo, minSimilarity float64) *domain.Duplication {
	sim := jaccardSimilarity(a.fn.Calls, b.fn.Calls)
	if sim < minSimilarity {
		return nil
	}
	shared := intersect(a.fn.Calls, b.fn.Calls)
	return &domain.Duplication{
		FuncA:       a.qualName,
		FuncB:       b.qualName,
		Similarity:  sim,
		Description: fmt.Sprintf("shared calls: %s", strings.Join(shortenNames(shared), ", ")),
		Locations: [2]domain.Location{
			{File: a.fn.File, Line: a.fn.Line},
			{File: b.fn.File, Line: b.fn.Line},
		},
	}
}

type funcAST struct {
	qualName  string
	hash      string
	nodeCount int
	file      string
	line      int
}

func (d *DuplicationDetector) detectByAST(domainPkgs []domain.Package, t domain.Thresholds) []domain.Duplication {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil
	}

	allFuncs := collectFuncHashes(pkgs, cfg.Fset, t.DupASTMinNodes)
	return findASTDuplicates(allFuncs)
}

func collectFuncHashes(pkgs []*packages.Package, fset *token.FileSet, minNodes int) []funcAST {
	var result []funcAST
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			result = append(result, collectFuncHashesInFile(pkg, file, fset, minNodes)...)
		}
	}
	return result
}

func collectFuncHashesInFile(pkg *packages.Package, file *ast.File, fset *token.FileSet, minNodes int) []funcAST {
	var result []funcAST
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		nodeCount := countNodes(fn.Body)
		if nodeCount < minNodes {
			continue
		}

		pos := fset.Position(fn.Pos())
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = exprString(fn.Recv.List[0].Type) + "." + name
		}

		result = append(result, funcAST{
			qualName:  pkg.PkgPath + "." + name,
			hash:      structuralHash(fn.Body),
			nodeCount: nodeCount,
			file:      pos.Filename,
			line:      pos.Line,
		})
	}
	return result
}

func findASTDuplicates(funcs []funcAST) []domain.Duplication {
	groups := make(map[string][]funcAST)
	for _, fn := range funcs {
		groups[fn.hash] = append(groups[fn.hash], fn)
	}

	var dups []domain.Duplication
	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				a, b := group[i], group[j]
				if a.qualName == b.qualName {
					continue
				}
				dups = append(dups, domain.Duplication{
					FuncA:       a.qualName,
					FuncB:       b.qualName,
					Similarity:  1.0,
					Description: fmt.Sprintf("identical AST structure (%d nodes)", a.nodeCount),
					Locations: [2]domain.Location{
						{File: a.file, Line: a.line},
						{File: b.file, Line: b.line},
					},
				})
			}
		}
	}
	return dups
}

func structuralHash(node ast.Node) string {
	var b strings.Builder
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			b.WriteString("_")
			return false
		}
		b.WriteString(fmt.Sprintf("%T|", n))
		return true
	})
	h := sha256.Sum256([]byte(b.String()))
	return fmt.Sprintf("%x", h[:12])
}

func countNodes(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		if n != nil {
			count++
		}
		return true
	})
	return count
}

func exprString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + exprString(t.X)
	case *ast.SelectorExpr:
		return exprString(t.X) + "." + t.Sel.Name
	default:
		return "?"
	}
}

func callGraphHash(calls []string) string {
	sorted := make([]string, len(calls))
	copy(sorted, calls)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, ",")))
	return fmt.Sprintf("%x", h[:8])
}

func jaccardSimilarity(a, b []string) float64 {
	setA := make(map[string]bool, len(a))
	for _, c := range a {
		setA[c] = true
	}
	setB := make(map[string]bool, len(b))
	for _, c := range b {
		setB[c] = true
	}

	intersection := 0
	for k := range setA {
		if setB[k] {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func intersect(a, b []string) []string {
	set := make(map[string]bool)
	for _, s := range a {
		set[s] = true
	}
	var result []string
	for _, s := range b {
		if set[s] {
			result = append(result, s)
		}
	}
	return result
}

func shortenNames(names []string) []string {
	short := make([]string, len(names))
	for i, name := range names {
		parts := strings.Split(name, "/")
		short[i] = parts[len(parts)-1]
	}
	return short
}

func mergeDuplications(a, b []domain.Duplication) []domain.Duplication {
	seen := make(map[string]bool)
	for _, d := range a {
		key := d.FuncA + "|" + d.FuncB
		seen[key] = true
		key2 := d.FuncB + "|" + d.FuncA
		seen[key2] = true
	}

	result := append([]domain.Duplication{}, a...)
	for _, d := range b {
		key := d.FuncA + "|" + d.FuncB
		if !seen[key] {
			result = append(result, d)
			seen[key] = true
			seen[d.FuncB+"|"+d.FuncA] = true
		}
	}
	return result
}
