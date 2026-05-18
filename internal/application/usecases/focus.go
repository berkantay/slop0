package usecases

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type symbolIndex struct {
	funcs     map[string]*domain.Function
	types     map[string]*domain.Type
	funcToPkg map[string]string
}

func buildSymbolIndex(pkgs []domain.Package) symbolIndex {
	idx := symbolIndex{
		funcs:     make(map[string]*domain.Function),
		types:     make(map[string]*domain.Type),
		funcToPkg: make(map[string]string),
	}
	for i := range pkgs {
		for j := range pkgs[i].Functions {
			fn := &pkgs[i].Functions[j]
			key := pkgs[i].Path + "." + fn.Name
			idx.funcs[key] = fn
			idx.funcToPkg[key] = pkgs[i].Path
		}
		for j := range pkgs[i].Types {
			t := &pkgs[i].Types[j]
			key := pkgs[i].Path + "." + t.Name
			idx.types[key] = t
		}
	}
	return idx
}

func focusOnSymbol(pkgs []domain.Package, focus string, depth int) []domain.Package {
	if depth <= 0 {
		depth = 3
	}

	idx := buildSymbolIndex(pkgs)
	rootKey := findRoot(idx, focus)
	if rootKey == "" {
		return pkgs
	}

	reachable := collectFocusReachable(idx, rootKey, depth)
	return buildFocusedPackages(pkgs, idx, reachable)
}

func findRoot(idx symbolIndex, focus string) string {
	for key := range idx.funcs {
		if strings.HasSuffix(key, "."+focus) || key == focus {
			return key
		}
	}
	for key := range idx.types {
		if strings.HasSuffix(key, "."+focus) || key == focus {
			return key
		}
	}
	return ""
}

func collectFocusReachable(idx symbolIndex, rootKey string, depth int) map[string]bool {
	reachable := map[string]bool{rootKey: true}
	if fn, ok := idx.funcs[rootKey]; ok {
		walkReachable(fn, idx.funcs, reachable, depth, 0)
	}
	return reachable
}

func walkReachable(fn *domain.Function, allFuncs map[string]*domain.Function, reachable map[string]bool, maxDepth, depth int) {
	if depth >= maxDepth {
		return
	}

	for _, key := range fn.Calls {
		if reachable[key] {
			continue
		}
		reachable[key] = true
		if callee, ok := allFuncs[key]; ok {
			walkReachable(callee, allFuncs, reachable, maxDepth, depth+1)
		}
	}

	for _, key := range fn.CalledBy {
		if reachable[key] {
			continue
		}
		reachable[key] = true
		if caller, ok := allFuncs[key]; ok {
			walkReachable(caller, allFuncs, reachable, maxDepth, depth+1)
		}
	}
}

func buildFocusedPackages(pkgs []domain.Package, idx symbolIndex, reachable map[string]bool) []domain.Package {
	pkgFuncs := make(map[string][]domain.Function)
	for key := range reachable {
		if fn, ok := idx.funcs[key]; ok {
			pkg := idx.funcToPkg[key]
			pkgFuncs[pkg] = append(pkgFuncs[pkg], *fn)
		}
	}

	pkgTypes := collectReferencedTypes(idx, reachable)

	var result []domain.Package
	seen := make(map[string]bool)
	for _, pkg := range pkgs {
		funcs := pkgFuncs[pkg.Path]
		types := pkgTypes[pkg.Path]
		if len(funcs) == 0 && len(types) == 0 {
			continue
		}
		if seen[pkg.Path] {
			continue
		}
		seen[pkg.Path] = true
		result = append(result, domain.Package{
			Path:      pkg.Path,
			Functions: funcs,
			Types:     types,
			Imports:   pkg.Imports,
		})
	}
	return result
}

func collectReferencedTypes(idx symbolIndex, reachable map[string]bool) map[string][]domain.Type {
	referenced := make(map[string]bool)
	for key := range reachable {
		if fn, ok := idx.funcs[key]; ok {
			for _, use := range fn.Uses {
				referenced[use] = true
			}
		}
	}

	pkgTypes := make(map[string][]domain.Type)
	for key, t := range idx.types {
		if referenced[t.Name] || reachable[key] {
			pkgPath := key[:len(key)-len(t.Name)-1]
			pkgTypes[pkgPath] = append(pkgTypes[pkgPath], *t)
		}
	}
	return pkgTypes
}
