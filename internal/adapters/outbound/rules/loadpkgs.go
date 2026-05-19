package rules

import (
	"go/token"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type LoadResult struct {
	Pkgs []*packages.Package
	Fset *token.FileSet
}

func loadPackagesForAnalysis(domainPkgs []domain.Package, mode packages.LoadMode) (LoadResult, error) {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: mode,
		Fset: fset,
	}

	pkgs, err := packages.Load(cfg, patterns...)
	return LoadResult{Pkgs: pkgs, Fset: fset}, err
}

func loadSyntaxOnly(domainPkgs []domain.Package) (LoadResult, error) {
	return loadPackagesForAnalysis(domainPkgs, packages.NeedName|packages.NeedFiles|packages.NeedSyntax)
}

func loadWithTypes(domainPkgs []domain.Package) (LoadResult, error) {
	return loadPackagesForAnalysis(domainPkgs,
		packages.NeedName|packages.NeedFiles|packages.NeedSyntax|
			packages.NeedTypes|packages.NeedTypesInfo)
}
