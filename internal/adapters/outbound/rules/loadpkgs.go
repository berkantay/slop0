package rules

import (
	"go/token"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

func loadPackagesForAnalysis(domainPkgs []domain.Package, mode packages.LoadMode) ([]*packages.Package, *token.FileSet, error) {
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
	return pkgs, fset, err
}

func loadSyntaxOnly(domainPkgs []domain.Package) ([]*packages.Package, *token.FileSet, error) {
	return loadPackagesForAnalysis(domainPkgs, packages.NeedName|packages.NeedFiles|packages.NeedSyntax)
}

func loadWithTypes(domainPkgs []domain.Package) ([]*packages.Package, *token.FileSet, error) {
	return loadPackagesForAnalysis(domainPkgs,
		packages.NeedName|packages.NeedFiles|packages.NeedSyntax|
			packages.NeedTypes|packages.NeedTypesInfo)
}
