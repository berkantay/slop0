package rules

import (
	"go/token"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type PkgCache struct {
	syntaxPkgs []*packages.Package
	syntaxFset *token.FileSet
	typedPkgs  []*packages.Package
	typedFset  *token.FileSet
}

func NewPkgCache(domainPkgs []domain.Package) *PkgCache {
	c := &PkgCache{}
	if lr, err := loadSyntaxOnly(domainPkgs); err == nil {
		c.syntaxPkgs = lr.Pkgs
		c.syntaxFset = lr.Fset
	}
	if lr, err := loadWithTypes(domainPkgs); err == nil {
		c.typedPkgs = lr.Pkgs
		c.typedFset = lr.Fset
	}
	return c
}

func (c *PkgCache) Syntax() ([]*packages.Package, *token.FileSet) {
	return c.syntaxPkgs, c.syntaxFset
}

func (c *PkgCache) Typed() ([]*packages.Package, *token.FileSet) {
	return c.typedPkgs, c.typedFset
}
