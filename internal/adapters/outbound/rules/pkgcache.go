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
	syntaxPkgs, syntaxFset, err := loadSyntaxOnly(domainPkgs)
	if err == nil {
		c.syntaxPkgs = syntaxPkgs
		c.syntaxFset = syntaxFset
	}
	typedPkgs, typedFset, err := loadWithTypes(domainPkgs)
	if err == nil {
		c.typedPkgs = typedPkgs
		c.typedFset = typedFset
	}
	return c
}

func (c *PkgCache) Syntax() ([]*packages.Package, *token.FileSet) {
	return c.syntaxPkgs, c.syntaxFset
}

func (c *PkgCache) Typed() ([]*packages.Package, *token.FileSet) {
	return c.typedPkgs, c.typedFset
}
