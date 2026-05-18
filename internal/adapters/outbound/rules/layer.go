package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

type LayerDetector struct{}

func (d *LayerDetector) Detect(pkgs []domain.Package, layers []domain.LayerDef) ([]domain.LayerViolation, error) {
	pkgToLayer := mapPkgsToLayers(pkgs, layers)
	allowedDeps := buildAllowedDeps(layers)
	return checkLayerViolations(pkgs, pkgToLayer, allowedDeps), nil
}

func mapPkgsToLayers(pkgs []domain.Package, layers []domain.LayerDef) map[string]*domain.LayerDef {
	pkgToLayer := make(map[string]*domain.LayerDef)
	for i := range layers {
		layer := &layers[i]
		for _, pattern := range layer.Packages {
			for _, pkg := range pkgs {
				if matchesPattern(pkg.Path, pattern) {
					pkgToLayer[pkg.Path] = layer
				}
			}
		}
	}
	return pkgToLayer
}

func buildAllowedDeps(layers []domain.LayerDef) map[string]map[string]bool {
	allowed := make(map[string]map[string]bool)
	for _, layer := range layers {
		m := make(map[string]bool)
		for _, dep := range layer.AllowedDeps {
			m[dep] = true
		}
		allowed[layer.Name] = m
	}
	return allowed
}

func checkLayerViolations(pkgs []domain.Package, pkgToLayer map[string]*domain.LayerDef, allowedDeps map[string]map[string]bool) []domain.LayerViolation {
	var violations []domain.LayerViolation
	for _, pkg := range pkgs {
		srcLayer, ok := pkgToLayer[pkg.Path]
		if !ok {
			continue
		}
		violations = append(violations, checkPkgImports(pkg, srcLayer, pkgToLayer, allowedDeps)...)
	}
	return violations
}

func checkPkgImports(pkg domain.Package, srcLayer *domain.LayerDef, pkgToLayer map[string]*domain.LayerDef, allowedDeps map[string]map[string]bool) []domain.LayerViolation {
	var violations []domain.LayerViolation
	allowed := allowedDeps[srcLayer.Name]

	for _, imp := range pkg.Imports {
		dstLayer, ok := pkgToLayer[imp]
		if !ok || dstLayer.Name == srcLayer.Name {
			continue
		}
		if !allowed[dstLayer.Name] {
			violations = append(violations, domain.LayerViolation{
				From:         srcLayer.Name + " (" + pkg.Path + ")",
				To:           dstLayer.Name + " (" + imp + ")",
				ExpectedPath: srcLayer.Name + " → " + strings.Join(srcLayer.AllowedDeps, " → "),
				Location:     domain.Location{File: pkg.Path},
			})
		}
	}
	return violations
}

func matchesPattern(pkgPath, pattern string) bool {
	pattern = strings.TrimSuffix(pattern, "/...")
	pattern = strings.TrimPrefix(pattern, "./")
	return strings.Contains(pkgPath, pattern)
}
