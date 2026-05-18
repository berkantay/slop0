package rules

import (
	"math"

	"github.com/berkantay/slop0/internal/domain"
)

type PkgMetricsCalculator struct{}

func (c *PkgMetricsCalculator) Calculate(pkgs []domain.Package) []domain.PackageMetrics {
	projectPkgs := make(map[string]bool)
	for _, pkg := range pkgs {
		projectPkgs[pkg.Path] = true
	}

	ca, ce := buildCouplingMaps(pkgs, projectPkgs)

	var metrics []domain.PackageMetrics
	for _, pkg := range pkgs {
		metrics = append(metrics, computePkgMetrics(&pkg, len(ca[pkg.Path]), len(ce[pkg.Path])))
	}

	return metrics
}

func buildCouplingMaps(pkgs []domain.Package, projectPkgs map[string]bool) (map[string]map[string]bool, map[string]map[string]bool) {
	ca := make(map[string]map[string]bool)
	ce := make(map[string]map[string]bool)

	for _, pkg := range pkgs {
		if ce[pkg.Path] == nil {
			ce[pkg.Path] = make(map[string]bool)
		}
		for _, imp := range pkg.Imports {
			if !projectPkgs[imp] {
				continue
			}
			ce[pkg.Path][imp] = true

			if ca[imp] == nil {
				ca[imp] = make(map[string]bool)
			}
			ca[imp][pkg.Path] = true
		}
	}
	return ca, ce
}

func computePkgMetrics(pkg *domain.Package, afferent, efferent int) domain.PackageMetrics {
	totalTypes, ifaceCount := countTypesAndInterfaces(pkg.Types)

	instability := 0.0
	if afferent+efferent > 0 {
		instability = float64(efferent) / float64(afferent+efferent)
	}

	abstractness := 0.0
	if totalTypes > 0 {
		abstractness = float64(ifaceCount) / float64(totalTypes)
	}

	distance := math.Abs(abstractness + instability - 1.0)

	return domain.PackageMetrics{
		Path:           pkg.Path,
		Ca:             afferent,
		Ce:             efferent,
		Instability:    math.Round(instability*100) / 100,
		Abstractness:   math.Round(abstractness*100) / 100,
		Distance:       math.Round(distance*100) / 100,
		TypeCount:      totalTypes,
		InterfaceCount: ifaceCount,
	}
}

func countTypesAndInterfaces(types []domain.Type) (int, int) {
	totalTypes := 0
	ifaceCount := 0
	for _, t := range types {
		totalTypes++
		if t.Kind == "interface" && len(t.Methods) > 0 {
			ifaceCount++
		}
	}
	return totalTypes, ifaceCount
}
