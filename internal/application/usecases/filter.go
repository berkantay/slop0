package usecases

import "github.com/berkantay/slop0/internal/domain"

func filterPackages(pkgs []domain.Package, filter []string) []domain.Package {
	var result []domain.Package
	for _, pkg := range pkgs {
		for _, f := range filter {
			if pkg.Path == f || matchesSuffix(pkg.Path, f) {
				result = append(result, pkg)
				break
			}
		}
	}
	return result
}

func matchesSuffix(path, filter string) bool {
	if len(path) <= len(filter) {
		return false
	}
	return path[len(path)-len(filter):] == filter
}
