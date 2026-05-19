package rules

import (
	"fmt"
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

// detectGoExtras runs additional Go-specific idiom checks using domain model data.
func detectGoExtras(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	issues = append(issues, detectPanicInLibrary(pkgs)...)
	issues = append(issues, detectInitSideEffects(pkgs)...)
	issues = append(issues, detectWeakCryptoImports(pkgs)...)
	return issues
}

func detectPanicInLibrary(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		if isMainOrCmdPkg(pkg.Path) {
			continue
		}
		issues = append(issues, findPanicCalls(pkg)...)
	}
	return issues
}

func isMainOrCmdPkg(path string) bool {
	if strings.HasSuffix(path, "cmd/") || strings.HasSuffix(path, "/main") || path == "main" {
		return true
	}
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	return last == "main" || last == "cmd"
}

func findPanicCalls(pkg domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, fn := range pkg.Functions {
		for _, call := range fn.Calls {
			if call == "panic" || strings.HasSuffix(call, ".panic") {
				issues = append(issues, domain.PatternIssue{
					Category:  "style/panic-in-library",
					Dominant:  "panic in library code forces callers to crash — return errors instead",
					Violation: fmt.Sprintf("%s.%s calls panic()", domain.ShortPkgName(pkg.Path), fn.Name),
					Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
				})
			}
		}
	}
	return issues
}

var initSideEffectPatterns = []string{"http.", "os.Open", "sql.", "net.", "io."}

func detectInitSideEffects(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.Name != "init" {
				continue
			}
			issues = append(issues, checkInitCalls(fn, pkg.Path)...)
		}
	}
	return issues
}

func checkInitCalls(fn domain.Function, pkgPath string) []domain.PatternIssue {
	var issues []domain.PatternIssue
	for _, call := range fn.Calls {
		if isSideEffectCall(call) {
			issues = append(issues, domain.PatternIssue{
				Category:  "style/init-side-effects",
				Dominant:  "init() with I/O/network side effects makes testing and startup order fragile",
				Violation: fmt.Sprintf("%s.init() calls %s", domain.ShortPkgName(pkgPath), call),
				Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
			})
		}
	}
	return issues
}

func isSideEffectCall(call string) bool {
	for _, pat := range initSideEffectPatterns {
		if strings.Contains(call, pat) {
			return true
		}
	}
	return false
}

// detectWeakCryptoImports flags usage of MD5 or SHA1 in imports.
func detectWeakCryptoImports(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		for _, imp := range pkg.Imports {
			if strings.Contains(imp, "crypto/md5") || strings.Contains(imp, "crypto/sha1") {
				issues = append(issues, domain.PatternIssue{
					Category:  "security/weak-crypto",
					Dominant:  "MD5/SHA1 are cryptographically broken — use SHA-256 or stronger",
					Violation: fmt.Sprintf("%s imports %s", domain.ShortPkgName(pkg.Path), imp),
					Locations: []domain.Location{{File: pkg.Path}},
				})
			}
		}
	}
	return issues
}
