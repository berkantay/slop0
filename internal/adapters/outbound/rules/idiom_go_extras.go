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

// detectPanicInLibrary flags panic() calls in non-main packages.
func detectPanicInLibrary(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		if strings.HasSuffix(pkg.Path, "cmd/") || strings.HasSuffix(pkg.Path, "/main") || pkg.Path == "main" {
			continue
		}
		// Also skip if the last path component is "main" or starts with "cmd"
		parts := strings.Split(pkg.Path, "/")
		last := parts[len(parts)-1]
		if last == "main" || last == "cmd" {
			continue
		}

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
	}
	return issues
}

// detectInitSideEffects flags init() functions that perform I/O, network, or DB calls.
var initSideEffectPatterns = []string{"http.", "os.Open", "sql.", "net.", "io."}

func detectInitSideEffects(pkgs []domain.Package) []domain.PatternIssue {
	var issues []domain.PatternIssue

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.Name != "init" {
				continue
			}
			for _, call := range fn.Calls {
				for _, pat := range initSideEffectPatterns {
					if strings.Contains(call, pat) {
						issues = append(issues, domain.PatternIssue{
							Category:  "style/init-side-effects",
							Dominant:  "init() with I/O/network side effects makes testing and startup order fragile",
							Violation: fmt.Sprintf("%s.init() calls %s", domain.ShortPkgName(pkg.Path), call),
							Locations: []domain.Location{{File: fn.File, Line: fn.Line}},
						})
						break // one issue per call pattern match
					}
				}
			}
		}
	}
	return issues
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
