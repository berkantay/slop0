package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/berkantay/slop0/internal/adapters/outbound/lsp"
	"github.com/berkantay/slop0/internal/application/ports/outbound"
	"github.com/berkantay/slop0/internal/domain"
)

type LSPAnalyzer struct{}

func (a *LSPAnalyzer) BuildPreciseCallGraph(pkgs []domain.Package) *outbound.CallGraphResult {
	lang := detectLangFromPkgs(pkgs)
	serverCmd := lspServerForLang(lang)
	if serverCmd == "" {
		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}

	client, err := lsp.NewClient(serverCmd, lspArgsForLang(lang)...)
	if err != nil {
		return nil
	}
	defer client.Close()

	if _, err := client.Initialize("file://" + cwd); err != nil {
		return nil
	}

	result := &outbound.CallGraphResult{
		Calls:    make(map[string][]string),
		CalledBy: make(map[string][]string),
	}

	openFiles(pkgs, client, lang)
	buildCallGraphFromHierarchy(pkgs, client, result)

	return result
}

func (a *LSPAnalyzer) HarvestDiagnostics(pkgs []domain.Package) []domain.PatternIssue {
	lang := detectLangFromPkgs(pkgs)
	serverCmd := lspServerForLang(lang)
	if serverCmd == "" {
		return nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}

	client, err := lsp.NewClient(serverCmd, lspArgsForLang(lang)...)
	if err != nil {
		return nil
	}
	defer client.Close()

	if _, err := client.Initialize("file://" + cwd); err != nil {
		return nil
	}

	openFiles(pkgs, client, lang)

	return nil
}

func buildCallGraphFromHierarchy(pkgs []domain.Package, client *lsp.Client, result *outbound.CallGraphResult) {
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || fn.Line <= 0 {
				continue
			}

			key := pkg.Path + "." + fn.Name
			if seen[key] {
				continue
			}
			seen[key] = true

			uri := "file://" + fn.File
			items, err := client.PrepareCallHierarchy(uri, fn.Line-1, len(fn.Name)/2)
			if err != nil || len(items) == 0 {
				continue
			}

			collectOutgoing(items[0], key, client, result, seen)
		}
	}
}

func collectOutgoing(item lsp.CallHierarchyItem, callerKey string, client *lsp.Client, result *outbound.CallGraphResult, visited map[string]bool) {
	outgoing, err := client.OutgoingCalls(item)
	if err != nil {
		return
	}

	for _, call := range outgoing {
		calleeKey := callHierarchyItemToKey(call.To)
		if calleeKey == "" || calleeKey == callerKey {
			continue
		}

		result.Calls[callerKey] = appendIfNew(result.Calls[callerKey], calleeKey)
		result.CalledBy[calleeKey] = appendIfNew(result.CalledBy[calleeKey], callerKey)
	}
}

func callHierarchyItemToKey(item lsp.CallHierarchyItem) string {
	file := strings.TrimPrefix(item.URI, "file://")
	base := filepath.Base(file)
	return fmt.Sprintf("%s.%s", strings.TrimSuffix(base, filepath.Ext(base)), item.Name)
}

func openFiles(pkgs []domain.Package, client *lsp.Client, lang string) {
	seen := make(map[string]bool)
	langID := langToLSPID(lang)

	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if fn.File == "" || seen[fn.File] {
				continue
			}
			seen[fn.File] = true
			content, err := os.ReadFile(fn.File)
			if err != nil {
				continue
			}
			client.DidOpen("file://"+fn.File, langID, string(content))
		}
	}
}

func detectLangFromPkgs(pkgs []domain.Package) string {
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			switch {
			case strings.HasSuffix(fn.File, ".py"):
				return "python"
			case strings.HasSuffix(fn.File, ".ts"), strings.HasSuffix(fn.File, ".tsx"):
				return "typescript"
			case strings.HasSuffix(fn.File, ".go"):
				return "go"
			}
		}
	}
	return "go"
}

func lspServerForLang(lang string) string {
	switch lang {
	case "go":
		return findLSPBinary("gopls")
	case "python":
		return findLSPBinary("pyright-langserver")
	case "typescript":
		return findLSPBinary("typescript-language-server")
	}
	return ""
}

func lspArgsForLang(lang string) []string {
	if lang == "typescript" || lang == "python" {
		return []string{"--stdio"}
	}
	return nil
}

func langToLSPID(lang string) string {
	switch lang {
	case "python":
		return "python"
	case "typescript":
		return "typescript"
	default:
		return "go"
	}
}

func findLSPBinary(name string) string {
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, "go", "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		full := filepath.Join(dir, name)
		if _, err := os.Stat(full); err == nil {
			return full
		}
	}

	return ""
}

func appendIfNew(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
