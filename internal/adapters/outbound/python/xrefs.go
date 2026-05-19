package python

import (
	"os"
	"path/filepath"

	"github.com/berkantay/slop0/internal/adapters/outbound/lsp"
	"github.com/berkantay/slop0/internal/domain"
)

type CrossRefResolver struct {
	serverCmd  string
	serverArgs []string
}

func NewCrossRefResolver() *CrossRefResolver {
	cmd := "pyright-langserver"

	candidates := []string{
		"pyright-langserver",
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "pyright-langserver"),
			filepath.Join(home, "node_modules", ".bin", "pyright-langserver"),
		)
	}

	for _, c := range candidates {
		if path, err := findExecutable(c); err == nil {
			cmd = path
			break
		}
	}

	return &CrossRefResolver{
		serverCmd:  cmd,
		serverArgs: []string{"--stdio"},
	}
}

func (r *CrossRefResolver) Resolve(pkgs []domain.Package) ([]domain.Package, error) {
	if len(pkgs) == 0 {
		return pkgs, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return pkgs, nil
	}

	client, err := lsp.NewClient(r.serverCmd, r.serverArgs...)
	if err != nil {
		return pkgs, nil
	}
	defer client.Close()

	rootURI := "file://" + cwd
	if _, err := client.Initialize(rootURI); err != nil {
		return pkgs, nil
	}

	openPythonFiles(pkgs, cwd, client)
	resolveTypeUsedBy(pkgs, cwd, client)

	return pkgs, nil
}

func openPythonFiles(pkgs []domain.Package, cwd string, client *lsp.Client) {
	seen := make(map[string]bool)
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
			client.DidOpen("file://"+fn.File, "python", string(content))
		}
	}
}

func resolveTypeUsedBy(pkgs []domain.Package, cwd string, client *lsp.Client) {
	for i := range pkgs {
		for j := range pkgs[i].Types {
			t := &pkgs[i].Types[j]
			resolveTypeRefs(t, pkgs[i], cwd, client)
		}
	}
}

func resolveTypeRefs(t *domain.Type, pkg domain.Package, cwd string, client *lsp.Client) {
	file, line := findSymbolInFiles(t.Name, pkg)
	if file == "" {
		return
	}

	col := len("class ")
	refs, err := client.References("file://"+file, line-1, col)
	if err != nil || len(refs) == 0 {
		return
	}

	for _, ref := range refs {
		name := filepath.Base(ref.URI) + ":" + string(rune(ref.Range.Start.Line+1))
		t.UsedBy = appendUniqueStr(t.UsedBy, name)
	}
}

func findSymbolInFiles(name string, pkg domain.Package) (string, int) {
	for _, fn := range pkg.Functions {
		if fn.Name == name {
			return fn.File, fn.Line
		}
	}
	return "", 0
}

func appendUniqueStr(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func findExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name, nil
		}
		return "", os.ErrNotExist
	}

	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		full := filepath.Join(dir, name)
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", os.ErrNotExist
}
