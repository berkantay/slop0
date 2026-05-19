package typescript

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
	cmd := findTSServer()
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

	openTSFiles(pkgs, client)

	return pkgs, nil
}

func openTSFiles(pkgs []domain.Package, client *lsp.Client) {
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
			lang := "typescript"
			if filepath.Ext(fn.File) == ".tsx" {
				lang = "typescriptreact"
			}
			client.DidOpen("file://"+fn.File, lang, string(content))
		}
	}
}

func findTSServer() string {
	candidates := []string{
		"typescript-language-server",
	}

	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "typescript-language-server"),
			filepath.Join(home, "node_modules", ".bin", "typescript-language-server"),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "node_modules", ".bin", "typescript-language-server"),
		)
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
		path := os.Getenv("PATH")
		for _, dir := range filepath.SplitList(path) {
			full := filepath.Join(dir, c)
			if _, err := os.Stat(full); err == nil {
				return full
			}
		}
	}

	return "typescript-language-server"
}
