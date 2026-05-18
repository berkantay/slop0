package golang

import (
	"fmt"
	"go/token"
	"go/types"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/adapters/outbound/lsp"
	"github.com/berkantay/slop0/internal/domain"
)

type CrossRefResolver struct {
	serverCmd  string
	serverArgs []string
}

func NewCrossRefResolver() *CrossRefResolver {
	cmd := "gopls"
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, "go", "bin", "gopls")
		if _, err := os.Stat(candidate); err == nil {
			cmd = candidate
		}
	}
	return &CrossRefResolver{
		serverCmd:  cmd,
		serverArgs: []string{},
	}
}

func (r *CrossRefResolver) Resolve(pkgs []domain.Package) ([]domain.Package, error) {
	if len(pkgs) == 0 {
		return pkgs, nil
	}

	r.resolveInterfacesSemantic(pkgs)

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

	absFiles := collectAbsFiles(pkgs, cwd)
	for absPath, content := range absFiles {
		client.DidOpen(pathToURI(absPath), "go", content)
	}

	r.resolveTypeUsedByLSP(pkgs, client, absFiles)
	r.resolveVarUsedByLSP(pkgs, client, absFiles)

	return pkgs, nil
}

type typeEntry struct {
	named   *types.Named
	pkgPath string
}

type ifaceEntry struct {
	iface   *types.Interface
	name    string
	pkgPath string
}

func (r *CrossRefResolver) resolveInterfacesSemantic(domainPkgs []domain.Package) {
	patterns := make([]string, 0, len(domainPkgs))
	for _, p := range domainPkgs {
		patterns = append(patterns, p.Path)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedTypes | packages.NeedSyntax |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Fset: token.NewFileSet(),
	}

	loadedPkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return
	}

	namedTypes, ifaces := collectTypesAndInterfaces(loadedPkgs)
	implMap := buildImplMap(namedTypes, ifaces)
	applyImplMap(domainPkgs, implMap)
}

func collectTypesAndInterfaces(pkgs []*packages.Package) ([]typeEntry, []ifaceEntry) {
	var named []typeEntry
	var ifaces []ifaceEntry

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			n, ok := obj.Type().(*types.Named)
			if !ok {
				continue
			}
			if iface, ok := n.Underlying().(*types.Interface); ok {
				ifaces = append(ifaces, ifaceEntry{iface: iface, name: name, pkgPath: pkg.PkgPath})
			} else {
				named = append(named, typeEntry{named: n, pkgPath: pkg.PkgPath})
			}
		}
	}
	return named, ifaces
}

func buildImplMap(namedTypes []typeEntry, ifaces []ifaceEntry) map[string][]string {
	implMap := make(map[string][]string)
	for _, nt := range namedTypes {
		key := nt.pkgPath + "." + nt.named.Obj().Name()
		ptrType := types.NewPointer(nt.named)

		for _, ie := range ifaces {
			if ie.iface.NumMethods() == 0 {
				continue
			}
			if types.Implements(nt.named, ie.iface) || types.Implements(ptrType, ie.iface) {
				ifaceKey := ie.pkgPath + "." + ie.name
				implMap[key] = append(implMap[key], ifaceKey)
			}
		}
	}
	return implMap
}

func applyImplMap(domainPkgs []domain.Package, implMap map[string][]string) {
	for di := range domainPkgs {
		for ti := range domainPkgs[di].Types {
			t := &domainPkgs[di].Types[ti]
			key := domainPkgs[di].Path + "." + t.Name

			if impls, ok := implMap[key]; ok {
				for _, impl := range impls {
					parts := strings.Split(impl, ".")
					shortName := parts[len(parts)-1]
					t.Implements = appendUnique(t.Implements, shortName)
				}
			}
		}
	}
}

func (r *CrossRefResolver) resolveTypeUsedByLSP(pkgs []domain.Package, client *lsp.Client, absFiles map[string]string) {
	for di := range pkgs {
		for ti := range pkgs[di].Types {
			resolveTypeRefs(&pkgs[di].Types[ti], client, absFiles)
		}
	}
}

func resolveTypeRefs(t *domain.Type, client *lsp.Client, absFiles map[string]string) {
	absPath, line := findDeclInFiles(absFiles, "type "+t.Name+" ")
	if absPath == "" {
		return
	}

	col := findColInLine(absFiles[absPath], line, t.Name)
	refs, err := client.References(pathToURI(absPath), line, col)
	if err != nil || len(refs) == 0 {
		return
	}

	for _, ref := range refs {
		name := extractShortRef(ref.URI, ref.Range.Start.Line)
		if name != "" {
			t.UsedBy = appendUnique(t.UsedBy, name)
		}
	}
}

func (r *CrossRefResolver) resolveVarUsedByLSP(pkgs []domain.Package, client *lsp.Client, absFiles map[string]string) {
	for di := range pkgs {
		for vi := range pkgs[di].Variables {
			v := &pkgs[di].Variables[vi]
			resolveVarRefs(v, client, absFiles)
		}
	}
}

func resolveVarRefs(v *domain.Variable, client *lsp.Client, absFiles map[string]string) {
	absPath, line := findVarDecl(v.Name, absFiles)
	if absPath == "" {
		return
	}

	col := findColInLine(absFiles[absPath], line, v.Name)
	refs, err := client.References(pathToURI(absPath), line, col)
	if err != nil || len(refs) == 0 {
		return
	}

	for _, ref := range refs {
		name := extractShortRef(ref.URI, ref.Range.Start.Line)
		if name != "" {
			v.UsedBy = appendUnique(v.UsedBy, name)
		}
	}
}

func findVarDecl(varName string, absFiles map[string]string) (string, int) {
	for path, content := range absFiles {
		lines := strings.Split(content, "\n")
		for i, l := range lines {
			trimmed := strings.TrimSpace(l)
			if strings.HasPrefix(trimmed, varName+" ") ||
				strings.HasPrefix(trimmed, varName+"\t") ||
				strings.HasPrefix(trimmed, varName+"=") {
				return path, i
			}
		}
	}
	return "", 0
}

func collectAbsFiles(pkgs []domain.Package, cwd string) map[string]string {
	files := make(map[string]string)
	seen := make(map[string]bool)

	for _, pkg := range pkgs {
		allFiles := collectFilesFromPackage(pkg)
		for _, fname := range allFiles {
			if seen[fname] {
				continue
			}
			seen[fname] = true

			absPath := resolveFilePath(fname, pkg.Path, cwd)
			if absPath == "" {
				continue
			}
			content, err := os.ReadFile(absPath)
			if err != nil {
				continue
			}
			files[absPath] = string(content)
		}
	}
	return files
}

func collectFilesFromPackage(pkg domain.Package) []string {
	seen := make(map[string]bool)
	var files []string
	for _, fn := range pkg.Functions {
		if fn.File != "" && !seen[fn.File] {
			seen[fn.File] = true
			files = append(files, fn.File)
		}
	}
	return files
}

func findDeclInFiles(absFiles map[string]string, pattern string) (string, int) {
	for path, content := range absFiles {
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if strings.Contains(line, pattern) {
				return path, i
			}
		}
	}
	return "", 0
}

func findColInLine(content string, lineNum int, name string) int {
	lines := strings.Split(content, "\n")
	if lineNum >= len(lines) {
		return 0
	}
	idx := strings.Index(lines[lineNum], name)
	if idx < 0 {
		return 0
	}
	return idx
}

func resolveFilePath(filename, pkgPath, cwd string) string {
	candidates := []string{
		filepath.Join(cwd, filename),
	}

	parts := strings.Split(pkgPath, "/")
	for i := len(parts); i > 0; i-- {
		subpath := filepath.Join(parts[i-1:]...)
		candidates = append(candidates, filepath.Join(cwd, subpath, filename))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	var found string
	filepath.Walk(cwd, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Base(path) == filename {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func pathToURI(path string) string {
	return "file://" + path
}

func extractShortRef(uri string, line int) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(parsed.Path), line+1)
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func (r *CrossRefResolver) ResolveWithAST(pkgs []domain.Package, loadedPkgs []*packages.Package) {
	for _, pkg := range loadedPkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}

		for ident, obj := range info.Uses {
			_ = ident
			_ = obj
		}
	}
}
