package golang

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/berkantay/slop0/internal/domain"
)

type SymbolExtractor struct{}

func NewSymbolExtractor() *SymbolExtractor {
	return &SymbolExtractor{}
}

func (e *SymbolExtractor) Extract(patterns []string) ([]domain.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedImports,
		Fset: token.NewFileSet(),
	}

	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}

	var result []domain.Package
	for _, pkg := range pkgs {
		if pkg.Types == nil {
			continue
		}
		dp := extractPackage(pkg, cfg.Fset)
		result = append(result, dp)
	}
	return result, nil
}

func extractPackage(pkg *packages.Package, fset *token.FileSet) domain.Package {
	dp := domain.Package{
		Path: pkg.PkgPath,
	}

	for imp := range pkg.Imports {
		dp.Imports = append(dp.Imports, imp)
	}

	for _, file := range pkg.Syntax {
		fname := filepath.Base(fset.File(file.Pos()).Name())
		extractFileDecls(file, pkg, fset, fname, &dp)
	}

	return dp
}

func extractFileDecls(file *ast.File, pkg *packages.Package, fset *token.FileSet, fname string, dp *domain.Package) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			fn := extractFunction(d, pkg.TypesInfo, fset, fname, dp.Path)
			dp.Functions = append(dp.Functions, fn)
		case *ast.GenDecl:
			extractGenDecl(d, pkg, fset, fname, dp)
		}
	}
}

func extractGenDecl(d *ast.GenDecl, pkg *packages.Package, fset *token.FileSet, fname string, dp *domain.Package) {
	if d.Tok == token.TYPE {
		for _, spec := range d.Specs {
			ts := spec.(*ast.TypeSpec)
			t := extractType(ts, pkg.TypesInfo, fset, fname)
			dp.Types = append(dp.Types, t)
		}
	}
	if d.Tok == token.VAR || d.Tok == token.CONST {
		for _, spec := range d.Specs {
			vs := spec.(*ast.ValueSpec)
			vars := extractVariables(vs, pkg.TypesInfo)
			dp.Variables = append(dp.Variables, vars...)
		}
	}
}

func extractFunction(fn *ast.FuncDecl, info *types.Info, fset *token.FileSet, fname, pkgPath string) domain.Function {
	pos := fset.Position(fn.Pos())
	sig := buildSignature(fn, info)

	return domain.Function{
		Name:      fn.Name.Name,
		Signature: sig,
		Package:   pkgPath,
		File:      fname,
		Line:      pos.Line,
	}
}

func buildSignature(fn *ast.FuncDecl, info *types.Info) string {
	obj := info.Defs[fn.Name]
	if obj == nil {
		return fn.Name.Name + "(...)"
	}

	sig, ok := obj.Type().(*types.Signature)
	if !ok {
		return fn.Name.Name + "(...)"
	}

	var b strings.Builder

	if recv := sig.Recv(); recv != nil {
		b.WriteString("(")
		b.WriteString(shortType(recv.Type()))
		b.WriteString(") ")
	}

	b.WriteString(fn.Name.Name)
	b.WriteString("(")
	writeTupleTypes(&b, sig.Params())
	b.WriteString(")")

	writeResults(&b, sig.Results())

	return b.String()
}

func writeTupleTypes(b *strings.Builder, tuple *types.Tuple) {
	for i := 0; i < tuple.Len(); i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(shortType(tuple.At(i).Type()))
	}
}

func writeResults(b *strings.Builder, results *types.Tuple) {
	if results.Len() == 0 {
		return
	}
	b.WriteString(" ")
	if results.Len() == 1 {
		b.WriteString(shortType(results.At(0).Type()))
		return
	}
	b.WriteString("(")
	writeTupleTypes(b, results)
	b.WriteString(")")
}

func shortType(t types.Type) string {
	s := types.TypeString(t, func(pkg *types.Package) string {
		return pkg.Name()
	})
	return s
}

func extractType(ts *ast.TypeSpec, info *types.Info, fset *token.FileSet, fname string) domain.Type {
	dt := domain.Type{
		Name: ts.Name.Name,
	}

	switch t := ts.Type.(type) {
	case *ast.StructType:
		dt.Kind = "struct"
		dt.Fields = extractStructFields(t)
	case *ast.InterfaceType:
		dt.Kind = "interface"
		dt.Methods = extractInterfaceMethodNames(t)
	default:
		dt.Kind = "alias"
	}

	appendNamedMethods(&dt, info.Defs[ts.Name])

	return dt
}

func extractStructFields(st *ast.StructType) []domain.Field {
	if st.Fields == nil {
		return nil
	}
	var fields []domain.Field
	for _, f := range st.Fields.List {
		fieldType := types.ExprString(f.Type)
		if len(f.Names) == 0 {
			fields = append(fields, domain.Field{Name: fieldType, Type: fieldType})
		}
		for _, name := range f.Names {
			fields = append(fields, domain.Field{Name: name.Name, Type: fieldType})
		}
	}
	return fields
}

func extractInterfaceMethodNames(it *ast.InterfaceType) []string {
	if it.Methods == nil {
		return nil
	}
	var methods []string
	for _, m := range it.Methods.List {
		for _, name := range m.Names {
			methods = append(methods, name.Name)
		}
	}
	return methods
}

func appendNamedMethods(dt *domain.Type, obj types.Object) {
	if obj == nil {
		return
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return
	}
	for i := 0; i < named.NumMethods(); i++ {
		dt.Methods = append(dt.Methods, named.Method(i).Name())
	}
}

func extractVariables(vs *ast.ValueSpec, info *types.Info) []domain.Variable {
	var result []domain.Variable
	for _, name := range vs.Names {
		if name.Name == "_" {
			continue
		}
		v := domain.Variable{
			Name: name.Name,
		}
		obj := info.Defs[name]
		if obj != nil {
			v.TypeName = shortType(obj.Type())
		}
		result = append(result, v)
	}
	return result
}
