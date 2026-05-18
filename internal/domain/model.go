package domain

import "strings"

func ShortPkgName(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return path
	}
	return strings.Join(parts[len(parts)-2:], "/")
}

type Package struct {
	Path      string
	Functions []Function
	Types     []Type
	Variables []Variable
	Imports   []string
}

type Function struct {
	Name      string
	Signature string
	Calls     []string
	CalledBy  []string
	Uses      []string
	Package   string
	File      string
	Line      int
}

type Type struct {
	Name       string
	Kind       string // struct, interface
	Fields     []Field
	Methods    []string
	Implements []string
	UsedBy     []string
}

type Variable struct {
	Name     string
	TypeName string
	UsedBy   []string
}

type Field struct {
	Name string
	Type string
}
