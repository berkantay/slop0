package inbound

import "github.com/berkantay/slop0/internal/domain"

type AnalyzeOpts struct {
	Patterns      []string
	Focus         string
	Depth         int
	RulesOnly     bool
	StructureOnly bool
	Format        string
	ConfigPath    string
	PkgFilter     []string
}

type AnalyzePort interface {
	Execute(opts AnalyzeOpts) (*domain.Report, error)
}
