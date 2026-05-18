package usecases

import (
	"github.com/berkantay/slop0/internal/application/ports/inbound"
	"github.com/berkantay/slop0/internal/application/ports/outbound"
	"github.com/berkantay/slop0/internal/domain"
)

type AnalyzeDeps struct {
	Symbols     outbound.SymbolExtractorPort
	CallGraph   outbound.CallGraphPort
	XRefs       outbound.CrossRefPort
	RuleConfig  outbound.RuleConfigPort
	RuleChecker outbound.RuleCheckerPort
	Renderer    outbound.RendererPort
}

type AnalyzeUseCase struct {
	deps AnalyzeDeps
}

func NewAnalyzeUseCase(deps AnalyzeDeps) *AnalyzeUseCase {
	return &AnalyzeUseCase{deps: deps}
}

func (uc *AnalyzeUseCase) Execute(opts inbound.AnalyzeOpts) (*domain.Report, error) {
	pkgs, err := uc.buildStructure(opts.Patterns)
	if err != nil {
		return nil, err
	}

	report := &domain.Report{Packages: pkgs}

	if !opts.StructureOnly {
		if err := uc.applyRules(report, pkgs, opts.ConfigPath); err != nil {
			return nil, err
		}
	}

	if opts.RulesOnly {
		report.Packages = nil
	}
	if len(opts.PkgFilter) > 0 {
		report.Packages = filterPackages(report.Packages, opts.PkgFilter)
	}
	if opts.Focus != "" {
		report.Packages = focusOnSymbol(report.Packages, opts.Focus, opts.Depth)
	}

	return report, nil
}

func (uc *AnalyzeUseCase) buildStructure(patterns []string) ([]domain.Package, error) {
	pkgs, err := uc.deps.Symbols.Extract(patterns)
	if err != nil {
		return nil, err
	}

	cg, err := uc.deps.CallGraph.Build(patterns)
	if err != nil {
		return nil, err
	}
	applyCallGraph(pkgs, cg)

	return uc.deps.XRefs.Resolve(pkgs)
}

func (uc *AnalyzeUseCase) applyRules(report *domain.Report, pkgs []domain.Package, configPath string) error {
	config, err := uc.loadRuleConfig(configPath)
	if err != nil {
		return err
	}

	ruleReport, err := uc.deps.RuleChecker.Check(pkgs, config)
	if err != nil {
		return err
	}

	report.Circulars = ruleReport.Circulars
	report.LayerViolations = ruleReport.LayerViolations
	report.PatternIssues = ruleReport.PatternIssues
	report.Duplications = ruleReport.Duplications
	report.DesignPatterns = ruleReport.DesignPatterns
	report.PkgMetrics = ruleReport.PkgMetrics
	report.TypeMetrics = ruleReport.TypeMetrics
	report.EntryPoints = ruleReport.EntryPoints
	report.ExternalDeps = ruleReport.ExternalDeps
	report.Hotspots = ruleReport.Hotspots
	report.DataFlows = ruleReport.DataFlows
	report.Summary = ruleReport.Summary
	return nil
}

func (uc *AnalyzeUseCase) loadRuleConfig(path string) (*domain.RuleConfig, error) {
	if path == "" {
		return nil, nil
	}
	return uc.deps.RuleConfig.Load(path)
}

func applyCallGraph(pkgs []domain.Package, cg *outbound.CallGraphResult) {
	funcIndex := make(map[string]*domain.Function)
	for i := range pkgs {
		for j := range pkgs[i].Functions {
			fn := &pkgs[i].Functions[j]
			key := pkgs[i].Path + "." + fn.Name
			funcIndex[key] = fn
		}
	}

	for caller, callees := range cg.Calls {
		if fn, ok := funcIndex[caller]; ok {
			fn.Calls = callees
		}
	}
	for callee, callers := range cg.CalledBy {
		if fn, ok := funcIndex[callee]; ok {
			fn.CalledBy = callers
		}
	}
}
