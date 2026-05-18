package rules

import "github.com/berkantay/slop0/internal/domain"

type Engine struct {
	circular    *CircularDetector
	layer       *LayerDetector
	pattern     *PatternDetector
	duplication *DuplicationDetector
	inferrer    *PatternInferrer
	idiom       *IdiomDetector
	complexity  *ComplexityDetector
	design      *DesignPatternDetector
	arch        *ArchViolationDetector
	cognitive   *CognitiveComplexityDetector
	pkgMetrics  *PkgMetricsCalculator
	typeRoles   *TypeRoleClassifier
	confidence  *ConfidenceScorer
	entryPoints *EntryPointDetector
	boundaries  *BoundaryDetector
	hotspots    *HotspotAnalyzer
	dataflow    *DataFlowTracer
	summary     *SummaryGenerator
	untypedMap  *UntypedMapDetector
}

func NewEngine() *Engine {
	return &Engine{
		circular:    &CircularDetector{},
		layer:       &LayerDetector{},
		pattern:     &PatternDetector{},
		duplication: &DuplicationDetector{},
		inferrer:    &PatternInferrer{},
		idiom:       &IdiomDetector{},
		complexity:  &ComplexityDetector{},
		design:      &DesignPatternDetector{},
		arch:        &ArchViolationDetector{},
		cognitive:   &CognitiveComplexityDetector{},
		pkgMetrics:  &PkgMetricsCalculator{},
		typeRoles:   &TypeRoleClassifier{},
		confidence:  &ConfidenceScorer{},
		entryPoints: &EntryPointDetector{},
		boundaries:  &BoundaryDetector{},
		hotspots:    &HotspotAnalyzer{},
		dataflow:    &DataFlowTracer{},
		summary:     &SummaryGenerator{},
		untypedMap:  &UntypedMapDetector{},
	}
}

func (e *Engine) Check(pkgs []domain.Package, config *domain.RuleConfig) (*domain.Report, error) {
	report := &domain.Report{}

	thresholds := domain.DefaultThresholds()
	if config != nil {
		thresholds = thresholds.Merge(config.Thresholds)
	}

	cache := NewPkgCache(pkgs)

	e.runStructuralChecks(pkgs, config, thresholds, report)
	e.runPatternChecks(pkgs, thresholds, cache, report)
	e.runScoringAndMetrics(pkgs, cache, report)

	return report, nil
}

func (e *Engine) runStructuralChecks(pkgs []domain.Package, config *domain.RuleConfig, thresholds domain.Thresholds, report *domain.Report) {
	if circulars, err := e.circular.Detect(pkgs); err == nil {
		report.Circulars = circulars
	}

	if config != nil && len(config.Layers) > 0 {
		if violations, err := e.layer.Detect(pkgs, config.Layers); err == nil {
			report.LayerViolations = violations
		}
	}

	archViolations, archIssues := e.arch.Detect(pkgs)
	report.LayerViolations = append(report.LayerViolations, archViolations...)
	report.PatternIssues = append(report.PatternIssues, archIssues...)

	if dups, err := e.duplication.Detect(pkgs, thresholds); err == nil {
		report.Duplications = dups
	}
}

func (e *Engine) runPatternChecks(pkgs []domain.Package, thresholds domain.Thresholds, cache *PkgCache, report *domain.Report) {
	if patterns, err := e.pattern.Detect(pkgs, thresholds); err == nil {
		report.PatternIssues = append(report.PatternIssues, patterns...)
	}

	report.PatternIssues = append(report.PatternIssues, e.inferrer.InferErrorPatternsFromCache(cache, thresholds)...)
	report.PatternIssues = append(report.PatternIssues, e.idiom.DetectFromCache(cache)...)

	syntaxPkgs, syntaxFset := cache.Syntax()
	report.PatternIssues = append(report.PatternIssues, e.complexity.DetectFromLoaded(syntaxPkgs, syntaxFset, thresholds)...)
	report.PatternIssues = append(report.PatternIssues, e.cognitive.DetectFromLoaded(syntaxPkgs, syntaxFset, thresholds)...)

	typedPkgs, typedFset := cache.Typed()
	report.PatternIssues = append(report.PatternIssues, e.untypedMap.Detect(typedPkgs, typedFset, thresholds)...)

	if designPatterns, err := e.design.DetectFromCache(pkgs, cache); err == nil {
		report.DesignPatterns = e.confidence.ScorePatterns(designPatterns, pkgs)
	}

	report.PatternIssues = e.confidence.ScoreIssues(report.PatternIssues, pkgs)
}

func (e *Engine) runScoringAndMetrics(pkgs []domain.Package, cache *PkgCache, report *domain.Report) {
	report.PkgMetrics = e.pkgMetrics.Calculate(pkgs)

	typedPkgs, typedFset := cache.Typed()
	report.TypeMetrics = e.typeRoles.ClassifyFromLoaded(pkgs, typedPkgs, typedFset)
	report.EntryPoints = e.entryPoints.DetectFromLoaded(typedPkgs, typedFset)

	if extDeps, err := e.boundaries.Detect(pkgs); err == nil {
		report.ExternalDeps = extDeps
	}

	report.Hotspots = e.hotspots.Analyze(pkgs)
	report.DataFlows = e.dataflow.Trace(pkgs, report.EntryPoints, report.ExternalDeps)
	report.Summary = e.summary.Generate(report, pkgs)
}
