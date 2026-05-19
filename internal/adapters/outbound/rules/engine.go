package rules

import (
	"strings"

	"github.com/berkantay/slop0/internal/domain"
)

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
	untypedMap       *UntypedMapDetector
	pyEntryPoints    *PythonEntryPointDetector
	pyIdiom          *PythonIdiomDetector
	pyBoundaries     *PythonBoundaryDetector
	tsEntryPoints    *TypeScriptEntryPointDetector
	tsIdiom          *TypeScriptIdiomDetector
	tsBoundaries     *TypeScriptBoundaryDetector
	react            *ReactDetector
	nextjs           *NextJSDetector
	security         *SecurityDetector
	codeQuality      *CodeQualityDetector
	graphAnalyzer    *GraphAnalyzer
	django           *DjangoDetector
	fastapi          *FastAPIDetector
	nestjsFw         *NestJSDetector
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
		untypedMap:       &UntypedMapDetector{},
		pyEntryPoints:    NewPythonEntryPointDetector(),
		pyIdiom:          NewPythonIdiomDetector(),
		pyBoundaries:     &PythonBoundaryDetector{},
		tsEntryPoints:    &TypeScriptEntryPointDetector{},
		tsIdiom:          &TypeScriptIdiomDetector{},
		tsBoundaries:     &TypeScriptBoundaryDetector{},
		react:            NewReactDetector(),
		nextjs:           NewNextJSDetector(),
		security:         NewSecurityDetector(),
		codeQuality:      &CodeQualityDetector{},
		graphAnalyzer:    &GraphAnalyzer{},
		django:           &DjangoDetector{},
		fastapi:          &FastAPIDetector{},
		nestjsFw:         &NestJSDetector{},
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

	report.PatternIssues = append(report.PatternIssues, e.security.Detect(pkgs)...)
	report.PatternIssues = append(report.PatternIssues, e.codeQuality.Detect(pkgs)...)

	lang := detectProjectLang(pkgs)

	switch lang {
	case "go":
		e.runGoPatternChecks(pkgs, thresholds, cache, report)
	case "python":
		report.PatternIssues = append(report.PatternIssues, e.pyIdiom.Detect(pkgs)...)
	case "typescript":
		report.PatternIssues = append(report.PatternIssues, e.tsIdiom.Detect(pkgs)...)
		report.PatternIssues = append(report.PatternIssues, e.react.Detect(pkgs)...)
		report.PatternIssues = append(report.PatternIssues, e.nextjs.Detect(pkgs)...)
	}

	report.PatternIssues = append(report.PatternIssues, e.django.Detect(pkgs)...)
	report.PatternIssues = append(report.PatternIssues, e.fastapi.Detect(pkgs)...)
	report.PatternIssues = append(report.PatternIssues, e.nestjsFw.Detect(pkgs)...)

	report.PatternIssues = e.confidence.ScoreIssues(report.PatternIssues, pkgs)
}

func (e *Engine) runGoPatternChecks(pkgs []domain.Package, thresholds domain.Thresholds, cache *PkgCache, report *domain.Report) {
	report.PatternIssues = append(report.PatternIssues, e.inferrer.InferErrorPatternsFromCache(cache, thresholds)...)
	report.PatternIssues = append(report.PatternIssues, e.idiom.DetectFromCache(cache)...)
	report.PatternIssues = append(report.PatternIssues, detectGoExtras(pkgs)...)

	syntaxPkgs, syntaxFset := cache.Syntax()
	report.PatternIssues = append(report.PatternIssues, e.complexity.DetectFromLoaded(syntaxPkgs, syntaxFset, thresholds)...)
	report.PatternIssues = append(report.PatternIssues, e.cognitive.DetectFromLoaded(syntaxPkgs, syntaxFset, thresholds)...)

	typedPkgs, typedFset := cache.Typed()
	report.PatternIssues = append(report.PatternIssues, e.untypedMap.Detect(typedPkgs, typedFset, thresholds)...)

	if designPatterns, err := e.design.DetectFromCache(pkgs, cache); err == nil {
		report.DesignPatterns = e.confidence.ScorePatterns(designPatterns, pkgs)
	}
}

func (e *Engine) runScoringAndMetrics(pkgs []domain.Package, cache *PkgCache, report *domain.Report) {
	report.PkgMetrics = e.pkgMetrics.Calculate(pkgs)

	lang := detectProjectLang(pkgs)

	switch lang {
	case "python":
		report.EntryPoints = e.pyEntryPoints.Detect(pkgs)
		report.ExternalDeps = e.pyBoundaries.Detect(pkgs)
	case "typescript":
		report.EntryPoints = e.tsEntryPoints.Detect(pkgs)
		report.ExternalDeps = e.tsBoundaries.Detect(pkgs)
	default:
		typedPkgs, typedFset := cache.Typed()
		report.TypeMetrics = e.typeRoles.ClassifyFromLoaded(pkgs, typedPkgs, typedFset)
		report.EntryPoints = e.entryPoints.DetectFromLoaded(typedPkgs, typedFset)
		if extDeps, err := e.boundaries.Detect(pkgs); err == nil {
			report.ExternalDeps = extDeps
		}
	}

	report.Hotspots = e.hotspots.Analyze(pkgs)
	report.DataFlows = e.dataflow.Trace(pkgs, report.EntryPoints, report.ExternalDeps)

	ga := e.graphAnalyzer.Analyze(pkgs)
	graph, nodes := buildCallGraph(pkgs)
	ga.Layers, ga.LayerSkips = assignLayers(graph, nodes)
	community, _ := detectCommunities(graph, nodes)
	ga.Misplaced = findMisplacedCode(pkgs, community)
	ga.HenryKafura = computeHenryKafura(pkgs)
	ga.DSMPackages, ga.DSMMatrix = buildDSM(pkgs)

	commMap := make(map[int][]string)
	for fn, c := range community {
		commMap[c] = append(commMap[c], fn)
	}
	for id, members := range commMap {
		if len(members) > 1 {
			ga.Communities = append(ga.Communities, domain.CommunityInfo{ID: id, Members: members})
		}
	}

	report.GraphAnalysis = ga
	report.Summary = e.summary.Generate(report, pkgs)
}

func detectProjectLang(pkgs []domain.Package) string {
	for _, pkg := range pkgs {
		for _, fn := range pkg.Functions {
			if strings.HasSuffix(fn.File, ".py") {
				return "python"
			}
			if strings.HasSuffix(fn.File, ".ts") || strings.HasSuffix(fn.File, ".tsx") {
				return "typescript"
			}
		}
	}
	return "go"
}
