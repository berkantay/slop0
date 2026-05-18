package domain

type RuleConfig struct {
	Layers     []LayerDef
	Thresholds Thresholds
	Rules      map[string]any
}

type LayerDef struct {
	Name        string
	Packages    []string
	AllowedDeps []string
}

type Thresholds struct {
	DupASTMinNodes       int     // minimum AST nodes to consider for duplication (default: 25)
	DupCallGraphMinCalls int     // minimum outgoing calls for call-graph duplication (default: 3)
	DupSimilarity        float64 // jaccard similarity threshold for call-graph dups (default: 0.7)
	PatternDominance     float64 // ratio threshold to flag pattern violations (default: 0.5)
	PatternMinSamples    int     // minimum samples before inferring patterns (default: 3)
	MaxParams            int     // max function parameters before flagging (default: 5)
	MaxReturns           int     // max return values before flagging (default: 3)
	MaxMethodsPerType    int     // max methods on a single type (default: 15)
	FuncMaxLines         int     // max lines in a function body (default: 60)
	MaxCognitiveComplexity  int  // max cognitive complexity per function (default: 15)
	MaxCyclomaticComplexity int  // max cyclomatic complexity per function (default: 10)
	MaxMapLiteralKeys       int  // max keys in map[string]any literal before suggesting struct (default: 3)
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		DupASTMinNodes:       25,
		DupCallGraphMinCalls: 3,
		DupSimilarity:        0.7,
		PatternDominance:     0.5,
		PatternMinSamples:    3,
		MaxParams:            5,
		MaxReturns:           2,
		MaxMethodsPerType:       15,
		FuncMaxLines:            60,
		MaxCognitiveComplexity:  15,
		MaxCyclomaticComplexity: 10,
		MaxMapLiteralKeys:       3,
	}
}

func (t Thresholds) Merge(other Thresholds) Thresholds {
	mergeInt(&t.DupASTMinNodes, other.DupASTMinNodes)
	mergeInt(&t.DupCallGraphMinCalls, other.DupCallGraphMinCalls)
	mergeFloat(&t.DupSimilarity, other.DupSimilarity)
	mergeFloat(&t.PatternDominance, other.PatternDominance)
	mergeInt(&t.PatternMinSamples, other.PatternMinSamples)
	mergeInt(&t.MaxParams, other.MaxParams)
	mergeInt(&t.MaxReturns, other.MaxReturns)
	mergeInt(&t.MaxMethodsPerType, other.MaxMethodsPerType)
	mergeInt(&t.FuncMaxLines, other.FuncMaxLines)
	mergeInt(&t.MaxCognitiveComplexity, other.MaxCognitiveComplexity)
	mergeInt(&t.MaxCyclomaticComplexity, other.MaxCyclomaticComplexity)
	mergeInt(&t.MaxMapLiteralKeys, other.MaxMapLiteralKeys)
	return t
}

func mergeInt(dst *int, src int) {
	if src > 0 {
		*dst = src
	}
}

func mergeFloat(dst *float64, src float64) {
	if src > 0 {
		*dst = src
	}
}
