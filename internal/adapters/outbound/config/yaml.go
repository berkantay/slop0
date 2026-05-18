package config

import (
	"os"

	"gopkg.in/yaml.v3"

	"github.com/berkantay/slop0/internal/domain"
)

type YAMLLoader struct{}

func NewYAMLLoader() *YAMLLoader {
	return &YAMLLoader{}
}

type yamlConfig struct {
	Layers     []yamlLayer       `yaml:"layers"`
	Thresholds yamlThresholds    `yaml:"thresholds"`
	Rules      map[string]any    `yaml:"rules"`
}

type yamlLayer struct {
	Name        string   `yaml:"name"`
	Packages    []string `yaml:"packages"`
	AllowedDeps []string `yaml:"allowed_deps"`
}

type yamlThresholds struct {
	DupASTMinNodes       int     `yaml:"dup_ast_min_nodes"`
	DupCallGraphMinCalls int     `yaml:"dup_callgraph_min_calls"`
	DupSimilarity        float64 `yaml:"dup_similarity"`
	PatternDominance     float64 `yaml:"pattern_dominance"`
	PatternMinSamples    int     `yaml:"pattern_min_samples"`
	MaxParams               int     `yaml:"max_params"`
	MaxReturns              int     `yaml:"max_returns"`
	MaxMethodsPerType       int     `yaml:"max_methods_per_type"`
	FuncMaxLines            int     `yaml:"func_max_lines"`
	MaxCognitiveComplexity  int     `yaml:"max_cognitive_complexity"`
	MaxCyclomaticComplexity int     `yaml:"max_cyclomatic_complexity"`
}

func (l *YAMLLoader) Load(path string) (*domain.RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg yamlConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	rc := &domain.RuleConfig{
		Rules: cfg.Rules,
		Thresholds: domain.Thresholds{
			DupASTMinNodes:       cfg.Thresholds.DupASTMinNodes,
			DupCallGraphMinCalls: cfg.Thresholds.DupCallGraphMinCalls,
			DupSimilarity:        cfg.Thresholds.DupSimilarity,
			PatternDominance:     cfg.Thresholds.PatternDominance,
			PatternMinSamples:    cfg.Thresholds.PatternMinSamples,
			MaxParams:               cfg.Thresholds.MaxParams,
			MaxReturns:              cfg.Thresholds.MaxReturns,
			MaxMethodsPerType:       cfg.Thresholds.MaxMethodsPerType,
			FuncMaxLines:            cfg.Thresholds.FuncMaxLines,
			MaxCognitiveComplexity:  cfg.Thresholds.MaxCognitiveComplexity,
			MaxCyclomaticComplexity: cfg.Thresholds.MaxCyclomaticComplexity,
		},
	}

	for _, layer := range cfg.Layers {
		rc.Layers = append(rc.Layers, domain.LayerDef{
			Name:        layer.Name,
			Packages:    layer.Packages,
			AllowedDeps: layer.AllowedDeps,
		})
	}

	return rc, nil
}
