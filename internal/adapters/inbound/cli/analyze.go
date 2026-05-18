package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/berkantay/slop0/internal/application/ports/inbound"
	"github.com/berkantay/slop0/internal/application/ports/outbound"
	"github.com/spf13/cobra"
)

var ErrUnknownFormat = errors.New("unknown output format")

type analyzeFlags struct {
	focus         string
	depth         int
	format        string
	pkgFilter     string
	rulesOnly     bool
	structureOnly bool
	configPath    string
}

func (f *analyzeFlags) toOpts(args []string) inbound.AnalyzeOpts {
	patterns := args
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}

	var pkgFilterSlice []string
	if f.pkgFilter != "" {
		pkgFilterSlice = strings.Split(f.pkgFilter, ",")
	}

	return inbound.AnalyzeOpts{
		Patterns:      patterns,
		Focus:         f.focus,
		Depth:         f.depth,
		RulesOnly:     f.rulesOnly,
		StructureOnly: f.structureOnly,
		Format:        f.format,
		ConfigPath:    f.configPath,
		PkgFilter:     pkgFilterSlice,
	}
}

func newAnalyzeCommand(analyzer inbound.AnalyzePort, renderers map[string]outbound.RendererPort) *cobra.Command {
	f := &analyzeFlags{}

	cmd := &cobra.Command{
		Use:   "analyze [path...]",
		Short: "Analyze codebase and output dependency map",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAnalyze(analyzer, renderers, f, args)
		},
	}

	cmd.Flags().StringVar(&f.focus, "focus", "", "center map on a symbol")
	cmd.Flags().IntVar(&f.depth, "depth", 0, "limit transitive dependency depth")
	cmd.Flags().StringVar(&f.format, "format", "compact", "output format: compact, json")
	cmd.Flags().StringVar(&f.pkgFilter, "pkg", "", "filter to specific packages (comma-separated)")
	cmd.Flags().BoolVar(&f.rulesOnly, "rules-only", false, "skip structure, show only violations")
	cmd.Flags().BoolVar(&f.structureOnly, "structure-only", false, "skip rules, show only structure")
	cmd.Flags().StringVar(&f.configPath, "config", "", "path to .slop0.yaml")

	return cmd
}

func runAnalyze(analyzer inbound.AnalyzePort, renderers map[string]outbound.RendererPort, f *analyzeFlags, args []string) error {
	report, err := analyzer.Execute(f.toOpts(args))
	if err != nil {
		return err
	}

	renderer, ok := renderers[f.format]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownFormat, f.format)
	}

	output, err := renderer.Render(report)
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stdout, output)
	return nil
}
