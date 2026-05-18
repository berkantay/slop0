package cli

import (
	"github.com/berkantay/slop0/internal/application/ports/inbound"
	"github.com/berkantay/slop0/internal/application/ports/outbound"
	"github.com/spf13/cobra"
)

func NewRootCommand(analyzer inbound.AnalyzePort, renderers map[string]outbound.RendererPort) *cobra.Command {
	analyzeCmd := newAnalyzeCommand(analyzer, renderers)

	root := &cobra.Command{
		Use:                "slop0 [path...]",
		Short:              "Code intelligence maps for humans and LLMs",
		Long:               "Analyze Go codebases and output token-efficient dependency maps with architectural violation detection.",
		RunE:               analyzeCmd.RunE,
		DisableFlagParsing: false,
	}

	root.Flags().AddFlagSet(analyzeCmd.Flags())
	root.AddCommand(analyzeCmd)
	root.AddCommand(newInitCommand())

	root.SilenceUsage = true
	root.SilenceErrors = true

	return root
}
