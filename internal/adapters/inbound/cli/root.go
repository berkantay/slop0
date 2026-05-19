package cli

import (
	"github.com/berkantay/slop0/internal/adapters/outbound/python"
	"github.com/berkantay/slop0/internal/application/ports/inbound"
	"github.com/berkantay/slop0/internal/application/ports/outbound"
	"github.com/spf13/cobra"
)

type AnalyzerBuilder func(lang string) inbound.AnalyzePort

func NewRootCommand(analyzer inbound.AnalyzePort, renderers map[string]outbound.RendererPort) *cobra.Command {
	return NewRootCommandWithLang(func(_ string) inbound.AnalyzePort { return analyzer }, renderers)
}

func NewRootCommandWithLang(builder AnalyzerBuilder, renderers map[string]outbound.RendererPort) *cobra.Command {
	var lang string

	analyzeCmd := newAnalyzeCommandWithLang(builder, renderers, &lang)

	root := &cobra.Command{
		Use:                "slop0 [path...]",
		Short:              "Code intelligence for humans and LLMs",
		Long:               "Analyze Go and Python codebases — structure, violations, patterns, metrics.",
		RunE:               analyzeCmd.RunE,
		DisableFlagParsing: false,
	}

	root.PersistentFlags().StringVar(&lang, "lang", "", "language: go, python (auto-detect if empty)")
	root.Flags().AddFlagSet(analyzeCmd.Flags())
	root.AddCommand(analyzeCmd)
	root.AddCommand(newInitCommand())

	root.SilenceUsage = true
	root.SilenceErrors = true

	return root
}

func resolveLang(lang, dir string) string {
	if lang != "" {
		return lang
	}
	return python.DetectLanguage(dir)
}
