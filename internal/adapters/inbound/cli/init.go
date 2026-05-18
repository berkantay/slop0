package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var ErrConfigExists = errors.New(".slop0.yaml already exists")

const defaultConfig = `layers:
  - name: handler
    packages: ["./internal/handler/..."]
    allowed_deps: ["service"]
  - name: service
    packages: ["./internal/service/..."]
    allowed_deps: ["repo", "model"]
  - name: repo
    packages: ["./internal/repo/..."]
    allowed_deps: ["model"]

thresholds:
  # minimum AST nodes for two functions to be flagged as duplicates
  dup_ast_min_nodes: 25
  # minimum outgoing calls for call-graph duplication detection
  dup_callgraph_min_calls: 3
  # jaccard similarity threshold for call-graph duplicates (0.0 - 1.0)
  dup_similarity: 0.7
  # ratio of dominant pattern to total before flagging violations (0.0 - 1.0)
  pattern_dominance: 0.5
  # minimum samples before inferring a dominant pattern
  pattern_min_samples: 3
  # max function parameters before suggesting options struct
  max_params: 5
  # max return values before flagging
  max_returns: 3
  # max methods on a single type before flagging god object
  max_methods_per_type: 15
  # max lines in a function body before suggesting split
  func_max_lines: 60

rules:
  no-circular-deps: true
  error-wrapping: required
`

func newInitCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a .slop0.yaml config template",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(".slop0.yaml"); err == nil {
				return fmt.Errorf("%w", ErrConfigExists)
			}

			if err := os.WriteFile(".slop0.yaml", []byte(defaultConfig), 0644); err != nil {
				return err
			}

			fmt.Println("created .slop0.yaml")
			return nil
		},
	}
}
