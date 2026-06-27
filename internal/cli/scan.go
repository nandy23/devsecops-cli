package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nandy23/devsecops-cli/internal/cli/output"
)

func newScanCmd(opts *Options, build containerBuilder) *cobra.Command {
	var tools string
	var minScore int
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run locally-installed scanners and ingest their results",
		Long: "Runs the security scanners you already have installed (gitleaks, semgrep, snyk, trivy, checkov), " +
			"then ingests their reports into the unified score and report. devsec runs tools it does not bundle: " +
			"missing scanners are skipped, not installed for you.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			var only []string
			if tools != "" {
				only = strings.Split(tools, ",")
			}
			a, outcomes, err := c.Scan.Run(cmd.Context(), repo, only)
			if err != nil {
				return err
			}
			score, err := c.Score.Run(cmd.Context(), a)
			if err != nil {
				return err
			}
			if opts.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"outcomes": outcomes, "analysis": a, "score": score})
			}

			fmt.Println("Scanner runs:")
			for _, o := range outcomes {
				switch o.Status {
				case "ran":
					fmt.Printf("  ✓ %-10s ran (exit %d)\n", o.Tool, o.ExitCode)
				case "skipped":
					fmt.Printf("  – %-10s skipped (%s)\n", o.Tool, o.Detail)
				default:
					fmt.Printf("  ✗ %-10s error: %s\n", o.Tool, o.Detail)
				}
			}
			output.Scans(os.Stdout, a)
			output.Score(os.Stdout, score)
			if minScore > 0 && score.Total < minScore {
				return errBelowThreshold{got: score.Total, want: minScore}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tools, "tools", "", "comma-separated subset of scanners to run (default: all available)")
	cmd.Flags().IntVar(&minScore, "min-score", 0, "fail with exit code 2 if score is below this threshold")
	return cmd
}
