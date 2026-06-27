package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/nandy23/devsecops-cli/internal/cli/output"
)

func newDoctorCmd(opts *Options, build containerBuilder) *cobra.Command {
	var minScore int
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Audit existing CI/CD pipelines and report gaps",
		Long:  "Audits GitHub Actions, GitLab CI, Azure DevOps and Jenkins pipelines for missing security stages.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			a, err := c.Doctor.Run(cmd.Context(), repo)
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
				return enc.Encode(map[string]any{"analysis": a, "score": score})
			}
			output.Technologies(os.Stdout, a)
			output.Findings(os.Stdout, a)
			output.Scans(os.Stdout, a)
			output.Score(os.Stdout, score)
			if minScore > 0 && score.Total < minScore {
				return errBelowThreshold{got: score.Total, want: minScore}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&minScore, "min-score", 0, "fail with exit code 2 if score is below this threshold")
	return cmd
}
