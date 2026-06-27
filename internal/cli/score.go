package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/nandy23/devsecops-cli/internal/cli/output"
)

func newScoreCmd(opts *Options, build containerBuilder) *cobra.Command {
	var minScore int
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Output the security maturity score (0-100)",
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
			s, err := c.Score.Run(cmd.Context(), a)
			if err != nil {
				return err
			}
			if opts.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(s)
			}
			output.Score(os.Stdout, s)
			if minScore > 0 && s.Total < minScore {
				return errBelowThreshold{got: s.Total, want: minScore}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&minScore, "min-score", 0, "fail with exit code 2 if score is below this threshold")
	return cmd
}
