package cli

import (
	"encoding/json"
	"os"

	"github.com/spf13/cobra"

	"github.com/nandy23/devsecops-cli/internal/cli/output"
)

func newDetectCmd(opts *Options, build containerBuilder) *cobra.Command {
	return &cobra.Command{
		Use:   "detect",
		Short: "Analyze a repository and detect technologies",
		Long:  "Detects languages, frameworks, containers, IaC and CI platforms, then prints recommendations.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			a, err := c.Detect.Run(cmd.Context(), repo)
			if err != nil {
				return err
			}
			if opts.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(a)
			}
			output.Technologies(os.Stdout, a)
			output.Recommendations(os.Stdout, a)
			return nil
		},
	}
}
