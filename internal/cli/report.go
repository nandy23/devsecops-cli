package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func newReportCmd(opts *Options, build containerBuilder) *cobra.Command {
	var format, outPath string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a security report (markdown | html | json | sarif)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			if format == "" {
				format = c.Config.Report.Format
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			a, err := c.Doctor.Run(cmd.Context(), repo)
			if err != nil {
				return err
			}
			var w io.Writer = os.Stdout
			if outPath != "" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			if err := c.Report.Render(cmd.Context(), a, format, w); err != nil {
				return err
			}
			if outPath != "" {
				fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", format, outPath)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "", "report format: markdown | html | json | sarif")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "write the report to a file instead of stdout")
	return cmd
}
