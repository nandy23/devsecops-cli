package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newGraphCmd(opts *Options, build containerBuilder) *cobra.Command {
	return &cobra.Command{
		Use:   "graph",
		Short: "Render the recommended pipeline as a Mermaid diagram",
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
			diagram, err := c.Graph.Render(cmd.Context(), a)
			if err != nil {
				return err
			}
			fmt.Println("```mermaid")
			fmt.Print(diagram)
			fmt.Println("```")
			return nil
		},
	}
}
