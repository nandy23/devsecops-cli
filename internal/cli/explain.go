package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func newExplainCmd(opts *Options, build containerBuilder) *cobra.Command {
	return &cobra.Command{
		Use:   "explain [tool]",
		Short: "Explain why a security tool is recommended",
		Long:  "Returns the purpose, advantages, when-to-use, alternatives and pipeline stage for a tool. Run without arguments to list all known tools.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				tools, err := c.Explain.List(cmd.Context())
				if err != nil {
					return err
				}
				fmt.Println("Known tools (use `devsec explain <tool>`):")
				for _, t := range tools {
					fmt.Printf("  %-12s %-14s %s\n", t.Name, t.Category, t.Purpose)
				}
				return nil
			}
			t, err := c.Explain.Explain(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if opts.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(t)
			}
			fmt.Printf("%s  (%s)\n\n", strings.ToUpper(t.Name), t.Category)
			fmt.Printf("Purpose\n  %s\n\n", t.Purpose)
			fmt.Println("Advantages")
			for _, a := range t.Advantages {
				fmt.Printf("  • %s\n", a)
			}
			fmt.Printf("\nWhen to use\n  %s\n\n", t.WhenToUse)
			fmt.Printf("Pipeline stage\n  %s\n\n", t.Stage)
			fmt.Printf("Alternatives\n  %s\n\n", strings.Join(t.Alternatives, ", "))
			fmt.Printf("License: %s\n", t.License)
			for _, l := range t.Links {
				fmt.Printf("Docs: %s\n", l)
			}
			return nil
		},
	}
}
