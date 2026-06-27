package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newFixCmd(opts *Options, build containerBuilder) *cobra.Command {
	var apply bool
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Propose and optionally apply safe remediations",
		Long: "Plans idempotent fixes (e.g. least-privilege workflow permissions, security-events: write for SARIF " +
			"upload). Previews changes by default; pass --apply to write them.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			actions, err := c.Fix.Plan(cmd.Context(), repo)
			if err != nil {
				return err
			}
			if len(actions) == 0 {
				fmt.Println("Nothing to fix — no safe remediations found.")
				return nil
			}

			fmt.Printf("Proposed fixes (%d):\n", len(actions))
			for _, a := range actions {
				fmt.Printf("  • %s\n    %s\n", a.File, a.Description)
			}
			if !apply {
				fmt.Println("\nRun with --apply to write these changes.")
				return nil
			}
			if err := c.Fix.Apply(repo.Root(), actions); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "\nApplied %d fix(es).\n", len(actions))
			return nil
		},
	}
	cmd.Flags().BoolVar(&apply, "apply", false, "write the proposed changes to disk (default: preview only)")
	return cmd
}
