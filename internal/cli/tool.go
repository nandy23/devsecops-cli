package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newToolCmd(_ *Options, build containerBuilder) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tool <name> [-- args...]",
		Short: "Run an allow-listed external tool with devsec config injected",
		Long: "Thin passthrough to a locally-installed CLI (e.g. vault, sonar-scanner, trivy), with configuration " +
			"such as Vault address or SonarQube host injected from devsec config. Use `--` to separate the tool's " +
			"own flags. devsec runs tools it does not bundle.\n\nExample:\n  devsec tool vault -- status\n  devsec tool trivy -- image alpine:3",
		// Pass the tool's own flags through untouched.
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
				c, err := build()
				if err == nil {
					fmt.Println("Allow-listed tools:", c.Tool.Allowed())
				}
				return cmd.Help()
			}
			c, err := build()
			if err != nil {
				return err
			}
			name := args[0]
			passArgs := args[1:]
			if len(passArgs) > 0 && passArgs[0] == "--" {
				passArgs = passArgs[1:]
			}
			code, err := c.Tool.Run(cmd.Context(), name, passArgs, os.Stdin, os.Stdout, os.Stderr)
			if err != nil {
				return err
			}
			if code != 0 {
				return errExitCode{code: code}
			}
			return nil
		},
	}
	return cmd
}
