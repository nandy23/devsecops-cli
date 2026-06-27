package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newInitCmd(opts *Options, build containerBuilder) *cobra.Command {
	var platform string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a secure CI/CD pipeline for the detected stack",
		Long:  "Detects the stack, builds a recommended secure pipeline and writes platform-specific CI files.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			if platform == "" {
				platform = c.Config.Generate.Platform
			}
			repo, err := c.OpenRepo(opts.Path)
			if err != nil {
				return err
			}
			a, err := c.Detect.Run(cmd.Context(), repo)
			if err != nil {
				return err
			}
			files, _, err := c.Generate.Generate(cmd.Context(), a, platform)
			if err != nil {
				return err
			}
			for rel, content := range files {
				dest := filepath.Join(opts.Path, rel)
				if dryRun {
					fmt.Printf("# ---- %s ----\n%s\n", dest, content)
					continue
				}
				if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", dest)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platform, "platform", "", "target platform: github | gitlab | azure | jenkins (default from config)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print generated files instead of writing them")
	return cmd
}
