package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
)

func newConfigCmd(opts *Options, build containerBuilder) *cobra.Command {
	var dryRun, force bool
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Generate scanner configuration files for the detected stack",
		Long: "Detects the stack and generates ready-to-use scanner config files " +
			"(sonar-project.properties, trivy.yaml, .gitleaks.toml, .checkov.yaml, " +
			"syft.yaml, .hadolint.yaml, .ansible-lint). Existing files are skipped " +
			"unless --force is given. Secrets are never written — pass tokens at scan time.",
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
			files := c.ConfigGen.Generate(a)
			if len(files) == 0 {
				fmt.Println("no applicable scanner configs for the detected stack")
				return nil
			}

			// Deterministic output order.
			paths := make([]string, 0, len(files))
			for p := range files {
				paths = append(paths, p)
			}
			sort.Strings(paths)

			for _, rel := range paths {
				content := files[rel]
				dest := filepath.Join(opts.Path, rel)
				if dryRun {
					fmt.Printf("# ---- %s ----\n%s\n", dest, content)
					continue
				}
				if _, err := os.Stat(dest); err == nil && !force {
					fmt.Printf("skip  %s (exists; use --force to overwrite)\n", dest)
					continue
				}
				if err := os.WriteFile(dest, []byte(content), 0o644); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", dest)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print generated configs instead of writing them")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing config files")
	return cmd
}
