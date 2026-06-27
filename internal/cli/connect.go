package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newConnectCmd(opts *Options, build containerBuilder) *cobra.Command {
	return &cobra.Command{
		Use:   "connect",
		Short: "Query configured enterprise connectors (e.g. SonarQube)",
		Long: "Runs the Connect → Validate → Collect lifecycle for every enabled connector and prints the collected " +
			"quality gate, metrics and findings. Enable connectors in devsec.yaml or via DEVSEC_SONAR_* env vars.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := build()
			if err != nil {
				return err
			}
			if !c.Connect.Enabled() {
				fmt.Fprintln(os.Stderr, "No connectors configured. Enable one in devsec.yaml or set DEVSEC_SONAR_URL/PROJECT/TOKEN.")
				return nil
			}
			results := c.Connect.Collect(cmd.Context())
			if opts.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(results)
			}
			if len(results) == 0 {
				fmt.Println("No connector results (all connectors failed or returned nothing).")
				return nil
			}
			for _, r := range results {
				fmt.Printf("Connector: %s\n", r.Connector)
				fmt.Printf("  Project:       %s\n", r.Project)
				fmt.Printf("  Quality gate:  %s\n", r.Status)
				if len(r.Metrics) > 0 {
					fmt.Println("  Metrics:")
					for k, v := range r.Metrics {
						fmt.Printf("    %-22s %s\n", k, v)
					}
				}
				if len(r.Covers) > 0 {
					fmt.Printf("  Covers:        %v\n", r.Covers)
				}
				if len(r.Findings) > 0 {
					fmt.Printf("  Findings (%d):\n", len(r.Findings))
					for _, f := range r.Findings {
						fmt.Printf("    ✗ [%s] %s\n", f.Severity, f.Message)
					}
				}
				fmt.Println()
			}
			return nil
		},
	}
}
