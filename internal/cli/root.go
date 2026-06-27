// Package cli wires Cobra commands to the application services. It contains no
// business logic — only flag parsing, container construction and output.
package cli

import (
	"github.com/spf13/cobra"

	"github.com/nandy23/devsecops-cli/internal/cli/output"
	"github.com/nandy23/devsecops-cli/internal/di"
	"github.com/nandy23/devsecops-cli/internal/infra/config"
)

// Options are the global flags shared by all commands.
type Options struct {
	Path       string
	ConfigPath string
	Verbose    bool
	JSON       bool
}

// NewRoot builds the root command tree.
func NewRoot(version string) *cobra.Command {
	opts := &Options{}

	root := &cobra.Command{
		Use:           "devsec",
		Short:         "The Open Source DevSecOps Assistant",
		Long:          "devsec analyzes repositories, audits CI/CD pipelines, recommends security tooling and generates secure pipelines.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&opts.Path, "path", "p", ".", "path to the repository to analyze")
	pf.StringVarP(&opts.ConfigPath, "config", "c", "", "path to a devsec config file (yaml/json)")
	pf.BoolVarP(&opts.Verbose, "verbose", "v", false, "enable verbose logging")
	pf.BoolVar(&opts.JSON, "json", false, "output machine-readable JSON where supported")

	// container is built lazily so commands like `explain` work without a repo.
	build := func() (*di.Container, error) {
		cfg, err := config.Load(opts.ConfigPath)
		if err != nil {
			return nil, err
		}
		return di.Build(cfg, version, output.Logger{Verbose: opts.Verbose})
	}

	root.AddCommand(
		newDetectCmd(opts, build),
		newDoctorCmd(opts, build),
		newScoreCmd(opts, build),
		newInitCmd(opts, build),
		newExplainCmd(opts, build),
		newReportCmd(opts, build),
		newGraphCmd(opts, build),
		newConnectCmd(opts, build),
		newScanCmd(opts, build),
		newToolCmd(opts, build),
		newFixCmd(opts, build),
	)
	return root
}

// containerBuilder lazily constructs the DI container.
type containerBuilder func() (*di.Container, error)
