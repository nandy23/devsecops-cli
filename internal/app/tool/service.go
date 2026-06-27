// Package tool implements `devsec tool <name> -- <args>`: a thin, safe
// passthrough that runs an allow-listed external CLI, injecting configuration
// (e.g. Vault address, SonarQube host) from devsec config. devsec never bundles
// the tool; it must already be installed.
package tool

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Spec is an allow-listed tool: the binary to run plus any environment to
// inject from configuration.
type Spec struct {
	Bin string
	Env []string // KEY=VAL entries
}

// Service runs allow-listed external tools.
type Service struct {
	runner port.CommandRunner
	specs  map[string]Spec
}

// New builds the tool service from an allow-list keyed by tool name.
func New(runner port.CommandRunner, specs map[string]Spec) *Service {
	return &Service{runner: runner, specs: specs}
}

// Allowed returns the sorted list of permitted tool names.
func (s *Service) Allowed() []string {
	names := make([]string, 0, len(s.specs))
	for n := range s.specs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Run executes the named tool with passthrough args and streams. It returns the
// tool's exit code. An unknown tool or a missing binary is an error.
func (s *Service) Run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	spec, ok := s.specs[name]
	if !ok {
		return 1, fmt.Errorf("tool %q is not allow-listed (allowed: %v)", name, s.Allowed())
	}
	binPath, ok := s.runner.Look(spec.Bin)
	if !ok {
		return 1, fmt.Errorf("%s is not installed (devsec runs tools, it does not bundle them)", spec.Bin)
	}
	res, err := s.runner.Run(ctx, port.Command{
		Bin: binPath, Args: args, Env: spec.Env,
		Stdin: stdin, Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		return 1, err
	}
	return res.ExitCode, nil
}
