// Package exec implements port.CommandRunner over os/exec. It is the single
// place in devsec allowed to spawn external processes. devsec runs tools that
// the user already installed; it never bundles or downloads binaries.
package exec

import (
	"context"
	"io"
	"os"
	"os/exec"

	"github.com/nandy23/devsecops-cli/internal/domain/port"
)

// Runner is the default CommandRunner backed by the host PATH.
type Runner struct{}

// New returns an exec-backed runner.
func New() Runner { return Runner{} }

// Look resolves a binary on PATH.
func (Runner) Look(bin string) (string, bool) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return "", false
	}
	return path, true
}

// Run executes the command. A non-zero exit status is returned in the result
// (not as an error) so callers can distinguish "tool found issues" from "tool
// failed to start".
func (Runner) Run(ctx context.Context, c port.Command) (port.CommandResult, error) {
	cmd := exec.CommandContext(ctx, c.Bin, c.Args...)
	cmd.Dir = c.Dir
	if len(c.Env) > 0 {
		cmd.Env = append(os.Environ(), c.Env...)
	}
	cmd.Stdin = c.Stdin
	cmd.Stdout = orDiscard(c.Stdout)
	cmd.Stderr = orDiscard(c.Stderr)

	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return port.CommandResult{ExitCode: exitErr.ExitCode()}, nil
	}
	if err != nil {
		return port.CommandResult{ExitCode: -1}, err
	}
	return port.CommandResult{ExitCode: 0}, nil
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
