package cli

import "fmt"

// errBelowThreshold signals a policy-gate failure (exit code 2).
type errBelowThreshold struct {
	got, want int
}

func (e errBelowThreshold) Error() string {
	return fmt.Sprintf("security score %d is below the required threshold of %d", e.got, e.want)
}

// errExitCode propagates a wrapped tool's exit code through `devsec tool`.
type errExitCode struct{ code int }

func (e errExitCode) Error() string {
	return fmt.Sprintf("tool exited with code %d", e.code)
}

// ExitCode maps an error to a process exit code. 0 success, 2 policy failure,
// a wrapped tool's own code for `tool`, 1 any other error.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if _, ok := err.(errBelowThreshold); ok {
		return 2
	}
	if e, ok := err.(errExitCode); ok {
		return e.code
	}
	return 1
}
