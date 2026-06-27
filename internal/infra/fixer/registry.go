package fixer

import "github.com/nandy23/devsecops-cli/internal/domain/port"

// Builtin returns the default set of fixers.
func Builtin() []port.Fixer {
	return []port.Fixer{
		GitHubActions{},
	}
}
