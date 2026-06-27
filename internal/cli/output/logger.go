// Package output holds CLI presentation helpers: logging and human-readable
// writers. It is the only place that touches stdout/stderr formatting.
package output

import (
	"fmt"
	"os"
)

// Logger is a minimal leveled logger writing to stderr.
type Logger struct {
	Verbose bool
}

func (l Logger) Debugf(format string, args ...any) {
	if l.Verbose {
		fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...)
	}
}
func (l Logger) Infof(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
func (l Logger) Warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "WARN: "+format+"\n", args...)
}
func (l Logger) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
}
