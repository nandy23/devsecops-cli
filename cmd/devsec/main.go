// Command devsec is the Open Source DevSecOps Assistant CLI.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/nandy23/devsecops-cli/internal/cli"
)

// version is overridden at build time via -ldflags.
var version = "0.1.0-dev"

func main() {
	root := cli.NewRoot(version)
	err := root.ExecuteContext(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "devsec: "+err.Error())
	}
	os.Exit(cli.ExitCode(err))
}
