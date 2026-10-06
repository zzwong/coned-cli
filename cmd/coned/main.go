package main

import (
	"io"
	"os"

	"github.com/zzwong/coned-cli/internal/cli"
	"github.com/zzwong/coned-cli/internal/config"
)

func main() {
	if code := execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, productionDependencies()); code != 0 {
		os.Exit(code)
	}
}

// productionDependencies retains the default configuration path when the
// production entry point uses the versioned execution wrapper.
func productionDependencies() cli.Dependencies {
	return cli.Dependencies{ConfigPath: config.DefaultPath()}
}

// execute is shared by main and its config-loading regression test so the test
// exercises the same command entry path as the built executable.
func execute(args []string, stdin io.Reader, stdout, stderr io.Writer, deps cli.Dependencies) int {
	return cli.ExecuteCLI(args, stdin, stdout, stderr, deps)
}
