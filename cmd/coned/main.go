package main

import (
	"os"

	"github.com/zzwong/coned-cli/internal/cli"
)

func main() {
	if err := cli.NewRootCommand(os.Stdin, os.Stdout, os.Stderr).Execute(); err != nil {
		os.Exit(1)
	}
}
