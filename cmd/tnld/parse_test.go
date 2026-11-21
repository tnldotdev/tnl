package main

import (
	"io"

	"github.com/spf13/cobra"
)

func parseServerForTest(flags *tnldCLI, out io.Writer) func([]string) (*cobra.Command, error) {
	root := newServerCommand(flags, out)
	for _, cmd := range root.Commands() {
		if cmd.Name() == "serve" {
			cmd.RunE = func(*cobra.Command, []string) error { return nil }
		}
	}
	return func(args []string) (*cobra.Command, error) { root.SetArgs(args); return root.ExecuteC() }
}
