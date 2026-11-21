package main

import (
	"io"

	"github.com/spf13/cobra"
)

// parse the production command tree without starting the selected operation.
func commandForTest(flags *cli, out io.Writer) func([]string) (*cobra.Command, error) {
	return func(args []string) (*cobra.Command, error) {
		*flags = cli{}
		root := (&commandApp{flags: flags, out: out, errOut: io.Discard}).root()
		var visit func(*cobra.Command)
		visit = func(cmd *cobra.Command) {
			if !cmd.HasSubCommands() || cmd.Annotations["default"] != "" {
				cmd.RunE = func(*cobra.Command, []string) error { return nil }
			}
			for _, child := range cmd.Commands() {
				visit(child)
			}
		}
		visit(root)
		root.SetArgs(args)
		return root.ExecuteC()
	}
}
