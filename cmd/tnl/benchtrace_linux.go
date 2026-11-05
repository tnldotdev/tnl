//go:build tnl_benchtrace && linux

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/tnldotdev/tnl/internal/observability/runtimetrace"
)

func init() {
	args, directory, enabled, err := runtimetrace.ConsumeArgs(os.Args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid fixture-only native trace flags")
		os.Exit(2)
	}
	if !enabled {
		return
	}
	os.Args = args
	commands, commandErr := runtimetrace.OpenPipeFD(3, "native-trace-commands")
	replies, replyErr := runtimetrace.OpenPipeFD(4, "native-trace-replies")
	if commandErr != nil || replyErr != nil {
		fmt.Fprintln(os.Stderr, "fixture-only native trace pipes unavailable")
		os.Exit(2)
	}
	go func() { _ = runtimetrace.Run(context.Background(), commands, replies, directory) }()
}
