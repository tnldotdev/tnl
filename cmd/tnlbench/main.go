package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
)

type benchmarkCLI struct {
	Plan   planCommand   `cmd:"" help:"Describe a deployed workload without making changes."`
	Run    runCommand    `cmd:"" help:"Run an approved local workload against a tnl server."`
	Report reportCommand `cmd:"" help:"Show the results of a deployed workload."`
}

func main() {
	var commands benchmarkCLI
	parsed := kong.Parse(&commands, kong.Name("tnlbench"), kong.Description("Measure a tnl server from a local publisher and visitor."))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch parsed.Command() {
	case "plan":
		err = commands.Plan.run(os.Stdout)
	case "run":
		err = commands.Run.run(ctx, os.Stdout, os.Stderr)
	case "report":
		err = commands.Report.run(os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: %s: %v\n", parsed.Command(), err)
		os.Exit(1)
	}
}
