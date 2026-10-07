package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
)

type benchmarkCLI struct {
	Plan   planCommand   `cmd:"" help:"Describe a deployed workload without making changes."`
	Run    runCommand    `cmd:"" help:"Run an approved local workload against a tnl server."`
	Report reportCommand `cmd:"" help:"Show the results of a deployed workload."`
}

func main() {
	var commands benchmarkCLI
	parser, err := kong.New(&commands, kong.Name("tnlbench"), kong.Description("Measure a tnl server from a local publisher and visitor."))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tnlbench:", failure.SafeMessage(err, failure.BenchmarkInputInvalid))
		os.Exit(1)
	}
	parsed, err := parser.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "tnlbench:", failure.SafeMessage(err, failure.BenchmarkInputInvalid))
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = nil
	switch parsed.Command() {
	case "plan":
		err = commands.Plan.run(os.Stdout)
	case "run":
		err = commands.Run.run(ctx, os.Stdout, os.Stderr)
	case "report":
		err = commands.Report.run(os.Stdout)
	}
	if err != nil {
		reason := failure.BenchmarkMeasurementFailed
		if parsed.Command() == "plan" {
			reason = failure.BenchmarkInputInvalid
		}
		fmt.Fprintf(os.Stderr, "tnlbench: %s: %s\n", parsed.Command(), failure.SafeMessage(err, reason))
		os.Exit(1)
	}
}
