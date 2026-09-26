package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/benchworkload"
)

type benchmarkCLI struct {
	Plan        planCommand        `cmd:"" help:"Describe one workload and its infrastructure without creating resources."`
	Run         runCommand         `cmd:"" help:"Provision, execute, collect, and clean up an approved Fly benchmark."`
	Cleanup     cleanupCommand     `cmd:"" help:"Remove resources recorded by an interrupted benchmark run."`
	Coordinator coordinatorCommand `cmd:"" help:"Serve workload phase coordination."`
	Publisher   publisherCommand   `cmd:"" help:"Create and hold one shard of benchmark public URLs."`
	Load        loadCommand        `cmd:"" help:"Generate fresh and held visitor requests."`
	Report      reportCommand      `cmd:"" help:"Merge worker results and write report artifacts."`
	Resolver    resolverCommand    `cmd:"" help:"Resolve benchmark hostnames through authoritative DNS."`
}

func main() {
	var commands benchmarkCLI
	parsed := kong.Parse(&commands, kong.Name("tnlbench"), kong.Description("Benchmark a production-candidate tnl server."))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch parsed.Command() {
	case "plan":
		err = commands.Plan.run(os.Stdout)
	case "run":
		err = commands.Run.run(ctx, os.Stdout)
	case "cleanup":
		err = commands.Cleanup.run(ctx, os.Stdout)
	case "coordinator":
		err = commands.Coordinator.run(ctx)
	case "publisher":
		err = commands.Publisher.run(ctx)
	case "load":
		err = commands.Load.run(ctx)
	case "report":
		err = commands.Report.run(os.Stdout)
	case "resolver":
		err = commands.Resolver.run(ctx)
	default:
		panic("unhandled tnlbench command")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: %s: %v\n", parsed.Command(), err)
		os.Exit(1)
	}
}

type workerCommand struct {
	CellID           string        `name:"cell-id" env:"TNL_BENCH_CELL_ID" required:"" help:"Expanded benchmark cell ID."`
	CoordinatorURL   string        `name:"coordinator-url" env:"TNL_BENCH_COORDINATOR_URL" required:"" help:"Coordinator HTTP origin."`
	CoordinatorToken string        `name:"coordinator-token" env:"TNL_BENCH_COORDINATOR_TOKEN" required:"" help:"Coordinator bearer token."`
	WorkerIndex      int           `name:"worker-index" env:"TNL_BENCH_WORKER_INDEX" help:"Zero-based worker index."`
	WorkerCount      int           `name:"worker-count" env:"TNL_BENCH_WORKER_COUNT" required:"" help:"Total workers of this kind."`
	Timeout          time.Duration `name:"timeout" env:"TNL_BENCH_TIMEOUT" default:"30m" help:"Worker deadline."`
}

func (c workerCommand) validate() error {
	if c.Timeout <= 0 {
		return fmt.Errorf("worker deadline must be positive")
	}
	if c.WorkerCount <= 0 || c.WorkerIndex < 0 || c.WorkerIndex >= c.WorkerCount {
		return fmt.Errorf("worker index must identify one configured worker")
	}
	_, err := benchworkload.NewCoordination(c.CoordinatorURL, c.CoordinatorToken)
	return err
}
