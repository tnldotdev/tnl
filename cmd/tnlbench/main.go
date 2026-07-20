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
	Plan        planCommand        `cmd:"" help:"Expand and price a benchmark suite without creating resources."`
	Coordinator coordinatorCommand `cmd:"" help:"Coordinate one benchmark cell."`
	Publisher   publisherCommand   `cmd:"" help:"Create and hold one shard of benchmark routes."`
	Load        loadCommand        `cmd:"" help:"Generate visitor load for one benchmark cell."`
	Report      reportCommand      `cmd:"" help:"Merge worker results and write report artifacts."`
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
	case "coordinator":
		err = commands.Coordinator.run(ctx)
	case "publisher":
		err = commands.Publisher.run(ctx)
	case "load":
		err = commands.Load.run(ctx)
	case "report":
		err = commands.Report.run(os.Stdout)
	default:
		panic("unhandled tnlbench command")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tnlbench: %s: %v\n", parsed.Command(), err)
		os.Exit(1)
	}
}

type workerCommand struct {
	CellID           string `name:"cell-id" env:"TNL_BENCH_CELL_ID" required:"" help:"Expanded benchmark cell ID."`
	Suite            string `name:"suite" env:"TNL_BENCH_SUITE" required:"" help:"Benchmark suite name."`
	Repetition       int    `name:"repetition" env:"TNL_BENCH_REPETITION" required:"" help:"One-based repetition."`
	CoordinatorURL   string `name:"coordinator-url" env:"TNL_BENCH_COORDINATOR_URL" required:"" help:"Coordinator HTTP origin."`
	CoordinatorToken string `name:"coordinator-token" env:"TNL_BENCH_COORDINATOR_TOKEN" required:"" help:"Coordinator bearer token."`
	WorkerIndex      int    `name:"worker-index" env:"TNL_BENCH_WORKER_INDEX" help:"Zero-based worker index."`
	WorkerCount      int    `name:"worker-count" env:"TNL_BENCH_WORKER_COUNT" required:"" help:"Total workers of this kind."`
	Sequence         int    `name:"sequence" env:"TNL_BENCH_SEQUENCE" help:"Zero-based suite cell sequence."`
}

func (c workerCommand) validate() error {
	if c.Repetition <= 0 {
		return fmt.Errorf("repetition must be positive")
	}
	if c.WorkerCount <= 0 || c.WorkerIndex < 0 || c.WorkerIndex >= c.WorkerCount {
		return fmt.Errorf("worker index must identify one configured worker")
	}
	if c.Sequence < 0 {
		return fmt.Errorf("cell sequence must not be negative")
	}
	_, err := newCoordinatorClient(c.CoordinatorURL, c.CoordinatorToken)
	return err
}
