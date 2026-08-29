package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/state"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tnld: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := config.ParseTNLD(args)
	if err != nil {
		return err
	}
	db, err := state.Open(ctx, cfg.StateDir)
	if err != nil {
		return err
	}
	<-ctx.Done()
	if err := db.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	return nil
}
