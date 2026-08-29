package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xcadams/tnl/internal/config"
	"github.com/0xcadams/tnl/internal/observability"
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
	closeState := func() error { return nil }
	if cfg.Mode.UsesState() {
		db, err := state.Open(ctx, cfg.StateDir)
		if err != nil {
			return err
		}
		closeState = func() error {
			if err := db.Close(); err != nil {
				return fmt.Errorf("close state: %w", err)
			}
			return nil
		}
	}

	metrics := observability.New(string(cfg.Mode))
	var metricsServer *observability.Server
	if cfg.MetricsListen != "" {
		metricsServer, err = observability.Listen(cfg.MetricsListen, metrics.Handler())
		if err != nil {
			return errors.Join(fmt.Errorf("listen for metrics: %w", err), closeState())
		}
	}

	var serveErr error
	if metricsServer == nil {
		<-ctx.Done()
	} else {
		select {
		case <-ctx.Done():
		case serveErr = <-metricsServer.Done():
			if serveErr != nil {
				serveErr = fmt.Errorf("serve metrics: %w", serveErr)
			}
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		serveErr = errors.Join(serveErr, metricsServer.Shutdown(shutdownCtx))
		cancel()
	}
	return errors.Join(serveErr, closeState())
}
