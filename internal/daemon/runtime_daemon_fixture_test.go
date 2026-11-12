package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRuntimeTopologyDaemonExplicitStopConsumesAcceptedDeadline(t *testing.T) {
	var shutdowns int
	t.Run("topology", func(t *testing.T) {
		owner := newRuntimeTopology(t)
		process := &daemon{controlListener: daemonShutdownListener{close: func() error {
			shutdowns++
			return context.DeadlineExceeded
		}}}
		stop := owner.ownDaemon(daemonconfig.RoleRelay, process)
		if err := stop(); !failure.Only(err, context.DeadlineExceeded) {
			t.Fatal("explicit stop lost its accepted deadline", err)
		}
		// topology cleanup must still join, without reporting this result again.
	})
	if shutdowns != 1 {
		t.Fatal("topology cleanup repeated physical shutdown", shutdowns)
	}
}

func TestRuntimeTopologyDaemonExplicitStopRetainsIndependentDeadlineFailure(t *testing.T) {
	owner := newRuntimeTopology(t)
	operation := errors.New("relay shutdown failed")
	stop := owner.ownDaemon(daemonconfig.RoleRelay, &daemon{controlListener: daemonShutdownListener{close: func() error {
		return errors.Join(context.DeadlineExceeded, operation)
	}}})
	if err := stop(); failure.Only(err, context.DeadlineExceeded) || !errors.Is(err, operation) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("explicit stop accepted a real failure joined with its drain deadline", err)
	}
}

func TestRuntimeTopologyDaemonCleanupRetainsUnconsumedFailures(t *testing.T) {
	owner := newRuntimeTopology(t)
	accepted := owner.ownDaemon(daemonconfig.RoleRelay, &daemon{controlListener: daemonShutdownListener{close: func() error {
		return context.DeadlineExceeded
	}}})
	if err := accepted(); !failure.Only(err, context.DeadlineExceeded) {
		t.Fatal("explicit stop lost its accepted deadline", err)
	}
	operation, independent := errors.New("relay shutdown failed"), errors.New("control shutdown failed")
	owner.ownDaemon(daemonconfig.RoleRelay, &daemon{controlListener: daemonShutdownListener{close: func() error {
		return errors.Join(context.Canceled, operation)
	}}})
	owner.ownDaemon(daemonconfig.RoleControl, &daemon{controlListener: daemonShutdownListener{close: func() error {
		return independent
	}}})
	var result error
	for _, processes := range [][]runtimeProcess{owner.relays, owner.controls} {
		for _, process := range processes {
			process.cancel()
		}
		for _, process := range processes {
			// wait is the result passed to topology cleanup's error reporter.
			result = errors.Join(result, process.wait())
		}
	}
	if !errors.Is(result, operation) || !errors.Is(result, context.Canceled) || !errors.Is(result, independent) {
		t.Fatal("cleanup lost an unconsumed shutdown cause", result)
	}
	if errors.Is(result, context.DeadlineExceeded) {
		t.Fatal("cleanup repeated an explicitly consumed shutdown result", result)
	}
}

func TestRuntimeTopologyDaemonConcurrentStopAndCleanupJoinOnce(t *testing.T) {
	owner := newRuntimeTopology(t)
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	operation := errors.New("shutdown failed during cancellation")
	var shutdowns atomic.Int32
	process := &daemon{controlListener: daemonShutdownListener{close: func() error {
		shutdowns.Add(1)
		close(entered)
		<-release
		return errors.Join(context.Canceled, operation)
	}}}
	process.components.Go(func() { <-release; close(joined) })
	stop := owner.ownDaemon(daemonconfig.RoleRelay, process)
	owned := owner.relays[0]
	start, results := make(chan struct{}), make(chan error, 3)
	for _, call := range []func() error{stop, stop, func() error { owned.cancel(); return owned.wait() }} {
		go func() { <-start; results <- call() }()
	}
	close(start)
	<-entered
	select {
	case err := <-results:
		t.Fatal("a stop caller returned before physical shutdown joined", err)
	default:
	}
	unblock()
	reports := 0
	for range 3 {
		if err := <-results; err != nil {
			reports++
			if !errors.Is(err, operation) || !errors.Is(err, context.Canceled) {
				t.Error("shutdown result lost an independent cause", err)
			}
		}
	}
	select {
	case <-joined:
	default:
		t.Error("stop callers returned before the owned component joined")
	}
	if shutdowns.Load() != 1 || reports != 1 {
		t.Fatal("concurrent stop and cleanup repeated shutdown or lost its result", shutdowns.Load(), reports)
	}
}

type daemonShutdownListener struct {
	net.Listener
	close func() error
}

func (l daemonShutdownListener) Close() error { return l.close() }
