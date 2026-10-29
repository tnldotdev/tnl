package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var processSignalChild = flag.String("tnl-process-signal-child", "", "owned process signal fixture")

func TestProcessSignalContextPreservesParentAndStopsOnce(t *testing.T) {
	for _, value := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		received := make(chan os.Signal, 1)
		var stopped atomic.Int32
		ctx, stop := processSignalContext(t.Context(), received, func() { stopped.Add(1) })
		received <- value
		<-ctx.Done()
		if context.Cause(ctx) != context.Canceled || stopped.Load() != 1 {
			t.Fatal("known signal did not publish ordinary cancellation after unregistering")
		}
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(stop)
		}
		workers.Wait()
		if stopped.Load() != 1 {
			t.Fatal("signal registration stopped more than once")
		}
	}
	unknown := errors.New("custom parent failure")
	for _, cause := range []error{unknown, errors.Join(context.Canceled, unknown), context.DeadlineExceeded, &processSignalPanicIs{}} {
		parent, cancel := context.WithCancelCause(t.Context())
		cancel(cause)
		received := make(chan os.Signal, 1)
		received <- os.Interrupt
		ctx, stop := processSignalContext(parent, received, func() {})
		stop()
		if context.Cause(ctx) != cause {
			t.Fatal("process signal adapter replaced its parent's exact cause")
		}
	}
}

type processSignalPanicIs struct{}

func (*processSignalPanicIs) Error() string { return "custom parent failure" }
func (*processSignalPanicIs) Is(error) bool {
	panic("the signal producer must not consult custom Is hooks")
}

type processSignalRecord struct {
	Stage    string `json:"stage"`
	Ordinary bool   `json:"ordinary"`
}

func TestProcessSignalsSubprocess(t *testing.T) {
	if *processSignalChild == "" {
		t.Skip("requires its owned subprocess")
	}
	received := make(chan os.Signal, 1)
	var ctx context.Context
	var stop context.CancelFunc
	if *processSignalChild == "old" {
		ctx, stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		unregistered := make(chan struct{})
		go func() { <-ctx.Done(); stop(); close(unregistered) }()
		_ = json.NewEncoder(os.Stdout).Encode(processSignalRecord{Stage: "ready"})
		<-ctx.Done()
		<-unregistered
	} else {
		signal.Notify(received, os.Interrupt, syscall.SIGTERM)
		ctx, stop = processSignalContext(context.Background(), received, func() { signal.Stop(received) })
		_ = json.NewEncoder(os.Stdout).Encode(processSignalRecord{Stage: "ready"})
		<-ctx.Done()
		stop()
	}
	_ = json.NewEncoder(os.Stdout).Encode(processSignalRecord{Stage: "stopped", Ordinary: context.Cause(ctx) == context.Canceled})
	<-time.After(5 * time.Second)
	os.Exit(99)
}

func TestProcessSignalsRestoreActualSecondSignal(t *testing.T) {
	for _, version := range []string{"old", "new"} {
		for _, first := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(version+"/"+first.String(), func(t *testing.T) {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, executable, "-test.run=^TestProcessSignalsSubprocess$", "-tnl-process-signal-child="+version)
				output, err := command.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				defer output.Close()
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				waited := false
				defer func() {
					cancel()
					if !waited {
						_ = command.Wait()
					}
				}()
				decoder := json.NewDecoder(output)
				var record processSignalRecord
				if err := decoder.Decode(&record); err != nil || record.Stage != "ready" {
					t.Fatal("signal child did not start", err)
				}
				if err := command.Process.Signal(first); err != nil {
					t.Fatal(err)
				}
				if err := decoder.Decode(&record); err != nil || record.Stage != "stopped" || record.Ordinary != (version == "new") {
					t.Fatal("first signal cause/stop changed", record, err)
				}
				if err := command.Process.Signal(os.Interrupt); err != nil {
					t.Fatal(err)
				}
				err = command.Wait()
				waited = true
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal("second signal did not terminate the child", err)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGINT {
					t.Fatal("second signal did not have its default SIGINT action", status)
				}
				t.Log("first signal acknowledged; actual second SIGINT terminated", version)
			})
		}
	}
}
