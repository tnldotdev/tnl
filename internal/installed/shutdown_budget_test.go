package installed

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
)

func TestInstalledShutdownSharesDeadlineAcrossJobsAndJoinsFailures(t *testing.T) {
	options := testOptions(t)
	options.User = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	for _, name := range []string{"api", "web"} {
		job, _, _ := kindFixture(t, KindConnector)
		job.ID = name
		if err := registry.InstallConnector(t.Context(), job); err != nil {
			t.Fatal(err)
		}
	}
	started, deadlines, joined := make(chan struct{}, 2), make(chan time.Time, 2), make(chan struct{}, 2)
	cleanup := errors.New("remote cleanup unconfirmed")
	deadline := sync.OnceValue(func() time.Time { return time.Now().Add(80 * time.Millisecond) })
	engine := Engine{Registry: registry, PollInterval: time.Millisecond, ShutdownDeadline: deadline,
		Connect: func(ctx context.Context, _ Job, _ *clienttelemetry.Collector, _ func() error, until func() time.Time) error {
			started <- struct{}{}
			<-ctx.Done()
			finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), until())
			defer cancel()
			value, _ := finish.Deadline()
			deadlines <- value
			<-finish.Done()
			joined <- struct{}{}
			return errors.Join(ctx.Err(), finish.Err(), cleanup)
		}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- engine.Serve(ctx) }()
	defer cancel()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("installed job did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, cleanup) {
			t.Fatal("supervisor hid timeout or independent cleanup failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("installed shutdown started an extra cleanup budget")
	}
	for range 2 {
		if value := <-deadlines; !value.Equal(deadline()) {
			t.Fatal("job received a fresh shutdown deadline", value, deadline())
		}
		select {
		case <-joined:
		default:
			t.Fatal("supervisor returned before joining an owned job")
		}
	}
}
