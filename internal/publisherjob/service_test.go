package publisherjob

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerReconcilesAndRetries(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	starts := map[string]int{}
	stops := make(chan string, 4)
	ended := make(chan error, 1)
	go func() {
		ended <- run(ctx, s, func(ctx context.Context, job Job) error {
			mu.Lock()
			starts[job.ID()]++
			n := starts[job.ID()]
			mu.Unlock()
			if job.ID() == "url-retry" && n == 1 {
				return errors.New("server unavailable")
			}
			<-ctx.Done()
			stops <- job.ID()
			return ctx.Err()
		}, time.Millisecond, 5*time.Millisecond)
	}()
	a := testJob(t, "url-retry")
	b := testJob(t, "url-independent")
	if err := s.Add(a); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(b); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		ready := starts[a.ID()] >= 2 && starts[b.ID()] == 1
		mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("jobs did not start independently or retry")
		case <-time.After(time.Millisecond):
		}
	}
	if err := s.Remove(a.Server, a.ID()); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-stops:
		if id != a.ID() {
			t.Fatalf("stopped %s instead", id)
		}
	case <-time.After(time.Second):
		t.Fatal("stop was not reconciled")
	}
	mu.Lock()
	if starts[b.ID()] != 1 {
		t.Fatal("unrelated job restarted")
	}
	mu.Unlock()
	cancel()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
}

func TestManagerReplacesStoppedJobBeforeNextPoll(t *testing.T) {
	s := testStore(t)
	first := testJob(t, "url-replaced")
	if err := s.Add(first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 3)
	stopped := make(chan struct{}, 3)
	ended := make(chan error, 1)
	go func() {
		ended <- run(ctx, s, func(ctx context.Context, job Job) error {
			started <- struct{}{}
			<-ctx.Done()
			stopped <- struct{}{}
			return ctx.Err()
		}, time.Millisecond, time.Second)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job did not start")
	}
	if err := s.Remove(first.Server, first.ID()); err != nil {
		t.Fatal(err)
	}
	replacement := testJob(t, first.ID())
	if err := s.Add(replacement); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("old signing key stayed active")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("new signing key did not start")
	}
	cancel()
	if err := <-ended; err != nil {
		t.Fatal(err)
	}
}

func TestServiceAdapterCommands(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "service.unit")
			var commands []string
			run := func(_ context.Context, name string, args ...string) error {
				commands = append(commands, name+" "+strings.Join(args, " "))
				if platform == "darwin" && len(args) != 0 && args[0] == "print" {
					return errors.New("not loaded")
				}
				return nil
			}
			if err := installService(context.Background(), platform, "/var/lib/tnl/publisher", path, run); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !(strings.Contains(string(body), "publisher service run") || strings.Contains(string(body), "<string>publisher</string><string>service</string><string>run</string>")) || strings.Contains(string(body), "enroll-key") || len(commands) < 2 {
				t.Fatalf("unit or service calls: %s %v", body, commands)
			}
		})
	}
}
