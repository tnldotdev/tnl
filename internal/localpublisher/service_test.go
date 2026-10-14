package localpublisher

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

func TestServiceAddsAndStopsJobsWithoutInterruptingOtherPublishers(t *testing.T) {
	state, err := clientstate.OpenService(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	const first = "url_0123456789abcdefghijkl"
	const second = "url_abcdefghijkl0123456789"
	job := clientstate.PublisherJob{Server: "https://control.example.test", Target: "127.0.0.1:22", Protocol: "ssh", Identity: []byte("private-test-identity")}
	job.PublicURLID = first
	if err := state.SavePublisherJob(t.Context(), job); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	started, stopped, done := make(chan string, 2), make(chan string, 2), make(chan error, 1)
	go func() {
		done <- servePublisherJobs(ctx, state, 20*time.Millisecond, func(ctx context.Context, _ *clientstate.Database, job clientstate.PublisherJob) error {
			started <- job.PublicURLID
			<-ctx.Done()
			stopped <- job.PublicURLID
			return nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("publisher service: %v", err)
		}
		state.Close()
	})
	wait := func(events <-chan string, want string) {
		t.Helper()
		select {
		case got := <-events:
			if got != want {
				t.Fatalf("publisher job = %s, want %s", got, want)
			}
		case <-ctx.Done():
			t.Fatal("publisher job did not change before deadline")
		}
	}
	wait(started, first)
	job.PublicURLID = second
	if err := state.SavePublisherJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	wait(started, second)
	if err := state.DeletePublisherJob(ctx, first); err != nil {
		t.Fatal(err)
	}
	wait(stopped, first)
	select {
	case <-stopped:
		t.Fatal("installing or stopping one job interrupted another")
	default:
	}
}
