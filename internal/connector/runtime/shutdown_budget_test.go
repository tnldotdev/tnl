package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type shutdownBudgetBackend struct {
	*fixtureBackend
	until   chan time.Time
	joined  chan struct{}
	failure error
}

func (b *shutdownBudgetBackend) Close(ctx context.Context) error {
	until, _ := ctx.Deadline()
	b.until <- until
	<-ctx.Done()
	close(b.joined)
	return errors.Join(ctx.Err(), b.failure)
}

func TestConnectionOwnerStopIPCUsesCallerBudgetAndRecordsUnconfirmedCleanup(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("remote cleanup unconfirmed")
	backend := &shutdownBudgetBackend{fixtureBackend: &fixtureBackend{deadline: time.Now().Add(time.Hour)}, until: make(chan time.Time, 1), joined: make(chan struct{}), failure: failure}
	reader, writer := io.Pipe()
	var recorded time.Time
	parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
		recorded = until
		return until
	})
	ctx, cancel := context.WithCancel(parent)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, scope, directory, "/test/tnl", OwnerConfig{Backend: backend}, writer) }()
	defer cancel()
	var status Status
	if err := json.NewDecoder(reader).Decode(&status); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(80 * time.Millisecond)
	requestCtx, stop := context.WithDeadline(t.Context(), until)
	defer stop()
	if err := Call(requestCtx, status.ConnectionHandle, "stop", Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, failure) {
			t.Fatal("owner hid the cleanup timeout or independent failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner granted a new cleanup phase after the caller deadline")
	}
	if got := <-backend.until; !got.Equal(until) {
		t.Fatal("owner replaced the caller stop budget", got, until)
	}
	if !recorded.Equal(until) {
		t.Fatal("owner did not hand its original IPC stop budget to final process flushing", recorded, until)
	}
	select {
	case <-backend.joined:
	default:
		t.Fatal("owner did not join cleanup")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "stopped.json"))
	if err != nil {
		t.Fatal(err)
	}
	var terminal struct {
		Clean bool `json:"clean"`
	}
	if err := json.Unmarshal(raw, &terminal); err != nil || terminal.Clean {
		t.Fatal("unconfirmed remote cleanup became a clean terminal result", string(raw), err)
	}
}
