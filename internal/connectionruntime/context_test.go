package connectionruntime

import (
	"context"
	"encoding/json"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type processObservationKey struct{}
type observationBackend struct {
	fixtureBackend
	observed atomic.Bool
}

func (b *observationBackend) Connect(ctx context.Context, name string) (Connection, error) {
	b.observed.Store(ctx.Value(processObservationKey{}) == "owner-process")
	return b.fixtureBackend.Connect(ctx, name)
}
func TestConnectionIPCInheritsProcessObservationContext(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	b := &observationBackend{fixtureBackend: fixtureBackend{deadline: time.Now().Add(time.Hour)}}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), processObservationKey{}, "owner-process"))
	defer func() { cancel(); <-done }()
	go func() { done <- Serve(ctx, scope, directory, "/test/tnl", b, writer) }()
	var state Status
	if err := json.NewDecoder(reader).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if err := Call(t.Context(), state.PrivateHandle, "connect", Request{Schema: 1, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}, new(Connection)); err != nil {
		t.Fatal(err)
	}
	if !b.observed.Load() {
		t.Fatal("IPC request lost owner process observations")
	}
}
