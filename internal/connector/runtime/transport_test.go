package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"
)

type invalidTransportBackend struct {
	*fixtureBackend
	transportID string
}

func (b *invalidTransportBackend) Connect(context.Context, string) (Connection, error) {
	return Connection{Schema: Schema, ExpiresAt: b.deadline, TransportID: b.transportID}, nil
}

func (b *invalidTransportBackend) Prepared(name string) (Connection, error) {
	return b.Connect(context.Background(), name)
}

type invalidPreparedTransportBackend struct {
	*fixtureBackend
	transportID string
}

func (b *invalidPreparedTransportBackend) SnapshotFor(string, string) (Prepared, error) {
	return Prepared{Schema: Schema, Connection: Connection{Schema: Schema, ExpiresAt: b.deadline, TransportID: b.transportID}}, nil
}

func TestConnectionOwnerRejectsInvalidTransportOutput(t *testing.T) {
	for _, identity := range []string{"", "ctg_invalid"} {
		for _, atomic := range []bool{false, true} {
			t.Run(identity+map[bool]string{false: "/connection", true: "/atomic prepared"}[atomic], func(t *testing.T) {
				scope := fixtureScope(t)
				directory, err := NewDirectory(scope.Directory)
				if err != nil {
					t.Fatal(err)
				}
				fixture := &fixtureBackend{deadline: time.Now().Add(time.Hour)}
				fixture.credential.Store(1)
				var backend Backend = &invalidTransportBackend{fixtureBackend: fixture, transportID: identity}
				if atomic {
					backend = &invalidPreparedTransportBackend{fixtureBackend: fixture, transportID: identity}
				}
				reader, writer := io.Pipe()
				done := make(chan error, 1)
				ctx, cancel := context.WithCancel(t.Context())
				defer func() {
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				go func() { done <- Serve(ctx, scope, directory, "/test/tnl", backend, writer) }()
				var status Status
				if err := json.NewDecoder(reader).Decode(&status); err != nil {
					t.Fatal(err)
				}
				request := Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"}
				operations := []string{"prepare", "prepared"}
				if !atomic {
					operations = append(operations, "connect")
				}
				for _, operation := range operations {
					var response map[string]any
					if err := Call(t.Context(), status.ConnectionHandle, operation, request, &response); !errors.Is(err, ErrUnavailable) || response != nil {
						t.Fatal("owner emitted an invalid transport snapshot", operation, err)
					}
				}
			})
		}
	}
}
