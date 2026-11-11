package runtime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
)

type preparationBackend struct {
	use      func(context.Context, string) error
	connect  func(context.Context, string) (Connection, error)
	snapshot func(string, string) (Prepared, error)
}

func (b preparationBackend) UseAssertion(ctx context.Context, assertion string) error {
	return b.use(ctx, assertion)
}
func (b preparationBackend) Connect(ctx context.Context, service string) (Connection, error) {
	return b.connect(ctx, service)
}
func (b preparationBackend) SnapshotFor(service, assertion string) (Prepared, error) {
	return b.snapshot(service, assertion)
}

func TestPrepareSnapshotReadsMetadataConnectionAndProofAtomically(t *testing.T) {
	var steps []string
	want := Prepared{
		Schema:         Schema,
		ProjectRuntime: meta.PublicMetadata{Namespace: "current.example"},
		Connection:     Connection{Schema: Schema, TransportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa", ExpiresAt: time.Now().Add(time.Minute)},
		Verification:   &AssertionVerification{Digest: "verified exact assertion", Binding: "current session"},
	}
	b := preparationBackend{
		use: func(_ context.Context, assertion string) error {
			if assertion != "exact assertion" {
				t.Fatal("preparation lost its assertion")
			}
			steps = append(steps, "assertion")
			return nil
		},
		connect: func(_ context.Context, service string) (Connection, error) {
			if service != "database" {
				t.Fatal("prepared the wrong service")
			}
			steps = append(steps, "connect")
			// a refresh can publish another coherent snapshot before the read.
			return Connection{TransportID: "earlier transport"}, nil
		},
		snapshot: func(service, assertion string) (Prepared, error) {
			if service != "database" || assertion != "exact assertion" {
				t.Fatal("snapshot read lost its service or exact proof selector")
			}
			steps = append(steps, "snapshot")
			return want, nil
		},
	}
	got, err := PrepareSnapshot(t.Context(), b, Request{Service: "database", Assertion: "exact assertion"})
	if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(steps, []string{"assertion", "connect", "snapshot"}) {
		t.Fatal("preparation reconstructed its snapshot or reordered authority", got, steps, err)
	}
}

func TestPrepareSnapshotStopsAtFailedBoundary(t *testing.T) {
	for _, boundary := range []string{"assertion", "connect", "snapshot"} {
		t.Run(boundary, func(t *testing.T) {
			failure := errors.New("preparation failed")
			var steps []string
			step := func(name string) error {
				steps = append(steps, name)
				if name == boundary {
					return failure
				}
				if len(steps) > 1 && steps[len(steps)-2] == boundary {
					t.Fatal("continued preparation after failed authority")
				}
				return nil
			}
			b := preparationBackend{
				use: func(_ context.Context, assertion string) error {
					if assertion != "" {
						t.Fatal("native acquisition was given an invented assertion")
					}
					return step("assertion")
				},
				connect:  func(context.Context, string) (Connection, error) { return Connection{}, step("connect") },
				snapshot: func(string, string) (Prepared, error) { return Prepared{}, step("snapshot") },
			}
			if _, err := PrepareSnapshot(t.Context(), b, Request{Service: "database", AcquireAssertion: true}); !errors.Is(err, failure) {
				t.Fatal("lost preparation failure", err)
			}
		})
	}
}
