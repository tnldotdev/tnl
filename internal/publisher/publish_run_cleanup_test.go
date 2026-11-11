package publisher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func cleanupFixture(t *testing.T) *publishRunCleanup {
	t.Helper()
	route := certificateTestPublicURL(t, "preview.example", controlv1.CertificatePlan{})
	paths, err := tunnel.NewSlots(t.Context(), tunnel.SlotsConfig{Connect: func(context.Context, uint8, bool) (tunnel.SlotSession, error) { return nil, tunnel.ErrAwaitAssignment }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = paths.Close() })
	return &publishRunCleanup{parentCtx: t.Context(), route: route, connections: &publisherConnectionManager{paths: paths}, config: Config{DrainTime: time.Second}}
}

func TestDrainPreservesFailureJoinedWithCancellation(t *testing.T) {
	cleanup := errors.New("stream cleanup failed")
	s := cleanupFixture(t)
	err := s.drain(errors.Join(context.Canceled, cleanup))
	if !errors.Is(err, cleanup) {
		t.Fatalf("drain hid cleanup failure: %v", err)
	}
}

func TestFinishPreservesCleanupAlongsideSessionCause(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "session failure", true: "completed budget"}[completed], func(t *testing.T) {
			s := cleanupFixture(t)
			ctx, cancel := context.WithCancelCause(t.Context())
			s.sessionCtx, s.cancelSession = ctx, cancel
			s.cancelTransports = func() {}
			s.heartbeatStarted = true
			heartbeat := make(chan error, 1)
			s.heartbeatDone = heartbeat
			expired := make(chan struct{})
			close(expired)
			s.expirationDone = expired
			cleanup, heartbeatFailure := errors.New("cleanup failed"), errors.New("heartbeat failed")
			if completed {
				close(s.route.admission.completed)
				heartbeat <- errors.Join(context.Canceled, heartbeatFailure)
			} else {
				cancel(heartbeatFailure)
				heartbeat <- nil
			}
			err := s.finish(cleanup)
			if !errors.Is(err, cleanup) || !errors.Is(err, heartbeatFailure) {
				t.Fatalf("finish lost a cause: %v", err)
			}
		})
	}
}
