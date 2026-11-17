package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorVisitorRefusalPreservesWorkerCleanupProvenance(t *testing.T) {
	independent := errors.New("independent refused visitor physical close failed")
	for _, refusal := range []string{"stale-metadata", "wrong-hostname"} {
		for _, cleanup := range []struct {
			name string
			err  error
		}{
			{"clean", nil},
			{"independent", errors.Join(context.Canceled, independent)},
			{"typed-physical", &muxsession.QUICTransportCloseError{Err: independent}},
			{"raw-endpoint-close", servicestream.ErrEndpoint},
		} {
			t.Run(refusal+"/"+cleanup.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				f := newOpeningRefusalFixture(t, ctx, config.ProtocolHTTP)
				peer := f.peer(t, ctx, 0, "S")
				gate := &permissionOpeningGate{entered: make(chan struct{}), release: make(chan struct{})}
				held := &permissionHeldClose{entered: make(chan struct{}), release: make(chan struct{}), closeErr: cleanup.err}
				release := sync.OnceFunc(func() { close(held.release) })
				serving := f.serve(t, ctx, peer, func(server muxsession.Session) muxsession.Session {
					closes := &permissionHeldSession{Session: server, held: held}
					return &permissionOpeningSession{Session: closes, ctx: ctx, gate: gate, hold: 2}
				}, func() { gate.open(); release() })
				rawConnectorControl(t, ctx, serving.client)
				entry := f.entry(t, peer, 0, "S")
				want := servicestream.ErrEndpoint
				if refusal == "stale-metadata" {
					entry.MetadataRevision++
					openingRefusalSign(t, &entry, f.subjects[0].key)
					want = ErrPrivateStream
				}
				raw := openingRefusalRaw(t, ctx, serving, entry)
				openingRefusalAwait(t, ctx, gate.entered)
				admission := openingRefusalPending(t, peer)
				gate.open()
				if refusal == "wrong-hostname" {
					if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
						t.Fatal("valid signed opening was not accepted before visitor TLS", err)
					}
					trust := f.trust.Clone()
					trust.ServerName = "old-namespace.example.test"
					if err := tls.Client(raw, trust).HandshakeContext(ctx); err == nil {
						t.Fatal("wrong visitor hostname acquired TLS or target authority")
					}
				} else {
					openingRefusalNoAcceptance(t, raw)
				}
				openingRefusalAwait(t, ctx, held.entered)
				select {
				case <-admission.joined:
					t.Fatal("refused visitor published its result before physical cleanup joined")
				default:
				}
				release()
				openingRefusalAwait(t, ctx, admission.joined)
				openingRefusalJoinWorkers(t, ctx, peer)
				f.bound.mu.Lock()
				visitorResult, workerResult := admission.joinedOutcome.err, peer.err
				pending, active := f.bound.connectorPending, f.bound.reservedStreams
				f.bound.mu.Unlock()
				t.Logf("visitor=%v; worker=%v", visitorResult, workerResult)
				if !errors.Is(visitorResult, want) || pending != 0 || active != 0 || f.target.dials.Load() != 0 {
					t.Fatal("authority refusal lost its visitor result, leaked capacity, or reached the target", visitorResult, pending, active, f.target.dials.Load())
				}
				if cleanup.err != nil {
					openingRefusalAwait(t, ctx, serving.done)
					if !errors.Is(visitorResult, cleanup.err) || !errors.Is(workerResult, cleanup.err) || !errors.Is(serving.err, cleanup.err) {
						t.Fatal("visitor-local refusal hid independent required cleanup", visitorResult, workerResult, serving.err)
					}
					return
				}
				if workerResult != nil {
					t.Fatal("visitor authority refusal poisoned the retained worker/run", workerResult)
				}
				serving.alive(t)
				connection := f.connect(t, ctx, serving, f.entry(t, peer, 0, "T"))
				f.roundTrip(t, connection)
				serving.alive(t)
			})
		}
	}
}

func TestConnectorHostnameRefusalDoesNotClassifyRawOrRequiredFailures(t *testing.T) {
	refusal := &servicestream.VisitorHostnameRefusal{}
	independent := errors.New("independent close failed")
	for _, test := range []struct {
		name    string
		err     error
		routine bool
	}{
		{"exact visitor hostname refusal", refusal, true},
		{"wrapped visitor hostname refusal", fmt.Errorf("visitor TLS: %w", refusal), true},
		{"visitor refusal and cancellation", errors.Join(refusal, context.Canceled), true},
		{"raw endpoint failure", servicestream.ErrEndpoint, false},
		{"visitor refusal and raw endpoint close", errors.Join(refusal, servicestream.ErrEndpoint), false},
		{"visitor refusal and independent close", errors.Join(refusal, independent), false},
		{"typed physical close", &muxsession.QUICTransportCloseError{Err: refusal}, false},
		{"typed session cleanup", &tunnel.SessionCleanupError{Err: refusal}, false},
		{"required control writer", &tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: refusal}, false},
		{"required control writer mixed cancellation", &tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure,
			Err: errors.Join(context.Canceled, refusal, independent)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := connectorAdmissionRoutineError(test.err); got != test.routine {
				t.Fatal("visitor hostname provenance changed an independent failure", got, test.err)
			}
		})
	}
	if !errors.Is(refusal, servicestream.ErrEndpoint) || refusal.Error() != servicestream.ErrEndpoint.Error() {
		t.Fatal("hostname refusal changed the original authority error")
	}
}
