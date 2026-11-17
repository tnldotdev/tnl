package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	for _, refusal := range []string{"stale-metadata", "wrong-hostname", "plaintext-http", "unsupported-version", "unsupported-ALPN", "malformed-client-hello", "peer-alert", "client-verification-alert"} {
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
				if refusal != "stale-metadata" {
					if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
						t.Fatal("valid signed opening was not accepted before visitor TLS", err)
					}
					switch refusal {
					case "plaintext-http":
						if _, err := raw.Write([]byte("GET /")); err != nil {
							t.Fatal("write plaintext HTTP to the admitted visitor", err)
						}
					case "malformed-client-hello", "peer-alert":
						record := []byte{22, 3, 3, 0, 4, 1, 0, 0, 0}
						if refusal == "peer-alert" {
							record = []byte{21, 3, 3, 0, 2, 2, 40}
						}
						if _, err := raw.Write(record); err != nil {
							t.Fatal("write visitor TLS record", err)
						}
					default:
						trust := f.trust.Clone()
						switch refusal {
						case "unsupported-version":
							trust.MinVersion, trust.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
						case "unsupported-ALPN":
							trust.NextProtos = []string{"unsupported/1"}
						case "client-verification-alert":
							trust.VerifyConnection = func(tls.ConnectionState) error { return errors.New("visitor refused the server certificate") }
						default:
							trust.ServerName = "old-namespace.example.test"
						}
						if err := tls.Client(raw, trust).HandshakeContext(ctx); err == nil {
							t.Fatal("refused visitor acquired TLS or target authority")
						}
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
				if refusal != "stale-metadata" && refusal != "wrong-hostname" {
					if refusal == "plaintext-http" {
						var record tls.RecordHeaderError
						if !errors.As(visitorResult, &record) {
							t.Fatal("plaintext visitor did not reach actual TLS negotiation", visitorResult)
						}
					}
					var refusal *servicestream.VisitorProtocolRefusal
					if !errors.As(visitorResult, &refusal) || !connectorAdmissionRoutineError(refusal) ||
						connectorAdmissionRoutineError(refusal.Unwrap()) {
						t.Fatal("visitor TLS provenance was missing or classified a raw failure", visitorResult)
					}
					for _, required := range []error{
						errors.Join(refusal, independent),
						&muxsession.QUICTransportCloseError{Err: refusal},
						&tunnel.SessionCleanupError{Err: refusal},
						&tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: refusal},
					} {
						if connectorAdmissionRoutineError(required) {
							t.Fatal("visitor TLS refusal hid an independent or required failure", required)
						}
					}
				} else if !errors.Is(visitorResult, want) {
					t.Fatal("authority refusal lost its original cause", visitorResult)
				}
				if pending != 0 || active != 0 || f.target.dials.Load() != 0 {
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

func TestConnectorTLSCallbackFailureCannotBorrowVisitorRefusalProvenance(t *testing.T) {
	independent := errors.New("visitor certificate callback failed independently")
	for _, problem := range []struct {
		name string
		err  error
	}{
		{"joined-cancellation", errors.Join(context.Canceled, independent)},
		{"EOF", io.EOF},
		{"raw-TLS", tls.RecordHeaderError{}},
		{"hostname-refusal", &servicestream.VisitorHostnameRefusal{}},
	} {
		t.Run(problem.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			f := newOpeningRefusalFixture(t, ctx, config.ProtocolHTTP)
			f.bound.prepared.visitorTLS = f.bound.prepared.visitorTLS.Clone()
			f.bound.prepared.visitorTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return nil, problem.err
			}
			p := f.peer(t, ctx, 0, "S")
			serving := f.serve(t, ctx, p, nil, nil)
			rawConnectorControl(t, ctx, serving.client)
			entry := f.entry(t, p, 0, "S")
			raw := openingRefusalRaw(t, ctx, serving, entry)
			if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
				t.Fatal("valid signed opening was not accepted", err)
			}
			_ = tls.Client(raw, f.trust.Clone()).HandshakeContext(ctx)
			openingRefusalAwait(t, ctx, serving.done)
			if !errors.Is(serving.err, problem.err) || f.target.dials.Load() != 0 {
				t.Fatal("required certificate callback failure was hidden or reached the target", serving.err)
			}
			var callback *servicestream.VisitorTLSCallbackFailure
			if !errors.As(serving.err, &callback) || connectorAdmissionRoutineError(callback) ||
				connectorAdmissionRoutineError(&tunnel.ConnectorControlFailure{Origin: tunnel.ConnectorControlWriterFailure, Err: callback}) {
				t.Fatal("local callback failure borrowed visitor or required-control provenance", serving.err)
			}
		})
	}
}

func TestConnectorTLSRefusalRetainsIgnoredAlertWriteFailure(t *testing.T) {
	for _, problem := range []struct {
		name string
		err  error
	}{
		{"independent", errors.Join(context.Canceled, errors.New("visitor TLS alert write failed independently"))},
		{"raw-TLS", tls.RecordHeaderError{}},
	} {
		t.Run(problem.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			f := newOpeningRefusalFixture(t, ctx, config.ProtocolHTTP)
			p := f.peer(t, ctx, 0, "S")
			fault := &openingRefusalWriteStream{ctx: ctx, err: problem.err, entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(fault.release) })
			serving := f.serve(t, ctx, p, func(server muxsession.Session) muxsession.Session {
				return &openingRefusalWriteSession{Session: server, selected: 2, stream: fault}
			}, release)
			rawConnectorControl(t, ctx, serving.client)
			entry := f.entry(t, p, 0, "S")
			raw := openingRefusalRaw(t, ctx, serving, entry)
			if err := tunnelv1.ReadConnectorPeerVisitorAccepted(raw, entry.VisitorConnectionID); err != nil {
				t.Fatal("valid signed opening was not accepted", err)
			}
			fault.armed.Store(true)
			if _, err := raw.Write([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0}); err != nil {
				t.Fatal("write malformed ClientHello", err)
			}
			openingRefusalAwait(t, ctx, fault.entered)
			release()
			openingRefusalAwait(t, ctx, serving.done)
			var operation *servicestream.VisitorTLSIOFailure
			if !errors.Is(serving.err, problem.err) || !errors.As(serving.err, &operation) ||
				connectorAdmissionRoutineError(operation) || f.target.dials.Load() != 0 {
				t.Fatal("TLS negotiation discarded its independently failed alert write", serving.err)
			}
		})
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
