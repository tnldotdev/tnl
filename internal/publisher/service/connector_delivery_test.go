package service

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func newConnectorDeliveryAdmission(t *testing.T, protocol config.ProtocolName, lifetime time.Duration) (*Bound, *PeerSession, *connectorAdmission, tunnelv1.ConnectorPeerVisitorEntry) {
	t.Helper()
	bound, peer, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	bound.prepared.managedProtocol = protocol
	bound.drainStarted = make(chan struct{})
	entry := opening("S")
	entry.Permission = signedPermissionUpdate(t, bound, peer, entry, 1, time.Now().Add(lifetime)).Permission
	view, _, _ := bound.prepared.policy.Current()
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, peer.bindingSnapshot().expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	wire := &drainingConnectorWire{closed: make(chan struct{})}
	admission := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel, stream: wire,
		state: readyConnectorAdmission{}, completed: make(chan struct{}), entry: entry, permission: permission}
	admission.guard, err = bound.prepared.policy.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), bound.prepared.metadataRevision, admission.stopAndClose)
	if err != nil {
		t.Fatal(err)
	}
	if err := admission.guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	admission.audit.VisitorConnectionID, admission.audit.DeliveryGeneration = entry.VisitorConnectionID, entry.DeliveryGeneration
	peer.streams[admission] = struct{}{}
	t.Cleanup(func() {
		cancel()
		admission.guard.Close()
		bound.mu.Lock()
		delete(peer.streams, admission)
		bound.mu.Unlock()
	})
	return bound, peer, admission, entry
}

func TestConnectorNormalCompletionKeepsExactReceiptAndImmediateRevocation(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		for _, finish := range []string{"consumed", "revoked", "canceled"} {
			t.Run(string(protocol)+"/"+finish, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bound, peer, admission, entry := newConnectorDeliveryAdmission(t, protocol, 2*time.Second)
					before := time.Now()
					done := make(chan error, 1)
					go func() { done <- admission.finishDelivery(nil) }()
					<-admission.stream.(*drainingConnectorWire).closed
					synctest.Wait()
					receipt := tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted,
						VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration}
					wrongVisitor, wrongGeneration := receipt, receipt
					wrongVisitor.VisitorConnectionID = "vc_aaaaaaaaaaaaaaaaaaaaaa"
					wrongGeneration.DeliveryGeneration++
					peer.completeVisitor(wrongVisitor)
					peer.completeVisitor(wrongGeneration)
					(&PeerSession{bound: bound, streams: make(map[*connectorAdmission]struct{})}).completeVisitor(receipt)
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatal("normal completion released ownership without the exact receipt", err)
					default:
					}
					var want error
					switch finish {
					case "revoked":
						admission.guard.Revoke()
						want = context.Canceled
					case "canceled":
						admission.cancel()
						want = context.Canceled
					default:
						peer.completeVisitor(receipt)
						peer.completeVisitor(receipt)
					}
					if err := <-done; !errors.Is(err, want) || !time.Now().Equal(before) {
						t.Fatal("normal completion lost exact receipt or immediate revocation", err, want, time.Since(before))
					}
					if err := admission.finishDelivery(nil); !errors.Is(err, want) {
						t.Fatal("duplicate completion changed the joined result", err, want)
					}
				})
			})
		}
	}
}

func TestConnectorMissingReceiptKeepsAuthoritySnapshotAcrossRenewalAndLateDrain(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		for _, drain := range []string{"none", "shorter", "longer"} {
			t.Run(string(protocol)+"/"+drain, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					lifetime := time.Second
					if drain == "shorter" {
						lifetime = 2 * time.Second
					}
					bound, peer, admission, entry := newConnectorDeliveryAdmission(t, protocol, lifetime)
					before := time.Now()
					done := make(chan error, 1)
					go func() { done <- admission.finishDelivery(nil) }()
					<-admission.stream.(*drainingConnectorWire).closed
					synctest.Wait()
					time.Sleep(250 * time.Millisecond)
					next := entry
					next.Permission = signedPermissionUpdate(t, bound, peer, entry, 1, before.Add(3*time.Second)).Permission
					view, _, _ := bound.prepared.policy.Current()
					renewed, err := visitortoken.VerifyConnectorPeerRenewalProof(next, nil, peer.bindingSnapshot().expected(), view, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					if err := admission.guard.Renew(renewed); err != nil {
						t.Fatal("fixture permission renewal failed", err)
					}
					current, err := admission.CheckUse(admission.ctx)
					if err != nil || !current.After(before.Add(lifetime)) {
						t.Fatal("fixture did not renew authority beyond the completion snapshot", current, err)
					}
					until := before.Add(lifetime)
					if drain != "none" {
						published := before.Add(2 * time.Second)
						if drain == "shorter" {
							published = before.Add(time.Second)
							until = published
						}
						if err := bound.startDrain(published); err != nil {
							t.Fatal(err)
						}
						if err := bound.startDrain(published.Add(time.Hour)); err != nil || !bound.drainUntil.Equal(published) {
							t.Fatal("another drain request extended the published deadline", err)
						}
					}
					if err := <-done; !errors.Is(err, context.DeadlineExceeded) || !time.Now().Equal(until) {
						t.Fatal("missing receipt extended its original authority or late drain bound", err, time.Now(), until)
					}
					if _, err := admission.CheckUse(admission.ctx); err != nil {
						t.Fatal("fixture ended by permission revocation rather than the captured completion bound", err)
					}
				})
			})
		}
	}
}

func TestConnectorFailedDeliveryKeepsOperationAndCleanupWithoutReceiptWait(t *testing.T) {
	for _, protocol := range []config.ProtocolName{config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolPostgres, config.ProtocolMySQL, config.ProtocolKubernetes} {
		for _, failure := range []string{"operation", "cleanup", "canceled cleanup", "deadline cleanup"} {
			t.Run(string(protocol)+"/"+failure, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					bound, peer, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
					bound.prepared.managedProtocol = protocol
					bound.drainUntil = time.Now().Add(time.Second)
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					wire := &drainingConnectorWire{closed: make(chan struct{})}
					operation, cleanup := errors.New("independent operation failed"), errors.New("independent physical cleanup failed")
					if failure != "operation" {
						wire.closeErr = cleanup
					}
					switch failure {
					case "cleanup":
						operation = nil
					case "canceled cleanup":
						operation = context.Canceled
						cancel()
					case "deadline cleanup":
						operation = context.DeadlineExceeded
					}
					admission := &connectorAdmission{peer: peer, ctx: ctx, caller: ctx, cancel: cancel, stream: wire,
						state: readyConnectorAdmission{}, completed: make(chan struct{})}
					before := time.Now()
					finished := make(chan error, 1)
					go func() { finished <- errors.Join(operation, admission.finishDelivery(operation)) }()
					err := <-finished
					if operation != nil && !errors.Is(err, operation) || wire.closeErr != nil && !errors.Is(err, cleanup) {
						t.Fatal("failed delivery lost an independent operation or cleanup cause", err)
					}
					if !time.Now().Equal(before) || wire.closes.Load() != 1 {
						t.Fatal("failed delivery waited for a success receipt or repeated physical cleanup", time.Since(before), wire.closes.Load())
					}
					again := errors.Join(operation, admission.finishDelivery(operation))
					if operation != nil && !errors.Is(again, operation) || wire.closeErr != nil && !errors.Is(again, cleanup) {
						t.Fatal("repeated failed delivery changed its causes", again)
					}
				})
			})
		}
	}
}
