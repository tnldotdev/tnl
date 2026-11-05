package service

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func connectorUseFixture(t testing.TB) (*Bound, *PeerSession, *connectorAdmission) {
	t.Helper()
	b, p, _, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
	binding := p.bindingSnapshot()
	view, _, _ := b.prepared.policy.Current()
	entry := opening("U")
	permission, err := visitortoken.VerifyConnectorPeerSession(entry, nil, binding.expected(), view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// keep callback delivery independent of the synchronous current-use fence.
	guard, err := b.prepared.policy.BindConnector(permission, binding.source, int64(entry.MetadataRevision), func() {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Close)
	if err := guard.AllowRenewal(); err != nil {
		t.Fatal(err)
	}
	life, cancel := context.WithCancel(p.ctx)
	t.Cleanup(cancel)
	a := &connectorAdmission{peer: p, ctx: life, caller: t.Context(), cancel: cancel, guard: guard, admitted: true, ready: true}
	if _, err := a.CheckUse(t.Context()); err != nil {
		t.Fatal("verified connector admission is not current", err)
	}
	return b, p, a
}

func TestConnectorAdmissionCheckUseRetainsLiveFences(t *testing.T) {
	for _, boundary := range []string{"peer cancellation", "admission cancellation", "caller cancellation", "owner replacement", "expiry", "retired owner", "closed run", "run replacement", "relay replacement", "revocation"} {
		t.Run(boundary, func(t *testing.T) {
			b, p, a := connectorUseFixture(t)
			// restore registration before fixture cleanup, including a replaced owner.
			t.Cleanup(func() {
				b.mu.Lock()
				b.connectorPeers[p.identity.pairID] = p
				b.mu.Unlock()
			})
			switch boundary {
			case "peer cancellation":
				p.cancel()
			case "admission cancellation":
				a.cancel()
			case "caller cancellation":
				caller, cancel := context.WithCancel(a.caller)
				a.caller = caller
				cancel()
			case "revocation":
				a.guard.Revoke()
			default:
				b.mu.Lock()
				switch boundary {
				case "owner replacement":
					b.connectorPeers[p.identity.pairID] = &PeerSession{}
				case "expiry":
					p.lease.until = time.Now().Add(-time.Second)
				case "retired owner":
					p.replayUntil = time.Now().Add(time.Minute)
				case "closed run":
					b.closed = true
				case "run replacement":
					b.prepared.Preparation.RunNumber++
				case "relay replacement":
					b.connections[0].ConnectionAssignmentRevision++
				}
				b.mu.Unlock()
			}
			if _, err := a.CheckUse(t.Context()); err == nil {
				t.Fatal("retained admission permitted use after", boundary)
			}
		})
	}
}
