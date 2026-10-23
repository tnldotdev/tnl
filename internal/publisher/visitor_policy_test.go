package publisher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type policyClientFixture struct {
	key      ed25519.PrivateKey
	fail     atomic.Bool
	calls    atomic.Int64
	revision atomic.Int64
}

func (f *policyClientFixture) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, credential string) (controlv1.VisitorPolicyUpdate, error) {
	f.calls.Add(1)
	if credential != "run-secret" {
		return controlv1.VisitorPolicyUpdate{}, errors.New("wrong run credential")
	}
	if f.fail.Load() {
		return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
	}
	now := time.Now()
	revision := max(int64(1), f.revision.Load())
	events := []int64{}
	if body.AfterRevision != 0 {
		for next := body.AfterRevision + 1; next <= revision; next++ {
			events = append(events, next)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: events, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: revision, KeyRevision: 1,
			ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: false, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "test-key", PublicKey: f.key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}, nil
}

func TestPublisherVisitorPolicyOutageEndsTrafficWithoutVisitorRPCs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
		policy, err := prepareVisitorPolicy(t.Context(), client, scope, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		view, enabled, _ := policy.lease.Current()
		if !enabled {
			t.Fatal("publisher became ready without policy")
		}
		permission := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 1, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("C", 22), SessionID: "cs_" + strings.Repeat("D", 22)}, ExpiresAt: time.Now().Add(time.Minute)}
		token, err := visitortoken.Sign(view.Issuer, "test-key", client.key, permission, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		before := client.calls.Load()
		for range 10 {
			if _, err := visitortoken.VerifyBearer(token, view, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		if client.calls.Load() != before {
			t.Fatal("prepared verification made a control call")
		}
		verified, err := visitortoken.VerifyBearer(token, view, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		var stopped atomic.Bool
		guard, err := policy.lease.Bind(verified, netip.MustParseAddr("192.0.2.1"), func() { stopped.Store(true) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		client.fail.Store(true)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if !stopped.Load() {
			t.Fatal("background failures extended publisher authority")
		}
		if _, enabled, _ := policy.lease.Current(); enabled {
			t.Fatal("publisher retained expired visitor policy")
		}
		client.fail.Store(false)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, enabled, _ := policy.lease.Current(); !enabled {
			t.Fatal("publisher did not recover through a fresh snapshot")
		}
	})
}
