package ingress

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ingressPolicyFixture struct {
	fail  atomic.Bool
	calls atomic.Int64
}

func (f *ingressPolicyFixture) ReadIngressVisitorPolicy(_ context.Context, id string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
	f.calls.Add(1)
	if id != "ingress-one" || body.IngressRunId != "run-one" || body.IngressLeaseRevision != 3 {
		return controlv1.VisitorPolicyUpdate{}, errors.New("wrong ingress lease")
	}
	if f.fail.Load() {
		return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
	}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", 32)))
	now := time.Now()
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: []int64{}, SnapshotRequired: body.AfterRevision == 0,
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: true,
			VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "key", PublicKey: key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}, nil
}

func TestIngressVisitorPolicyExpiresWhileProcessLeaseRemainsLive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &ingressPolicyFixture{}
		process := ingressv1.IngressLease{IngressId: "ingress-one", IngressRunId: "run-one", IngressLeaseRevision: 3, LeaseExpiresAt: time.Now().Add(time.Minute)}
		policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, func() ingressv1.IngressLease { return process }, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		client.fail.Store(true)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if !process.LeaseExpiresAt.After(time.Now()) {
			t.Fatal("fixture expired the process lease")
		}
		if _, enabled, anonymous := policy.lease.Current(); enabled || anonymous {
			t.Fatal("process renewal substituted for expired visitor policy")
		}
		if client.calls.Load() < 2 {
			t.Fatal("background policy renewal never ran")
		}
	})
}
