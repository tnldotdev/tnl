package service

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerPreparationRetriesUnconfirmedInstallation(t *testing.T) {
	for _, test := range []struct {
		name      string
		installed time.Duration
		want      bool
	}{
		{"not confirmed", 0, true},
		{"confirmation near expiry", 5 * time.Second, true},
		{"confirmation expired", -time.Second, true},
		{"confirmation current", time.Minute, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			binding := p.bindingSnapshot()
			binding.until = time.Now().Add(time.Minute)
			binding.authorityUntil = binding.until
			if err := p.Renew(binding); err != nil {
				t.Fatal(err)
			}
			b.mu.Lock()
			if test.installed != 0 {
				p.installedUntil = time.Now().Add(test.installed)
			}
			b.mu.Unlock()
			candidate := controlv1.ConnectorPeerPairCandidate{PairId: binding.pairID, DeliveryGeneration: binding.generation}
			if got := b.peerNeedsPreparation(candidate); got != test.want {
				t.Fatalf("installation retry = %t, want %t after binding renewal", got, test.want)
			}
		})
	}
}

func TestNativeWorkloadInstallationWaitsForBackgroundPolicy(t *testing.T) {
	b, p, _, _, control := connectorPeerFixture(t, "127.0.0.1:1")
	binding := p.bindingSnapshot()
	binding.subject = tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: "wls_aaaaaaaaaaaaaaaaaaaaaa"}
	if b.connectorPeerPolicyCurrent(binding) {
		t.Fatal("installation became ready before its workload appeared in local policy")
	}
	apply := func(parents []controlv1.VisitorWorkloadLease) {
		t.Helper()
		r := b.prepared.policy.Begin()
		policy := control.policy
		policy.ObservedAt = time.Now()
		policy.ValidUntil = policy.ObservedAt.Add(visitortoken.PolicyLifetime)
		policy.WorkloadLeases = parents
		update, err := visitorlease.Decode(controlv1.VisitorPolicyUpdate{Policy: policy, SnapshotRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.prepared.policy.Apply(r, update); err != nil {
			t.Fatal(err)
		}
	}
	parent := controlv1.VisitorWorkloadLease{SessionId: binding.subject.WorkloadSessionID, KeySha256: "fixture", ExpiresAt: time.Now().Add(time.Minute)}
	apply([]controlv1.VisitorWorkloadLease{parent})
	if !b.connectorPeerPolicyCurrent(binding) {
		t.Fatal("current background workload could not become ready")
	}
	parent.ExpiresAt = time.Now().Add(-time.Second)
	apply([]controlv1.VisitorWorkloadLease{parent})
	if b.connectorPeerPolicyCurrent(binding) {
		t.Fatal("expired workload retained installation readiness")
	}
	apply(nil)
	if b.connectorPeerPolicyCurrent(binding) {
		t.Fatal("removed workload retained installation readiness")
	}
	if control.calls != 1 {
		t.Fatal("local readiness check fetched delivery")
	}
}
