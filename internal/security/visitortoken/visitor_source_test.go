package visitortoken

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func sourceProofFixture(t *testing.T) ([32]byte, tunnelv1.VisitorSourceProof, tunnelv1.VisitorSourceBinding, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	master, err := ServiceVisitorSourceKey(bytes.Repeat([]byte{1}, 32), "srun_"+strings.Repeat("B", 22), 1)
	if err != nil {
		t.Fatal(err)
	}
	authority, child, err := IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{ServiceID: "svc_" + strings.Repeat("A", 22), ServiceRunID: "srun_" + strings.Repeat("B", 22), RunNumber: 1, EndpointRevision: 4,
		IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("D", 22), IngressLeaseRevision: 2, VisitorPolicyRevision: 3, ValidUntil: now.Add(PolicyLifetime).Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := tunnelv1.VisitorSourceBinding{ServiceID: "svc_" + strings.Repeat("A", 22), ServiceRunID: "srun_" + strings.Repeat("B", 22), RunNumber: 1, VisitorConnectionID: "vc_" + strings.Repeat("C", 22),
		Source: netip.MustParseAddrPort("192.0.2.1:3000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	proof, err := SignVisitorSource(child, authority, 1, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	return master, proof, binding, now
}

func TestVisitorSourceProofBindsRunProcessSequenceAndTrustedEndpoints(t *testing.T) {
	master, proof, binding, now := sourceProofFixture(t)
	if err := VerifyVisitorSource(master, proof, binding, 3, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*tunnelv1.VisitorSourceProof, *tunnelv1.VisitorSourceBinding){
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.Source = netip.MustParseAddrPort("198.51.100.1:3000")
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.Source = netip.MustParseAddrPort("192.0.2.1:3001")
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.Destination = netip.MustParseAddrPort("203.0.113.2:443")
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.Destination = netip.MustParseAddrPort("203.0.113.1:25443")
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.VisitorConnectionID = "vc_" + strings.Repeat("G", 22)
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.ServiceID = "svc_" + strings.Repeat("E", 22)
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) {
			b.ServiceRunID = "srun_" + strings.Repeat("F", 22)
		},
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) { b.RunNumber++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.Sequence++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.ObservedAt++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressID = "other-ingress"
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressRunID = "ir_" + strings.Repeat("H", 22)
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressLeaseRevision++
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.Authority.ValidUntil++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.Authority.EndpointRevision++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.VisitorPolicyRevision--
		},
	} {
		changed, endpoints := proof, binding
		mutate(&changed, &endpoints)
		if err := VerifyVisitorSource(master, changed, endpoints, 3, now); !errors.Is(err, ErrVisitorSource) {
			t.Fatal("rewritten forwarding facts were accepted", err)
		}
	}
}

func TestVisitorSourceDelegationCannotExtendAuthorityOrBecomeAMaster(t *testing.T) {
	master, proof, binding, now := sourceProofFixture(t)
	// a receiver's earlier authority-time estimate is not a shared-clock
	// not-before bound. expiry remains fixed at the actual delegation deadline.
	for _, at := range []time.Time{now.Add(PolicyLifetime), now.Add(time.Minute)} {
		if err := VerifyVisitorSource(master, proof, binding, 3, at); !errors.Is(err, ErrVisitorSource) {
			t.Fatal("proof escaped its original delegation deadline", err)
		}
	}
	if err := VerifyVisitorSource(master, proof, binding, 4, now); err != nil {
		t.Fatal("a newer access policy invalidated still-current source evidence", err)
	}
	for _, revision := range []int64{0, 2} {
		if err := VerifyVisitorSource(master, proof, binding, revision, now); !errors.Is(err, ErrVisitorSource) {
			t.Fatal("source proof outran installed access policy", err)
		}
	}
	child := visitorSourceChildKey(master, proof.Authority)
	forged := proof.Authority
	forged.IngressRunID = "ir_" + strings.Repeat("H", 22)
	authority, wrongChild, err := IssueVisitorSourceAuthority(child, forged, now)
	if err != nil {
		t.Fatal(err)
	}
	forgedProof, err := SignVisitorSource(wrongChild, authority, 2, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyVisitorSource(master, forgedProof, binding, 3, now); !errors.Is(err, ErrVisitorSource) {
		t.Fatal("delegated ingress key minted another process's authority", err)
	}
	if _, err := SignVisitorSource(child, proof.Authority, 2, binding, now.Add(PolicyLifetime)); !errors.Is(err, ErrVisitorSource) {
		t.Fatal("expired ingress delegation minted new evidence", err)
	}
}

func TestVisitorSourceKeysArePurposeAndRunBound(t *testing.T) {
	digest := bytes.Repeat([]byte{1}, 32)
	first, err := ServiceVisitorSourceKey(digest, "srun_"+strings.Repeat("B", 22), 1)
	if err != nil {
		t.Fatal(err)
	}
	otherRun, _ := ServiceVisitorSourceKey(digest, "srun_"+strings.Repeat("F", 22), 1)
	otherNumber, _ := ServiceVisitorSourceKey(digest, "srun_"+strings.Repeat("B", 22), 2)
	otherSecret, _ := ServiceVisitorSourceKey(bytes.Repeat([]byte{2}, 32), "srun_"+strings.Repeat("B", 22), 1)
	if first == otherRun || first == otherNumber || first == otherSecret || bytes.Equal(first[:], digest) {
		t.Fatal("source key derivation lost its purpose or run boundary")
	}
	if _, err := ServiceVisitorSourceKey(nil, "srun_"+strings.Repeat("B", 22), 1); !errors.Is(err, ErrVisitorSource) {
		t.Fatal("missing run secret produced a source key", err)
	}
}
