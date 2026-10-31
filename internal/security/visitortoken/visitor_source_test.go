package visitortoken

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func sourceProofFixture(t *testing.T) ([32]byte, tunnelv1.VisitorSourceProof, tunnelv1.VisitorSourceBinding, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	master, err := PublicVisitorSourceKey(bytes.Repeat([]byte{1}, 32), "run", 1)
	if err != nil {
		t.Fatal(err)
	}
	authority, child, err := IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{PublicURLID: "public-url", PublishRunID: "run", PublishRunNumber: 1,
		IngressID: "ingress", IngressRunID: "process", IngressLeaseRevision: 2, VisitorPolicyRevision: 3, ValidUntil: now.Add(PolicyLifetime).Unix()}, now)
	if err != nil {
		t.Fatal(err)
	}
	binding := tunnelv1.VisitorSourceBinding{PublicURLID: "public-url", PublishRunID: "run", PublishRunNumber: 1, VisitorID: "visitor",
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
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) { b.VisitorID = "other-visitor" },
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) { b.PublicURLID = "other-url" },
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) { b.PublishRunID = "other-run" },
		func(_ *tunnelv1.VisitorSourceProof, b *tunnelv1.VisitorSourceBinding) { b.PublishRunNumber++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.Sequence++ },
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressID = "other-ingress"
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressRunID = "restarted"
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) {
			p.Authority.IngressLeaseRevision++
		},
		func(p *tunnelv1.VisitorSourceProof, _ *tunnelv1.VisitorSourceBinding) { p.Authority.ValidUntil++ },
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
	for _, at := range []time.Time{now.Add(PolicyLifetime), now.Add(time.Minute), now.Add(-time.Second)} {
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
	forged.IngressRunID = "restarted"
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
	first, err := PublicVisitorSourceKey(digest, "run", 1)
	if err != nil {
		t.Fatal(err)
	}
	otherRun, _ := PublicVisitorSourceKey(digest, "other-run", 1)
	otherNumber, _ := PublicVisitorSourceKey(digest, "run", 2)
	otherSecret, _ := PublicVisitorSourceKey(bytes.Repeat([]byte{2}, 32), "run", 1)
	if first == otherRun || first == otherNumber || first == otherSecret || bytes.Equal(first[:], digest) {
		t.Fatal("source key derivation lost its purpose or run boundary")
	}
	if _, err := PublicVisitorSourceKey(nil, "run", 1); !errors.Is(err, ErrVisitorSource) {
		t.Fatal("missing run secret produced a source key", err)
	}
}
