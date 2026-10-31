package tunnelv1

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVisitorSourceProofWireAndBounds(t *testing.T) {
	proof := VisitorSourceProof{Authority: VisitorSourceAuthority{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 1, IngressID: "ingress", IngressRunID: "process",
		IngressLeaseRevision: 2, VisitorPolicyRevision: 3, ValidUntil: 1_800_000_010, MAC: bytes.Repeat([]byte{1}, 32)}, Sequence: 4, MAC: bytes.Repeat([]byte{2}, 32)}
	wire, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"authority":{"public_url_id":"url","publish_run_id":"run","publish_run_number":1,"ingress_id":"ingress","ingress_run_id":"process","ingress_lease_revision":2,"visitor_policy_revision":3,"valid_until":1800000010,"mac":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"sequence":4,"mac":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}`
	if string(wire) != want {
		t.Fatal("source proof wire contract changed")
	}
	parsed, err := ReadVisitorSourceProof(wire)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := parsed.MarshalBinary()
	if err != nil || !bytes.Equal(roundTrip, wire) {
		t.Fatal("source proof did not round trip", err)
	}
	for _, invalid := range []string{"", "null", "{}", want + " {}", strings.Repeat(" ", MaxVisitorSourceProofBytes+1), strings.Replace(want, `"sequence":4`, `"sequence":0`, 1), strings.Replace(want, `"sequence":4`, `"sequence":4,"capacity":10`, 1)} {
		if _, err := ReadVisitorSourceProof([]byte(invalid)); !errors.Is(err, ErrVisitorSourceProof) {
			t.Fatal("unbounded or incomplete source proof accepted", err)
		}
	}
}

func TestVisitorSourceAuthorityWireAndBounds(t *testing.T) {
	authority := VisitorSourceAuthority{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 1, IngressID: "ingress", IngressRunID: "process",
		IngressLeaseRevision: 2, VisitorPolicyRevision: 3, ValidUntil: 1_800_000_010, MAC: bytes.Repeat([]byte{1}, 32)}
	wire, err := authority.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"public_url_id":"url","publish_run_id":"run","publish_run_number":1,"ingress_id":"ingress","ingress_run_id":"process","ingress_lease_revision":2,"visitor_policy_revision":3,"valid_until":1800000010,"mac":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`
	if string(wire) != want {
		t.Fatal("source authority wire contract changed")
	}
	parsed, err := ReadVisitorSourceAuthority(wire)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := parsed.MarshalBinary()
	if err != nil || !bytes.Equal(roundTrip, wire) {
		t.Fatal("authority did not round trip", err)
	}
	for _, invalid := range []string{"", "null", "{}", want + " {}", strings.Repeat(" ", MaxVisitorSourceAuthorityBytes+1), strings.Replace(want, `"ingress_lease_revision":2`, `"ingress_lease_revision":0`, 1), strings.Replace(want, `"run"`, `"run","capacity":10`, 1)} {
		if _, err := ReadVisitorSourceAuthority([]byte(invalid)); !errors.Is(err, ErrVisitorSourceProof) {
			t.Fatal("unbounded or incomplete source authority accepted", err)
		}
	}
}

func FuzzVisitorSourceProof(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		proof, err := ReadVisitorSourceProof(wire)
		if err != nil {
			return
		}
		encoded, err := proof.MarshalBinary()
		if err != nil || len(encoded) > MaxVisitorSourceProofBytes {
			t.Fatal("accepted source proof cannot be bounded on write", err)
		}
		if _, err := ReadVisitorSourceProof(encoded); err != nil {
			t.Fatal("accepted source proof cannot round trip", err)
		}
	})
}

func FuzzVisitorSourceAuthority(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, wire []byte) {
		authority, err := ReadVisitorSourceAuthority(wire)
		if err != nil {
			return
		}
		encoded, err := authority.MarshalBinary()
		if err != nil || len(encoded) > MaxVisitorSourceAuthorityBytes {
			t.Fatal("accepted source authority cannot be bounded on write", err)
		}
		if _, err := ReadVisitorSourceAuthority(encoded); err != nil {
			t.Fatal("accepted source authority cannot round trip", err)
		}
	})
}
