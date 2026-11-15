package tunnelv1

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func sourceAuthorityFixture() VisitorSourceAuthority {
	return VisitorSourceAuthority{
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1, EndpointRevision: 5,
		IngressID: "ingress", IngressRunID: "ir_1234567890123456789012",
		IngressLeaseRevision: 2, VisitorPolicyRevision: 3, ValidUntil: 1_800_000_010,
		MAC: bytes.Repeat([]byte{1}, 32),
	}
}

func TestVisitorSourceProofWireAndBounds(t *testing.T) {
	proof := VisitorSourceProof{Authority: sourceAuthorityFixture(), Sequence: 4, ObservedAt: 1_800_000_000_000_000, MAC: bytes.Repeat([]byte{2}, 32)}
	wire, err := proof.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"authority":{"service_id":"svc_1234567890123456789012","service_run_id":"srun_1234567890123456789012","run_number":1,"endpoint_revision":5,"ingress_id":"ingress","ingress_run_id":"ir_1234567890123456789012","ingress_lease_revision":2,"visitor_policy_revision":3,"valid_until":1800000010,"mac":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},"sequence":4,"observed_at_us":1800000000000000,"mac":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}`
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
	for _, invalid := range []string{
		"", "null", "{}", want + " {}", strings.Repeat(" ", MaxVisitorSourceProofBytes+1),
		strings.Replace(want, `"sequence":4`, `"sequence":0`, 1),
		strings.Replace(want, `"observed_at_us":1800000000000000,`, "", 1),
		strings.Replace(want, `"observed_at_us":1800000000000000`, `"observed_at_us":0`, 1),
		strings.Replace(want, `"observed_at_us":1800000000000000`, `"observed_at_us":1800000010000000`, 1),
		strings.Replace(want, `"sequence":4`, `"sequence":4,"capacity":10`, 1),
		strings.Replace(want, `"service_id":`, `"public_url_id":"old","service_id":`, 1),
	} {
		if _, err := ReadVisitorSourceProof([]byte(invalid)); !errors.Is(err, ErrVisitorSourceProof) {
			t.Fatal("old, unbounded or incomplete source proof accepted", err)
		}
	}
	binding := VisitorSourceBinding{
		ServiceID: proof.Authority.ServiceID, ServiceRunID: proof.Authority.ServiceRunID,
		RunNumber: proof.Authority.RunNumber, VisitorConnectionID: "vc_1234567890123456789012",
		Source: netip.MustParseAddrPort("192.0.2.1:3000"), Destination: netip.MustParseAddrPort("203.0.113.1:443"),
	}
	if _, err := proof.SigningBytes(binding); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []func(*VisitorSourceBinding){
		func(b *VisitorSourceBinding) { b.ServiceID = "svc_aaaaaaaaaaaaaaaaaaaaaa" },
		func(b *VisitorSourceBinding) { b.ServiceRunID = "srun_aaaaaaaaaaaaaaaaaaaaaa" },
		func(b *VisitorSourceBinding) { b.RunNumber++ },
		func(b *VisitorSourceBinding) { b.VisitorConnectionID = "" },
		func(b *VisitorSourceBinding) { b.Source = netip.AddrPort{} },
	} {
		changed := binding
		wrong(&changed)
		if _, err := proof.SigningBytes(changed); !errors.Is(err, ErrVisitorSourceProof) {
			t.Fatal("foreign source binding accepted", err)
		}
	}
}

func TestVisitorSourceAuthorityWireAndBounds(t *testing.T) {
	authority := sourceAuthorityFixture()
	wire, err := authority.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"service_id":"svc_1234567890123456789012","service_run_id":"srun_1234567890123456789012","run_number":1,"endpoint_revision":5,"ingress_id":"ingress","ingress_run_id":"ir_1234567890123456789012","ingress_lease_revision":2,"visitor_policy_revision":3,"valid_until":1800000010,"mac":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`
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
	for _, invalid := range []string{
		"", "null", "{}", want + " {}", strings.Repeat(" ", MaxVisitorSourceAuthorityBytes+1),
		strings.Replace(want, `"ingress_lease_revision":2`, `"ingress_lease_revision":0`, 1),
		strings.Replace(want, `"service_run_id":`, `"publish_run_id":"old","service_run_id":`, 1),
		strings.Replace(want, `"run_number":1`, `"run_number":0`, 1),
		strings.Replace(want, `"endpoint_revision":5`, `"endpoint_revision":0`, 1),
		strings.Replace(want, `"endpoint_revision":5,`, "", 1),
	} {
		if _, err := ReadVisitorSourceAuthority([]byte(invalid)); !errors.Is(err, ErrVisitorSourceProof) {
			t.Fatal("old, unbounded or incomplete source authority accepted", err)
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
