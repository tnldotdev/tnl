package proxyproto

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestVisitorSourceProofTLVPreservesEndpointsAndVisitorBytes(t *testing.T) {
	header := Header{Source: netip.MustParseAddrPort("192.0.2.1:3000"), Destination: netip.MustParseAddrPort("203.0.113.1:443"), VisitorSourceProof: "proof bytes"}
	wire, err := Encode(header)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("visitor TLS")
	got, remaining, err := Decode(bytes.NewReader(append(bytes.Clone(wire), payload...)))
	if err != nil || got != header {
		t.Fatal("source proof or endpoints changed", err)
	}
	assertReplay(t, remaining, payload)
	duplicate := appendTLVs(wire, []byte{tunnelv1.VisitorSourceProofTLV, 0, 1, 'x'})
	_, _, err = Decode(bytes.NewReader(duplicate))
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Code != ErrorDuplicateSourceProof {
		t.Fatal("duplicate source attestation was accepted", err)
	}
	header.VisitorSourceProof = strings.Repeat("x", tunnelv1.MaxVisitorSourceProofBytes+1)
	if _, err := Encode(header); !errors.As(err, &protocol) || protocol.Code != ErrorInvalidLength {
		t.Fatal("unbounded source proof was encoded", err)
	}
}
