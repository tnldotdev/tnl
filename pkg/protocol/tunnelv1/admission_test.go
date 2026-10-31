package tunnelv1

import (
	"bytes"
	"strings"
	"testing"
)

func TestAdmissionIdentityAndFrameBounds(t *testing.T) {
	h := AdmissionHeader{ProtocolVersion: Version, Kind: IngressPromotion, VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 2,
		PublisherConnectionID: "p", ConnectionSlot: 1, ConnectionAssignmentRevision: 3, RelayServiceID: "s", RelayID: "relay", RelayRunID: "run", RelayLeaseRevision: 4}
	for _, change := range []func(*AdmissionHeader){
		func(h *AdmissionHeader) { h.ProtocolVersion++ }, func(h *AdmissionHeader) { h.ConnectionSlot = 2 },
		func(h *AdmissionHeader) { h.PublishRunNumber = 0 }, func(h *AdmissionHeader) { h.ConnectionAssignmentRevision = 0 },
		func(h *AdmissionHeader) { h.RelayRunID = "" }, func(h *AdmissionHeader) { h.RelayLeaseRevision = 0 },
		func(h *AdmissionHeader) { h.Kind = PublisherPromotion }, func(h *AdmissionHeader) { h.VisitorConnectionID = "" },
	} {
		bad := h
		change(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	h.VisitorConnectionID = strings.Repeat("\x01", 256)
	h.PublishRunID = strings.Repeat("\x01", 256)
	h.PublisherConnectionID = strings.Repeat("\x01", 256)
	h.PublicURLID = strings.Repeat("\x01", 256)
	h.RelayServiceID = strings.Repeat("\x01", 256)
	h.RelayID = strings.Repeat("\x01", 256)
	h.RelayRunID = strings.Repeat("\x01", 256)
	var out bytes.Buffer
	if h.Validate() != nil {
		t.Fatal("valid long identifiers rejected before aggregate bound")
	}
	if err := WriteReturnFrame(&out, ReturnFrame{Kind: ReturnPromoted, Promotion: h}); err != nil {
		t.Fatal("supported admission identifiers exceeded aggregate cap", err)
	}
	if got, err := ReadReturnFrame(&out); err != nil || got.Promotion != h {
		t.Fatal("maximum admission header did not round trip", err)
	}
	h.RelayID += "x"
	if err := WriteReturnFrame(&out, ReturnFrame{Kind: ReturnPromoted, Promotion: h}); err == nil || out.Len() != 0 {
		t.Fatal("oversized admission identifier wrote bytes")
	}
}
