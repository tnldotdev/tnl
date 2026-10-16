package tunnelv1

import (
	"bytes"
	"strings"
	"testing"
)

func TestAdmissionIdentityAndFrameBounds(t *testing.T) {
	h, err := ReadAdmissionHeader(bytes.NewReader(goldenWire(t, "ingress-admission-header")))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*AdmissionHeader){
		func(h *AdmissionHeader) { h.ProtocolVersion++ }, func(h *AdmissionHeader) { h.ConnectionSlot = 2 },
		func(h *AdmissionHeader) { h.PublishRunNumber = 0 }, func(h *AdmissionHeader) { h.ConnectionAssignmentRevision = 0 },
		func(h *AdmissionHeader) { h.RelayRunID = "" }, func(h *AdmissionHeader) { h.RelayLeaseRevision = 0 },
		func(h *AdmissionHeader) { h.Kind = PublisherAdmissionStream }, func(h *AdmissionHeader) { h.VisitorConnectionID = "" },
	} {
		bad := h
		change(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	h.VisitorConnectionID = strings.Repeat("v", 256)
	h.PublishRunID = strings.Repeat("r", 256)
	h.PublisherConnectionID = strings.Repeat("p", 256)
	h.PublicURLID = strings.Repeat("u", 256)
	var out bytes.Buffer
	if h.Validate() != nil {
		t.Fatal("valid long identifiers rejected before aggregate bound")
	}
	if WriteAdmissionHeader(&out, h) == nil || out.Len() != 0 {
		t.Fatal("oversized admission wrote bytes")
	}
	for _, payload := range []string{
		`{"type":"accepted","code":"capacity_exceeded"}`, `{"type":"rejected"}`, `{"type":"rejected","code":"unknown"}`, `{"type":"accepted","extra":true}`,
	} {
		if _, err := ReadAdmissionResult(frame(payload)); err == nil {
			t.Fatal(payload)
		}
	}
}
