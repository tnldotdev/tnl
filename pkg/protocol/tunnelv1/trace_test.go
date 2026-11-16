package tunnelv1

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const goldenTraceParent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

func TestTraceContextCanonicalAndBounded(t *testing.T) {
	for _, value := range []string{"", goldenTraceParent, strings.TrimSuffix(goldenTraceParent, "01") + "00"} {
		if err := (TraceContext{TraceParent: value}).Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{
		" " + goldenTraceParent, goldenTraceParent + " ", strings.ToUpper(goldenTraceParent),
		"01" + goldenTraceParent[2:], goldenTraceParent[:53] + "02", goldenTraceParent[:53] + "ff",
		goldenTraceParent[:3] + strings.Repeat("0", 32) + goldenTraceParent[35:],
		goldenTraceParent[:36] + strings.Repeat("0", 16) + goldenTraceParent[52:],
		goldenTraceParent + "-extra", strings.Repeat("a", 4096),
	} {
		if err := (TraceContext{TraceParent: value}).Validate(); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestTraceServiceGoldenFramedWireAndUnknownFields(t *testing.T) {
	want := publicServiceAdmissionFixture()
	want.TraceContext = TraceContext{goldenTraceParent}
	want.ExpiresAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	want.ServingUntil = time.Date(2026, 1, 2, 3, 5, 5, 0, time.UTC)
	const payload = `{"trace_context":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"protocol_version":1,"kind":"service_forward","service_id":"svc_aaaaaaaaaaaaaaaaaaaaaa","service_run_id":"srun_aaaaaaaaaaaaaaaaaaaaaa","public_service":{"ingress_id":"ingress-a","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa","ingress_lease_revision":1,"destination_port":25443},"source_ip":"192.0.2.10","run_number":1,"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","publisher_connection_id":"pc_aaaaaaaaaaaaaaaaaaaaaa","connection_assignment_revision":2,"expires_at":"2026-01-02T03:04:05Z","connection_slot":0,"relay_service_id":"relay","relay_id":"relay-a","relay_run_id":"rr_aaaaaaaaaaaaaaaaaaaaaa","relay_lease_revision":1,"serving_until":"2026-01-02T03:05:05Z"}`
	var wire bytes.Buffer
	if err := WriteServiceForwardingHeader(&wire, want); err != nil {
		t.Fatal(err)
	}
	expected, _ := io.ReadAll(frame(payload))
	if !bytes.Equal(wire.Bytes(), expected) {
		t.Fatalf("wire = %q", wire.Bytes())
	}
	// reading the telemetry frame must leave the encrypted visitor bytes intact.
	withVisitor := append(append([]byte{}, wire.Bytes()...), []byte("\x16\x03visitor")...)
	r := bytes.NewReader(withVisitor)
	got, err := ReadServiceForwardingHeader(r)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "\x16\x03visitor" {
		t.Fatalf("visitor changed: %q", rest)
	}
	for _, bad := range []string{
		strings.Replace(payload, `"traceparent":`, `"baggage":"tenant=other","traceparent":`, 1),
		strings.Replace(payload, `"traceparent":`, `"tracestate":"other=state","traceparent":`, 1),
		strings.Replace(payload, goldenTraceParent, strings.ToUpper(goldenTraceParent), 1),
	} {
		if _, err := ReadServiceForwardingHeader(frame(bad)); err == nil {
			t.Fatal("accepted invalid telemetry")
		}
	}
}

func FuzzWireTraceContext(f *testing.F) {
	f.Add(goldenTraceParent)
	f.Add("")
	f.Add("00-00000000000000000000000000000000-0000000000000000-00")
	f.Fuzz(func(t *testing.T, parent string) {
		tc := TraceContext{parent}
		if tc.Validate() == nil && parent != "" && len(parent) != 55 {
			t.Fatal("unbounded trace context")
		}
		var wire bytes.Buffer
		h := publicServiceAdmissionFixture()
		h.TraceContext = tc
		if err := WriteServiceForwardingHeader(&wire, h); err == nil {
			got, err := ReadServiceForwardingHeader(&wire)
			if err != nil || !bytes.Equal(wireJSON(t, got), wireJSON(t, h)) {
				t.Fatal("trace round trip", err)
			}
		}
		entry := peerOpeningFixture()
		entry.TraceContext = tc
		wire.Reset()
		if err := WriteConnectorPeerVisitorEntry(&wire, entry); err == nil {
			got, err := ReadConnectorPeerVisitorEntry(&wire)
			if err != nil || got != entry {
				t.Fatal("private trace round trip", err)
			}
		}
	})
}

func TestTracePrivateGoldenAndEveryHeaderValidation(t *testing.T) {
	entry := peerOpeningFixture()
	entry.TraceContext = TraceContext{goldenTraceParent}
	var compact bytes.Buffer
	if err := json.Compact(&compact, readFixture(t, "connector-peer-visitor-entry.json")); err != nil {
		t.Fatal(err)
	}
	golden := `{"trace_context":{"traceparent":"` + goldenTraceParent + `"},` + strings.TrimPrefix(compact.String(), "{")
	var wire bytes.Buffer
	if err := WriteConnectorPeerVisitorEntry(&wire, entry); err != nil {
		t.Fatal(err)
	}
	want, _ := io.ReadAll(frame(golden))
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("private entry golden changed: %s", wire.Bytes())
	}
	got, err := ReadConnectorPeerVisitorEntry(&wire)
	if err != nil || got != entry {
		t.Fatal(got, err)
	}
	for _, extra := range []string{`"baggage":"tenant=evil",`, `"tracestate":"vendor=state",`} {
		bad := strings.Replace(golden, `"traceparent":`, extra+`"traceparent":`, 1)
		if _, err := ReadConnectorPeerVisitorEntry(frame(bad)); err == nil {
			t.Fatal("accepted unknown private telemetry field")
		}
	}
	bad := TraceContext{TraceParent: "invalid"}
	for _, validate := range []func() error{
		func() error {
			return (ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{TraceContext: bad}}).Validate()
		},
		func() error { e := entry; e.TraceContext = bad; return e.Validate() },
	} {
		if err := validate(); err == nil || err.Error() != "tunnelv1: invalid trace context" {
			t.Fatalf("header missed telemetry validation: %v", err)
		}
	}
}

func TestTracePrivateMaximumFieldsFitFrameCap(t *testing.T) {
	now := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("max", 23*3600+59*60))
	h := ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: 1, Kind: ServiceForwardingStream,
		ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: math.MaxUint64,
		SourceIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: math.MaxUint64, ExpiresAt: now,
		PublicService: &PublicServiceAdmission{IngressID: strings.Repeat("\x01", 256), IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: math.MaxUint64, DestinationPort: math.MaxUint16}},
		ConnectionSlot: 1, RelayServiceID: strings.Repeat("\x01", 256), RelayID: strings.Repeat("\x01", 256), RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: math.MaxUint64, ServingUntil: now}
	{
		var wire bytes.Buffer
		if err := WriteServiceForwardingHeader(&wire, h); err != nil {
			t.Fatal("max private header no longer fits cap", err)
		}
		t.Logf("maximum public service protocol header: %d JSON bytes", wire.Len()-4)
		got, err := ReadServiceForwardingHeader(&wire)
		if err != nil || got.TraceContext != h.TraceContext || got.PublicService == nil {
			t.Fatal(got, err)
		}
		for _, mutate := range []func(*ServiceForwardingHeader){
			func(bad *ServiceForwardingHeader) { bad.RelayServiceID += "x" },
			func(bad *ServiceForwardingHeader) { bad.RelayID += "x" },
			func(bad *ServiceForwardingHeader) {
				admission := *bad.PublicService
				admission.IngressID += "x"
				bad.PublicService = &admission
			},
		} {
			bad := h
			mutate(&bad)
			if err := WriteServiceForwardingHeader(&wire, bad); err == nil || wire.Len() != 0 {
				t.Fatal("oversized private identifier wrote bytes")
			}
		}
	}
}

func TestServiceHeaderCapAndUnknownFields(t *testing.T) {
	h := ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: ServiceForwardingStream,
		ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1, SourceIP: "192.0.2.1",
		VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now(),
		PublicService: &PublicServiceAdmission{IngressID: "i", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 1024}},
		RelayServiceID: "s", RelayID: "i", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, ServingUntil: time.Now()}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	atLimit := string(data) + strings.Repeat(" ", MaxServiceHeaderBytes-len(data))
	reader := io.MultiReader(frame(atLimit), strings.NewReader("visitor bytes"))
	if _, err := ReadServiceForwardingHeader(reader); err != nil {
		t.Fatalf("selected kind exact cap rejected: %v", err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "visitor bytes" {
		t.Fatal("overconsumed visitor bytes")
	}
	for _, bad := range []string{atLimit + " ", strings.Replace(string(data), `"traceparent":`, `"baggage":"untrusted","traceparent":`, 1), strings.Replace(string(data), goldenTraceParent, "bad", 1)} {
		if _, err := ReadServiceForwardingHeader(frame(bad)); err == nil {
			t.Fatal("accepted overcap or unknown/bad trace fields")
		}
	}
}

func wireJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
