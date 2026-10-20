package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
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

func TestTraceVisitorGoldenFramedWireAndUnknownFields(t *testing.T) {
	const payload = `{"trace_context":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"protocol_version":1,"kind":"visitor","visitor_connection_id":"v","public_url_id":"u","publish_run_id":"r","publish_run_number":1,"publisher_connection_id":"p","connection_assignment_revision":1}`
	want := VisitorStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: 1, Kind: VisitorStream, VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 1, PublisherConnectionID: "p", ConnectionAssignmentRevision: 1}
	var wire bytes.Buffer
	if err := WriteVisitorStreamHeader(&wire, want); err != nil {
		t.Fatal(err)
	}
	expected, _ := io.ReadAll(frame(payload))
	if !bytes.Equal(wire.Bytes(), expected) {
		t.Fatalf("wire = %q", wire.Bytes())
	}
	// reading the telemetry frame must leave the encrypted visitor bytes intact.
	withVisitor := append(append([]byte{}, wire.Bytes()...), []byte("\x16\x03visitor")...)
	r := bytes.NewReader(withVisitor)
	got, err := ReadVisitorStreamHeader(r)
	if err != nil || got != want {
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
		if _, err := ReadVisitorStreamHeader(frame(bad)); err == nil {
			t.Fatal("accepted invalid telemetry")
		}
	}
}

func TestTraceForwardingMaximumFrameAllFields(t *testing.T) {
	now := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	h := InternalForwardingHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: InternalForwardingStream,
		VisitorConnectionID: strings.Repeat("v", 32), PublicURLID: strings.Repeat("u", 32), PublishRunID: strings.Repeat("r", 32), PublishRunNumber: math.MaxUint64,
		PublisherConnectionID: strings.Repeat("p", 32), ConnectionSlot: 1, ConnectionAssignmentRevision: math.MaxUint64,
		RelayServiceID: strings.Repeat("s", 32), RelayID: strings.Repeat("i", 32), RelayRunID: strings.Repeat("r", 32), RelayLeaseRevision: math.MaxUint64,
		PublicUrlExpiresAt: now, LeaseExpiresAt: now, AccessPending: true}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	padding := MaxHeaderBytes - len(data)
	if padding < 0 {
		t.Fatalf("all fields need %d bytes, cap is %d", len(data), MaxHeaderBytes)
	}
	h.RelayID += strings.Repeat("x", padding)
	var wire bytes.Buffer
	if err := WriteInternalForwardingHeader(&wire, h); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(wire.Bytes()[:4]); got != MaxHeaderBytes {
		t.Fatal(got)
	}
	got, private, err := ReadForwardingHeader(&wire)
	if err != nil || private != nil || got != h {
		t.Fatal(got, private, err)
	}
	h.RelayID += "x"
	if err := WriteInternalForwardingHeader(&wire, h); err == nil {
		t.Fatal("over-limit frame accepted")
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
		h := VisitorStreamHeader{TraceContext: tc, ProtocolVersion: 1, Kind: VisitorStream, VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 1, PublisherConnectionID: "p", ConnectionAssignmentRevision: 1}
		if err := WriteVisitorStreamHeader(&wire, h); err == nil {
			got, err := ReadVisitorStreamHeader(&wire)
			if err != nil || got != h {
				t.Fatal("trace round trip", err)
			}
		}
		entry := PrivateVisitorEntry{TraceContext: tc, ProtocolVersion: 1, Kind: PrivateVisitorStream, PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1}
		wire.Reset()
		if err := WritePrivateVisitorEntry(&wire, entry); err == nil {
			got, err := ReadPrivateVisitorEntry(&wire)
			if err != nil || got != entry {
				t.Fatal("private trace round trip", err)
			}
		}
	})
}

func TestTracePrivateGoldenAndEveryHeaderValidation(t *testing.T) {
	entry := PrivateVisitorEntry{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: 1, Kind: PrivateVisitorStream, PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 7}
	const golden = `{"trace_context":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"protocol_version":1,"kind":"private_visitor","private_service_id":"psvc_aaaaaaaaaaaaaaaaaaaaaa","private_run_id":"psrun_aaaaaaaaaaaaaaaaaaaaaa","run_number":7}`
	var wire bytes.Buffer
	if err := WritePrivateVisitorEntry(&wire, entry); err != nil {
		t.Fatal(err)
	}
	want, _ := io.ReadAll(frame(golden))
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("private entry golden changed: %s", wire.Bytes())
	}
	got, err := ReadPrivateVisitorEntry(&wire)
	if err != nil || got != entry {
		t.Fatal(got, err)
	}
	for _, extra := range []string{`"baggage":"tenant=evil",`, `"tracestate":"vendor=state",`} {
		bad := strings.Replace(golden, `"traceparent":`, extra+`"traceparent":`, 1)
		if _, err := ReadPrivateVisitorEntry(frame(bad)); err == nil {
			t.Fatal("accepted unknown private telemetry field")
		}
	}
	bad := TraceContext{TraceParent: "invalid"}
	for _, validate := range []func() error{
		func() error { return (VisitorStreamHeader{TraceContext: bad}).Validate() },
		func() error { return (InternalForwardingHeader{TraceContext: bad}).Validate() },
		func() error { return (PrivateStreamHeader{TraceContext: bad}).Validate() },
		func() error {
			return (PrivateForwardingHeader{PrivateStreamHeader: PrivateStreamHeader{TraceContext: bad}}).Validate()
		},
		func() error { e := entry; e.TraceContext = bad; return e.Validate() },
	} {
		if err := validate(); err == nil || err.Error() != "tunnelv1: invalid trace context" {
			t.Fatalf("header missed telemetry validation: %v", err)
		}
	}
}

func TestTracePrivateMaximumFieldsFitExistingFrameCap(t *testing.T) {
	now := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	h := PrivateForwardingHeader{PrivateStreamHeader: PrivateStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: 1, Kind: PrivateForwardingStream,
		PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: math.MaxUint64,
		SourceIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: math.MaxUint64, ExpiresAt: now,
		Connector: &ConnectorAdmission{SessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: strings.Repeat("d", 128), GrantRevision: math.MaxUint64}},
		ConnectionSlot: 1, RelayServiceID: strings.Repeat("s", 128), RelayID: strings.Repeat("r", 128), RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: math.MaxUint64, LeaseExpiresAt: now}
	for _, direct := range []bool{false, true} {
		if direct {
			h.Connector = nil
			h.Direct = &DirectAdmission{IngressID: strings.Repeat("i", 128), IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: math.MaxUint64, DestinationPort: math.MaxUint16}
		}
		var wire bytes.Buffer
		if err := WritePrivateForwardingHeader(&wire, h); err != nil {
			t.Fatal("max private header no longer fits cap", err)
		}
		_, got, err := ReadForwardingHeader(&wire)
		if err != nil || got == nil || got.TraceContext != h.TraceContext || got.Direct == nil && direct {
			t.Fatal(got, err)
		}
		h.Kind = PrivateVisitorStream
		if err := WritePrivateStreamHeader(&wire, h.PrivateStreamHeader); err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadPrivateStreamHeader(&wire)
		if err != nil || decoded.TraceContext != h.TraceContext {
			t.Fatal(decoded, err)
		}
		h.Kind = PrivateForwardingStream
	}
}
