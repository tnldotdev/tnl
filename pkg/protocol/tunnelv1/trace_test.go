package tunnelv1

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
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

func TestTraceVisitorGoldenFramedWireAndUnknownFields(t *testing.T) {
	const payload = `{"trace_context":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"protocol_version":2,"kind":"visitor","visitor_connection_id":"v","public_url_id":"u","publish_run_id":"r","publish_run_number":1,"publisher_connection_id":"p","connection_assignment_revision":1}`
	want := VisitorStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 1, PublisherConnectionID: "p", ConnectionAssignmentRevision: 1}
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
	// time.MarshalJSON accepts four-digit years and zone offsets below 24h.
	// a non-UTC offset and nanoseconds give the longest accepted timestamp.
	now := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("max", 23*3600+59*60))
	h := InternalForwardingHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: InternalForwardingStream,
		VisitorConnectionID: strings.Repeat("\x01", 256), PublicURLID: strings.Repeat("\x01", 256), PublishRunID: strings.Repeat("\x01", 256), PublishRunNumber: math.MaxUint64,
		PublisherConnectionID: strings.Repeat("\x01", 256), ConnectionSlot: 1, ConnectionAssignmentRevision: math.MaxUint64,
		RelayServiceID: strings.Repeat("\x01", 256), RelayID: strings.Repeat("\x01", 256), RelayRunID: strings.Repeat("\x01", 256), RelayLeaseRevision: math.MaxUint64,
		PublicUrlExpiresAt: now, LeaseExpiresAt: now, AccessPending: true}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxHeaderBytes {
		t.Fatalf("all fields need %d bytes, cap is %d", len(data), MaxHeaderBytes)
	}
	t.Logf("maximum public protocol header: %d JSON bytes", len(data))
	var wire bytes.Buffer
	if err := WriteInternalForwardingHeader(&wire, h); err != nil {
		t.Fatal(err)
	}
	got, private, err := ReadForwardingHeader(&wire)
	roundTrip, marshalErr := json.Marshal(got)
	if err != nil || marshalErr != nil || private != nil || !bytes.Equal(roundTrip, data) {
		t.Fatal("maximum public header changed", err, marshalErr)
	}
	h.RelayID += "\x01"
	if err := WriteInternalForwardingHeader(&wire, h); err == nil {
		t.Fatal("over-limit identifier accepted")
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
		h := VisitorStreamHeader{TraceContext: tc, ProtocolVersion: Version, Kind: VisitorStream, VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 1, PublisherConnectionID: "p", ConnectionAssignmentRevision: 1}
		if err := WriteVisitorStreamHeader(&wire, h); err == nil {
			got, err := ReadVisitorStreamHeader(&wire)
			if err != nil || got != h {
				t.Fatal("trace round trip", err)
			}
		}
		entry := ConnectorVisitorEntry{TraceContext: tc, ProtocolVersion: Version, Kind: ConnectorVisitorStream, ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1}
		wire.Reset()
		if err := WriteConnectorVisitorEntry(&wire, entry); err == nil {
			got, err := ReadConnectorVisitorEntry(&wire)
			if err != nil || got != entry {
				t.Fatal("private trace round trip", err)
			}
		}
	})
}

func TestTracePrivateGoldenAndEveryHeaderValidation(t *testing.T) {
	entry := ConnectorVisitorEntry{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: ConnectorVisitorStream, ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 7}
	const golden = `{"trace_context":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"protocol_version":2,"kind":"connector_visitor","service_id":"svc_aaaaaaaaaaaaaaaaaaaaaa","service_run_id":"srun_aaaaaaaaaaaaaaaaaaaaaa","run_number":7}`
	var wire bytes.Buffer
	if err := WriteConnectorVisitorEntry(&wire, entry); err != nil {
		t.Fatal(err)
	}
	want, _ := io.ReadAll(frame(golden))
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("private entry golden changed: %s", wire.Bytes())
	}
	got, err := ReadConnectorVisitorEntry(&wire)
	if err != nil || got != entry {
		t.Fatal(got, err)
	}
	for _, extra := range []string{`"baggage":"tenant=evil",`, `"tracestate":"vendor=state",`} {
		bad := strings.Replace(golden, `"traceparent":`, extra+`"traceparent":`, 1)
		if _, err := ReadConnectorVisitorEntry(frame(bad)); err == nil {
			t.Fatal("accepted unknown private telemetry field")
		}
	}
	bad := TraceContext{TraceParent: "invalid"}
	for _, validate := range []func() error{
		func() error { return (VisitorStreamHeader{TraceContext: bad}).Validate() },
		func() error { return (InternalForwardingHeader{TraceContext: bad}).Validate() },
		func() error { return (ServiceStreamHeader{TraceContext: bad}).Validate() },
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
	h := ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: ServiceForwardingStream,
		ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: math.MaxUint64,
		SourceIP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: math.MaxUint64, ExpiresAt: now,
		Connector: &ConnectorAdmission{SessionID: testOpaqueID(opaqueid.ConnectorSessionPrefix), Subject: VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, GrantRevision: math.MaxUint64}},
		ConnectionSlot: 1, RelayServiceID: strings.Repeat("\x01", 256), RelayID: strings.Repeat("\x01", 256), RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: math.MaxUint64, LeaseExpiresAt: now}
	for _, direct := range []bool{false, true} {
		if direct {
			h.Connector = nil
			h.Direct = &DirectAdmission{IngressID: strings.Repeat("\x01", 256), IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: math.MaxUint64, DestinationPort: math.MaxUint16}
		}
		var wire bytes.Buffer
		if err := WriteServiceForwardingHeader(&wire, h); err != nil {
			t.Fatal("max private header no longer fits cap", err)
		}
		t.Logf("maximum private protocol header direct=%t: %d JSON bytes", direct, wire.Len()-4)
		_, got, err := ReadForwardingHeader(&wire)
		if err != nil || got == nil || got.TraceContext != h.TraceContext || got.Direct == nil && direct {
			t.Fatal(got, err)
		}
		h.Kind = ConnectorVisitorStream
		if err := WriteServiceStreamHeader(&wire, h.ServiceStreamHeader); err != nil {
			t.Fatal(err)
		}
		decoded, err := ReadServiceStreamHeader(&wire)
		if err != nil || decoded.TraceContext != h.TraceContext {
			t.Fatal(decoded, err)
		}
		h.Kind = ServiceForwardingStream
		for _, mutate := range []func(*ServiceForwardingHeader){
			func(bad *ServiceForwardingHeader) { bad.RelayServiceID += "x" },
			func(bad *ServiceForwardingHeader) { bad.RelayID += "x" },
			func(bad *ServiceForwardingHeader) {
				if bad.Direct != nil {
					admission := *bad.Direct
					admission.IngressID += "x"
					bad.Direct = &admission
				} else {
					admission := *bad.Connector
					admission.Subject.DeviceID += "x"
					bad.Connector = &admission
				}
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

func TestForwardingDispatchSelectedKindCapsAndUnknownFields(t *testing.T) {
	public := InternalForwardingHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: InternalForwardingStream,
		VisitorConnectionID: "v", PublicURLID: "u", PublishRunID: "r", PublishRunNumber: 1, PublisherConnectionID: "p", ConnectionAssignmentRevision: 1,
		RelayServiceID: "s", RelayID: "i", RelayRunID: "r", RelayLeaseRevision: 1, PublicUrlExpiresAt: time.Now(), LeaseExpiresAt: time.Now()}
	private := ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{TraceContext: TraceContext{goldenTraceParent}, ProtocolVersion: Version, Kind: ServiceForwardingStream,
		ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1, SourceIP: "192.0.2.1",
		VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now(),
		Direct: &DirectAdmission{IngressID: "i", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 1024}},
		RelayServiceID: "s", RelayID: "i", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now()}
	for _, test := range []struct {
		name   string
		header any
		limit  int
	}{{"public", public, MaxHeaderBytes}, {"private", private, MaxServiceHeaderBytes}} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.header)
			if err != nil {
				t.Fatal(err)
			}
			atLimit := string(data) + strings.Repeat(" ", test.limit-len(data))
			reader := io.MultiReader(frame(atLimit), strings.NewReader("visitor bytes"))
			if _, _, err := ReadForwardingHeader(reader); err != nil {
				t.Fatalf("selected kind exact cap rejected: %v", err)
			}
			rest, _ := io.ReadAll(reader)
			if string(rest) != "visitor bytes" {
				t.Fatal("overconsumed visitor bytes")
			}
			for _, bad := range []string{atLimit + " ", strings.Replace(string(data), `"traceparent":`, `"baggage":"untrusted","traceparent":`, 1), strings.Replace(string(data), goldenTraceParent, "bad", 1)} {
				if _, _, err := ReadForwardingHeader(frame(bad)); err == nil {
					t.Fatal("accepted overcap or unknown/bad trace fields")
				}
			}
		})
	}
}
