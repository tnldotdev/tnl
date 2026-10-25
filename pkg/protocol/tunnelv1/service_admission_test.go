package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func testOpaqueID(prefix string) string { return prefix + strings.Repeat("a", 22) }

func nativeTestEntry() ConnectorVisitorEntry {
	return ConnectorVisitorEntry{ProtocolVersion: Version, Kind: ConnectorVisitorStream, ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 7,
		VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), MetadataRevision: 1,
		Permission: NativeVisitorPermission{Token: "signed-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func TestManagedAdmissionGoldenFrames(t *testing.T) {
	entry := nativeTestEntry()
	const golden = `{"protocol_version":1,"kind":"connector_visitor","service_id":"svc_aaaaaaaaaaaaaaaaaaaaaa","service_run_id":"srun_aaaaaaaaaaaaaaaaaaaaaa","run_number":7,"visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","metadata_revision":1,"permission":{"visitor_token":"signed-token","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`
	var wire bytes.Buffer
	if err := WriteConnectorVisitorEntry(&wire, entry); err != nil {
		t.Fatal(err)
	}
	if got := wire.Bytes(); string(got[4:]) != golden || int(binary.BigEndian.Uint32(got[:4])) != len(golden) {
		t.Fatalf("managed entry frame changed: %s", got[4:])
	}
	decoded, err := ReadConnectorVisitorEntry(&wire)
	if err != nil || decoded != entry {
		t.Fatal(decoded, err)
	}
	for _, field := range []string{"nonce", "signature", "stream_public_key", "public_url_id"} {
		wire.Reset()
		body := strings.TrimSuffix(golden, "}") + `,"` + field + `":"superseded"}`
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(body)))
		wire.Write(size[:])
		wire.WriteString(body)
		if _, err := ReadConnectorVisitorEntry(&wire); err == nil {
			t.Fatalf("accepted removed field %s", field)
		}
	}
}

func TestManagedAdmissionValidatesExactKindsAndIdentities(t *testing.T) {
	header := ServiceStreamHeader{ProtocolVersion: Version, Kind: ConnectorVisitorStream, ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1, Connector: &ConnectorAdmission{SessionID: testOpaqueID(opaqueid.ConnectorSessionPrefix), Subject: VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, GrantRevision: 3}, SourceIP: "192.0.2.10", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 2, ExpiresAt: time.Now().Add(time.Minute)}
	for name, mutate := range map[string]func(*ServiceStreamHeader){"public-service": func(h *ServiceStreamHeader) { h.ServiceID = testOpaqueID(opaqueid.PublicURLPrefix) }, "public-run": func(h *ServiceStreamHeader) { h.ServiceRunID = testOpaqueID(opaqueid.PublishRunPrefix) }, "missing-run": func(h *ServiceStreamHeader) { h.RunNumber = 0 }, "grant": func(h *ServiceStreamHeader) { c := *h.Connector; c.GrantRevision = 0; h.Connector = &c }, "session": func(h *ServiceStreamHeader) {
		c := *h.Connector
		c.SessionID = testOpaqueID(opaqueid.ControlSessionPrefix)
		h.Connector = &c
	}, "source": func(h *ServiceStreamHeader) { h.SourceIP = "192.0.2.10%spoof" }, "assignment": func(h *ServiceStreamHeader) { h.ConnectionAssignmentRevision = 0 }, "missing-admission": func(h *ServiceStreamHeader) { h.Connector = nil }, "mixed-admission": func(h *ServiceStreamHeader) {
		h.Direct = &DirectAdmission{IngressID: "a", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 25443}
	}} {
		t.Run(name, func(t *testing.T) {
			changed := header
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
	var framed bytes.Buffer
	if err := WriteServiceStreamHeader(&framed, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadServiceStreamHeader(&framed)
	if err != nil || *decoded.Connector != *header.Connector {
		t.Fatal(decoded, err)
	}
	header.Connector = nil
	header.Direct = &DirectAdmission{IngressID: "ingress-a", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 25443}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	forward := ServiceForwardingHeader{ServiceStreamHeader: header, RelayID: "relay-a", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayServiceID: "relay", RelayLeaseRevision: 1, LeaseExpiresAt: header.ExpiresAt}
	forward.Kind = ServiceForwardingStream
	if err := WriteServiceForwardingHeader(&framed, forward); err != nil {
		t.Fatal(err)
	}
	forward.RelayLeaseRevision = 0
	if forward.Validate() == nil {
		t.Fatal("missing relay lease accepted")
	}
}

func TestConnectorSessionCredentialNeverBecomesApplicationAdmission(t *testing.T) {
	hello := ConnectorSessionHello{ProtocolVersion: Version, Kind: "connector_session", ServiceID: testOpaqueID(opaqueid.ServicePrefix), SessionID: testOpaqueID(opaqueid.ConnectorSessionPrefix), Credential: strings.Repeat("a", 43), Subject: VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, Nonce: make([]byte, 32), Signature: make([]byte, ed25519.SignatureSize)}
	var framed bytes.Buffer
	if err := WriteConnectorSessionHello(&framed, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConnectorVisitorEntry(&framed); err == nil {
		t.Fatal("infrastructure credential admitted application bytes")
	}
	hello.Credential = ""
	if hello.Validate() == nil {
		t.Fatal("missing infrastructure credential accepted")
	}
	ref := &ServicePublisherConnectionRef{ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1, PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, RelayServiceID: "relay"}
	message := Message{Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "credential", ServiceConnection: ref}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	message.PublisherConnection = &PublisherConnectionRef{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 1, PublisherConnectionID: "connection", ConnectionAssignmentRevision: 1, RelayServiceID: "relay"}
	if message.Validate() == nil {
		t.Fatal("mixed public/private selectors accepted")
	}
}
