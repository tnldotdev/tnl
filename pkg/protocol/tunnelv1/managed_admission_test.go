package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func testOpaqueID(prefix string) string { return prefix + strings.Repeat("a", 22) }

func TestManagedAdmissionGoldenFrames(t *testing.T) {
	entry := PrivateVisitorEntry{ProtocolVersion: Version, Kind: PrivateVisitorStream, PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 7}
	const golden = `{"protocol_version":1,"kind":"private_visitor","private_service_id":"psvc_aaaaaaaaaaaaaaaaaaaaaa","private_run_id":"psrun_aaaaaaaaaaaaaaaaaaaaaa","run_number":7}`
	var wire bytes.Buffer
	if err := WritePrivateVisitorEntry(&wire, entry); err != nil {
		t.Fatal(err)
	}
	if got := wire.Bytes(); string(got[4:]) != golden || int(binary.BigEndian.Uint32(got[:4])) != len(golden) {
		t.Fatalf("managed entry frame changed: %s", got[4:])
	}
	decoded, err := ReadPrivateVisitorEntry(&wire)
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
		if _, err := ReadPrivateVisitorEntry(&wire); err == nil {
			t.Fatalf("accepted removed field %s", field)
		}
	}
}

func TestManagedAdmissionValidatesExactKindsAndIdentities(t *testing.T) {
	header := PrivateStreamHeader{ProtocolVersion: Version, Kind: PrivateVisitorStream, PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1, Connector: &ConnectorAdmission{SessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), Subject: VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, GrantRevision: 3}, SourceIP: "192.0.2.10", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 2, ExpiresAt: time.Now().Add(time.Minute)}
	for name, mutate := range map[string]func(*PrivateStreamHeader){"public-service": func(h *PrivateStreamHeader) { h.PrivateServiceID = testOpaqueID(opaqueid.PublicURLPrefix) }, "public-run": func(h *PrivateStreamHeader) { h.PrivateRunID = testOpaqueID(opaqueid.PublishRunPrefix) }, "missing-run": func(h *PrivateStreamHeader) { h.RunNumber = 0 }, "grant": func(h *PrivateStreamHeader) { c := *h.Connector; c.GrantRevision = 0; h.Connector = &c }, "session": func(h *PrivateStreamHeader) {
		c := *h.Connector
		c.SessionID = testOpaqueID(opaqueid.ControlSessionPrefix)
		h.Connector = &c
	}, "source": func(h *PrivateStreamHeader) { h.SourceIP = "192.0.2.10%spoof" }, "assignment": func(h *PrivateStreamHeader) { h.ConnectionAssignmentRevision = 0 }, "missing-admission": func(h *PrivateStreamHeader) { h.Connector = nil }, "mixed-admission": func(h *PrivateStreamHeader) {
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
	if err := WritePrivateStreamHeader(&framed, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateStreamHeader(&framed)
	if err != nil || *decoded.Connector != *header.Connector {
		t.Fatal(decoded, err)
	}
	header.Connector = nil
	header.Direct = &DirectAdmission{IngressID: "ingress-a", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 25443}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	forward := PrivateForwardingHeader{PrivateStreamHeader: header, RelayID: "relay-a", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayServiceID: "relay", RelayLeaseRevision: 1, LeaseExpiresAt: header.ExpiresAt}
	forward.Kind = PrivateForwardingStream
	if err := WritePrivateForwardingHeader(&framed, forward); err != nil {
		t.Fatal(err)
	}
	forward.RelayLeaseRevision = 0
	if forward.Validate() == nil {
		t.Fatal("missing relay lease accepted")
	}
}

func TestConnectorSessionCredentialNeverBecomesApplicationAdmission(t *testing.T) {
	hello := PrivateConnectorSessionHello{ProtocolVersion: Version, Kind: "private_connector_session", PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), SessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), Credential: strings.Repeat("a", 43), Subject: VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, Nonce: make([]byte, 32), Signature: make([]byte, ed25519.SignatureSize)}
	var framed bytes.Buffer
	if err := WritePrivateConnectorSessionHello(&framed, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateVisitorEntry(&framed); err == nil {
		t.Fatal("infrastructure credential admitted application bytes")
	}
	hello.Credential = ""
	if hello.Validate() == nil {
		t.Fatal("missing infrastructure credential accepted")
	}
	ref := &PrivatePublisherConnectionRef{PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1, PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, RelayServiceID: "relay"}
	message := Message{Type: Hello, ProtocolVersion: Version, Role: Publisher, Credential: "credential", PrivateConnection: ref}
	if err := message.Validate(); err != nil {
		t.Fatal(err)
	}
	message.PublisherConnection = &PublisherConnectionRef{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 1, PublisherConnectionID: "connection", ConnectionAssignmentRevision: 1, RelayServiceID: "relay"}
	if message.Validate() == nil {
		t.Fatal("mixed public/private selectors accepted")
	}
}
