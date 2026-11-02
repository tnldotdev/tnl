package tunnelv1

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func testOpaqueID(prefix string) string { return prefix + strings.Repeat("a", 22) }

func publicServiceAdmissionFixture() ServiceForwardingHeader {
	return ServiceForwardingHeader{ServiceStreamHeader: ServiceStreamHeader{ProtocolVersion: Version, Kind: ServiceForwardingStream, ServiceID: testOpaqueID(opaqueid.ServicePrefix), ServiceRunID: testOpaqueID(opaqueid.ServiceRunPrefix), RunNumber: 1, PublicService: &PublicServiceAdmission{IngressID: "ingress-a", IngressRunID: testOpaqueID(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 25443}, SourceIP: "192.0.2.10", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 2, ExpiresAt: time.Now().Add(time.Minute)}, RelayID: "relay-a", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayServiceID: "relay", RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
}

func TestManagedAdmissionValidatesExactKindsAndIdentities(t *testing.T) {
	header := publicServiceAdmissionFixture()
	for name, mutate := range map[string]func(*ServiceForwardingHeader){
		"public-service":        func(h *ServiceForwardingHeader) { h.ServiceID = testOpaqueID(opaqueid.PublicURLPrefix) },
		"public-run":            func(h *ServiceForwardingHeader) { h.ServiceRunID = testOpaqueID(opaqueid.PublishRunPrefix) },
		"missing-run":           func(h *ServiceForwardingHeader) { h.RunNumber = 0 },
		"source":                func(h *ServiceForwardingHeader) { h.SourceIP = "192.0.2.10%spoof" },
		"assignment":            func(h *ServiceForwardingHeader) { h.ConnectionAssignmentRevision = 0 },
		"missing-admission":     func(h *ServiceForwardingHeader) { h.PublicService = nil },
		"missing-ingress-run":   func(h *ServiceForwardingHeader) { h.PublicService.IngressRunID = "" },
		"missing-ingress-lease": func(h *ServiceForwardingHeader) { h.PublicService.IngressLeaseRevision = 0 },
		"missing-relay-lease":   func(h *ServiceForwardingHeader) { h.RelayLeaseRevision = 0 },
		"retired-visitor-kind":  func(h *ServiceForwardingHeader) { h.Kind = "connector_visitor" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := header
			admission := *header.PublicService
			changed.PublicService = &admission
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
	var wire bytes.Buffer
	if err := WriteServiceForwardingHeader(&wire, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadServiceForwardingHeader(&wire)
	if err != nil || *decoded.PublicService != *header.PublicService {
		t.Fatal(decoded, err)
	}
	data, err := json.Marshal(header.PublicService)
	const golden = `{"ingress_id":"ingress-a","ingress_run_id":"ir_aaaaaaaaaaaaaaaaaaaaaa","ingress_lease_revision":1,"destination_port":25443}`
	if err != nil || string(data) != golden {
		t.Fatalf("public service admission golden: %s %v", data, err)
	}
	data, err = json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"direct", "connector", "connector_session_id", "subject", "grant_revision", "session_credential", "public_url_id"} {
		body := strings.TrimSuffix(string(data), "}") + `,"` + field + `":null}`
		if _, err := ReadServiceForwardingHeader(frame(body)); err == nil {
			t.Fatalf("accepted retired or foreign field %s", field)
		}
	}
	retired := strings.Replace(string(data), `"public_service":`, `"direct":`, 1)
	if retired == string(data) {
		t.Fatal("fixture did not contain public service admission")
	}
	if _, err := ReadServiceForwardingHeader(frame(retired)); err == nil {
		t.Fatal("retired direct admission was accepted")
	}
}

func TestRetiredConnectorSessionNeverBecomesApplicationAdmission(t *testing.T) {
	const old = `{"protocol_version":1,"kind":"connector_session","service_id":"svc_aaaaaaaaaaaaaaaaaaaaaa","connector_session_id":"cns_aaaaaaaaaaaaaaaaaaaaaa","session_credential":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	if _, err := ReadConnectorPeerVisitorEntry(frame(old)); err == nil {
		t.Fatal("retired infrastructure credential admitted application bytes")
	}
	if _, err := ReadControl(frame(old)); err == nil {
		t.Fatal("retired connector session admitted a relay role")
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
