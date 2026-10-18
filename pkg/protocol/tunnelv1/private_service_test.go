package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func testOpaqueID(prefix string) string { return prefix + strings.Repeat("a", 22) }

func TestPrivateMuxSessionAuthenticationDoesNotAuthorizeVisitorStreams(t *testing.T) {
	hello := PrivateConnectorSessionHello{ProtocolVersion: Version, Kind: "private_connector_session",
		PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix),
		SessionID:        testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), Credential: "one-use-session-credential",
		DeviceID: "device-1", IdentityID: testOpaqueID(opaqueid.IdentityPrefix), Nonce: make([]byte, 32), Signature: make([]byte, ed25519.SignatureSize)}
	var framed bytes.Buffer
	if err := WritePrivateConnectorSessionHello(&framed, hello); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateConnectorSessionHello(&framed)
	if err != nil || decoded.SessionID != hello.SessionID || decoded.PrivateServiceID != hello.PrivateServiceID {
		t.Fatalf("session hello: %+v %v", decoded, err)
	}
	visitor := PrivateVisitorEntry{ProtocolVersion: Version, Kind: PrivateVisitorStream,
		PrivateServiceID: hello.PrivateServiceID, PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1, Nonce: make([]byte, 32)}
	if err := WritePrivateVisitorEntry(&framed, visitor); err != nil {
		t.Fatalf("nonce-bound stream: %v", err)
	}
	hello.Credential = ""
	if err := WritePrivateConnectorSessionHello(&framed, hello); err == nil {
		t.Fatal("accepted session without infrastructure credential")
	}
	hello.Credential = "valid-credential"
	hello.PrivateServiceID = testOpaqueID(opaqueid.PublicURLPrefix)
	if err := WritePrivateConnectorSessionHello(&framed, hello); err == nil {
		t.Fatal("accepted a public URL ID as a private service ID")
	}
}

func TestPrivateVisitorProofCannotCrossServiceRunDeviceOrGrant(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewPrivateNonce()
	if err != nil {
		t.Fatal(err)
	}
	entry := PrivateVisitorEntry{ProtocolVersion: Version, Kind: PrivateVisitorStream,
		PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix),
		RunNumber: 1, Nonce: nonce}
	accepted := PrivateVisitorAccepted{ProtocolVersion: Version, Kind: "private_visitor_accepted",
		ConnectorSessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix),
		IdentityID:         testOpaqueID(opaqueid.IdentityPrefix), SourceIP: "192.0.2.10",
		VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), DeviceID: "device-1", GrantRevision: 1,
		PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1}
	var framed bytes.Buffer
	if err := WritePrivateVisitorEntry(&framed, entry); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateVisitorEntry(&framed)
	if err != nil {
		t.Fatal(err)
	}
	framed.Reset()
	if err := WritePrivateVisitorAccepted(&framed, accepted); err != nil {
		t.Fatal(err)
	}
	accepted, err = ReadPrivateVisitorAccepted(&framed)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := PrivateChallenge(decoded, accepted)
	if err != nil {
		t.Fatal(err)
	}
	header := PrivateStreamHeader{ProtocolVersion: Version, Kind: PrivateVisitorStream,
		PrivateServiceID: entry.PrivateServiceID, PrivateRunID: entry.PrivateRunID, RunNumber: entry.RunNumber,
		ConnectorSessionID: accepted.ConnectorSessionID, IdentityID: accepted.IdentityID,
		SourceIP: accepted.SourceIP, VisitorConnectionID: accepted.VisitorConnectionID,
		PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1,
		DeviceID: accepted.DeviceID, GrantRevision: accepted.GrantRevision, Nonce: entry.Nonce, ExpiresAt: time.Now().Add(time.Minute)}
	publisherChallenge, err := PrivateChallengeFromHeader(header)
	if err != nil || !bytes.Equal(publisherChallenge, challenge) {
		t.Fatalf("publisher lacks the connector's device-bound challenge: %v", err)
	}
	header.GrantRevision++
	changedChallenge, err := PrivateChallengeFromHeader(header)
	if err != nil || bytes.Equal(changedChallenge, challenge) {
		t.Fatalf("grant revision was not bound by publisher proof: %v", err)
	}
	proof := PrivateStreamProof{Signature: ed25519.Sign(privateKey, challenge)}
	framed.Reset()
	if err := WritePrivateStreamProof(&framed, proof); err != nil {
		t.Fatal(err)
	}
	proof, err = ReadPrivateStreamProof(&framed)
	if err != nil || !VerifyPrivateStreamProof(publicKey, entry, accepted, proof) {
		t.Fatalf("valid publisher proof rejected: %v", err)
	}
	for _, mutate := range []func(*PrivateVisitorEntry){
		func(e *PrivateVisitorEntry) {
			e.PrivateServiceID = opaqueid.PrivateServicePrefix + strings.Repeat("b", 22)
		},
		func(e *PrivateVisitorEntry) { e.PrivateRunID = opaqueid.PrivateRunPrefix + strings.Repeat("b", 22) },
		func(e *PrivateVisitorEntry) { e.RunNumber++ },
		func(e *PrivateVisitorEntry) { e.Nonce = bytes.Repeat([]byte{1}, 32) },
	} {
		changed := entry
		mutate(&changed)
		if VerifyPrivateStreamProof(publicKey, changed, accepted, proof) {
			t.Fatalf("cross-resource proof accepted: %+v", changed)
		}
	}
	for _, mutate := range []func(*PrivateVisitorAccepted){
		func(a *PrivateVisitorAccepted) { a.DeviceID = "device-2" },
		func(a *PrivateVisitorAccepted) { a.GrantRevision++ },
		func(a *PrivateVisitorAccepted) { a.ConnectionAssignmentRevision++ },
		func(a *PrivateVisitorAccepted) {
			a.PublisherConnectionID = opaqueid.PublisherConnectionPrefix + strings.Repeat("b", 22)
		},
		func(a *PrivateVisitorAccepted) {
			a.ConnectorSessionID = opaqueid.PrivateConnectorSessionPrefix + strings.Repeat("b", 22)
		},
		func(a *PrivateVisitorAccepted) { a.IdentityID = opaqueid.IdentityPrefix + strings.Repeat("b", 22) },
		func(a *PrivateVisitorAccepted) { a.SourceIP = "192.0.2.11" },
		func(a *PrivateVisitorAccepted) {
			a.VisitorConnectionID = opaqueid.VisitorConnectionPrefix + strings.Repeat("b", 22)
		},
	} {
		otherStream := accepted
		mutate(&otherStream)
		if VerifyPrivateStreamProof(publicKey, entry, otherStream, proof) {
			t.Fatalf("proof transplanted to another claimed stream: %+v", otherStream)
		}
	}
	wrongAccepted := accepted
	wrongAccepted.ConnectorSessionID = testOpaqueID(opaqueid.ControlSessionPrefix)
	if err := WritePrivateVisitorAccepted(&framed, wrongAccepted); err == nil {
		t.Fatal("accepted control session ID as private connector session ID")
	}
	wrongAccepted = accepted
	wrongAccepted.VisitorConnectionID = testOpaqueID(opaqueid.PublishRunPrefix)
	if err := WritePrivateVisitorAccepted(&framed, wrongAccepted); err == nil {
		t.Fatal("accepted public run ID as visitor connection ID")
	}
	badEntry := entry
	badEntry.Nonce = make([]byte, 31)
	if err := WritePrivateVisitorEntry(&framed, badEntry); err == nil {
		t.Fatal("accepted short nonce")
	}
	if err := WritePrivateStreamProof(&framed, PrivateStreamProof{Signature: []byte("short")}); err == nil {
		t.Fatal("accepted short signature")
	}
	framed.Reset()
	if err := writeJSONFrame(&framed, map[string]any{
		"protocol_version": Version, "kind": PrivateVisitorStream, "private_service_id": entry.PrivateServiceID, "private_run_id": entry.PrivateRunID, "run_number": 1,
		"ticket": "one-use-ticket", "nonce": nonce, "public_url_id": "url",
	}, MaxPrivateHeaderBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateVisitorEntry(&framed); err == nil {
		t.Fatal("accepted a public URL selector in the private connector entry")
	}
	badEntry = entry
	badEntry.PrivateRunID = testOpaqueID(opaqueid.PublishRunPrefix)
	if err := WritePrivateVisitorEntry(&framed, badEntry); err == nil {
		t.Fatal("accepted public publish run ID in private visitor entry")
	}
}

func TestPrivateStreamHeaderRejectsMissingBinding(t *testing.T) {
	header := PrivateStreamHeader{ProtocolVersion: Version, Kind: PrivateVisitorStream,
		PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1,
		ConnectorSessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), IdentityID: testOpaqueID(opaqueid.IdentityPrefix), SourceIP: "192.0.2.10",
		VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix), PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1,
		DeviceID: "device-1", GrantRevision: 1, Nonce: make([]byte, 32), ExpiresAt: time.Now().Add(time.Minute)}
	var framed bytes.Buffer
	if err := WritePrivateStreamHeader(&framed, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateStreamHeader(&framed)
	if err != nil || decoded.PrivateServiceID != header.PrivateServiceID || decoded.DeviceID != header.DeviceID {
		t.Fatalf("header did not round trip: %+v %v", decoded, err)
	}
	header.GrantRevision = 0
	if err := WritePrivateStreamHeader(&framed, header); err == nil {
		t.Fatal("accepted stream without grant binding")
	}
	header.GrantRevision = 1
	header.SourceIP = "192.0.2.10%untrusted"
	if err := WritePrivateStreamHeader(&framed, header); err == nil {
		t.Fatal("accepted forged source IP with a zone")
	}
	header.SourceIP = "192.0.2.10"
	header.ConnectorSessionID = testOpaqueID(opaqueid.ControlSessionPrefix)
	if err := WritePrivateStreamHeader(&framed, header); err == nil {
		t.Fatal("accepted control session ID as connector session ID")
	}
}

func TestPrivateForwardingRequiresCurrentRelayIdentity(t *testing.T) {
	header := PrivateForwardingHeader{
		PrivateStreamHeader: PrivateStreamHeader{ProtocolVersion: Version, Kind: PrivateForwardingStream,
			PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix), RunNumber: 1,
			ConnectorSessionID: testOpaqueID(opaqueid.PrivateConnectorSessionPrefix), IdentityID: testOpaqueID(opaqueid.IdentityPrefix),
			SourceIP: "192.0.2.10", VisitorConnectionID: testOpaqueID(opaqueid.VisitorConnectionPrefix),
			PublisherConnectionID: testOpaqueID(opaqueid.PublisherConnectionPrefix), ConnectionAssignmentRevision: 1, DeviceID: "device-1", GrantRevision: 1,
			Nonce: make([]byte, 32), ExpiresAt: time.Now().Add(time.Minute)},
		RelayServiceID: "relay-service", RelayID: "relay", RelayRunID: testOpaqueID(opaqueid.RelayRunPrefix), RelayLeaseRevision: 1,
		LeaseExpiresAt: time.Now().Add(time.Minute),
	}
	var framed bytes.Buffer
	if err := WritePrivateForwardingHeader(&framed, header); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadPrivateForwardingHeader(&framed)
	if err != nil || decoded.RelayRunID != header.RelayRunID || decoded.PrivateServiceID != header.PrivateServiceID {
		t.Fatalf("forwarding header: %+v %v", decoded, err)
	}
	header.RelayLeaseRevision = 0
	if err := WritePrivateForwardingHeader(&framed, header); err == nil {
		t.Fatal("accepted forwarding without relay lease revision")
	}
}
