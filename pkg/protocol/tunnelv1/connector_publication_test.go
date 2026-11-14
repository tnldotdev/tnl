package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func publicURLPeerOpeningFixture() ConnectorPeerVisitorEntry {
	entry := peerOpeningFixture()
	entry.ServiceID, entry.ServiceRunID, entry.RunNumber = "", "", 0
	entry.PublicURLID, entry.PublishRunID, entry.PublishRunNumber = "url_1234567890123456789012", "pr_1234567890123456789012", 4
	return entry
}

func publicURLConnectorPairGoldenProof() ConnectorPeerPairProof {
	proof := connectorPairGoldenProof()
	proof.ServiceID, proof.ServiceRunID, proof.RunNumber = "", "", 0
	proof.PublicURLID, proof.PublishRunID, proof.PublishRunNumber = "url_1234567890123456789012", "pr_1234567890123456789012", 2
	return proof
}

func TestPublicURLConnectorPeerPairProofKeepsItsResourceAndDomain(t *testing.T) {
	proof := publicURLConnectorPairGoldenProof()
	message, err := proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("tnl public URL connector peer pair v1\x00")
	if !bytes.HasPrefix(message, domain) {
		t.Fatal("public URL pair proof has no independent signing domain")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, readFixture(t, "public-url-connector-peer-pair-proof.json")); err != nil ||
		!bytes.Equal(message, append(bytes.Clone(domain), compact.Bytes()...)) {
		t.Fatal("public URL pair proof changed its golden signing bytes", err)
	}
	var body []json.RawMessage
	if err := json.Unmarshal(message[len(domain):], &body); err != nil || len(body) != 11 ||
		string(body[1]) != `"url_1234567890123456789012"` || string(body[2]) != `"pr_1234567890123456789012"` || string(body[3]) != "2" {
		t.Fatal("pair proof lost the saved public URL or publish run", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signature := ed25519.Sign(key, message)
	serviceMessage, err := connectorPairGoldenProof().Message()
	if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), serviceMessage, signature) {
		t.Fatal("public URL proof authorized the service resource family", err)
	}
	serviceDomain := []byte("tnl connector peer pair v1\x00")
	if ed25519.Verify(key.Public().(ed25519.PublicKey), append(serviceDomain, message[len(domain):]...), signature) {
		t.Fatal("pair proof signature did not bind its public URL signing domain")
	}
	for name, edit := range map[string]func(*ConnectorPeerPairProof){
		"URL":    func(p *ConnectorPeerPairProof) { p.PublicURLID = "url_abcdefghijklmnopqrstuv" },
		"run":    func(p *ConnectorPeerPairProof) { p.PublishRunID = "pr_abcdefghijklmnopqrstuv" },
		"number": func(p *ConnectorPeerPairProof) { p.PublishRunNumber++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := proof
			edit(&changed)
			next, err := changed.Message()
			if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), next, signature) {
				t.Fatal("changed public URL identity retained pair authority", err)
			}
		})
	}
	for _, edit := range []func(*ConnectorPeerPairProof){
		func(p *ConnectorPeerPairProof) { p.ServiceID = "svc_1234567890123456789012" },
		func(p *ConnectorPeerPairProof) { p.ServiceRunID = "srun_1234567890123456789012" },
		func(p *ConnectorPeerPairProof) { p.RunNumber = 1 },
		func(p *ConnectorPeerPairProof) { p.PublicURLID = "" },
		func(p *ConnectorPeerPairProof) { p.PublicURLID = "svc_1234567890123456789012" },
		func(p *ConnectorPeerPairProof) { p.PublishRunID = "srun_1234567890123456789012" },
		func(p *ConnectorPeerPairProof) { p.PublishRunNumber = 0 },
		func(p *ConnectorPeerPairProof) { p.PublishRunNumber = -1 },
	} {
		invalid := proof
		edit(&invalid)
		if _, err := invalid.Message(); !errors.Is(err, ErrConnectorPeerPairProof) {
			t.Fatal("mixed or incomplete public URL pair proof was signed", err)
		}
	}
}

func TestPublicURLConnectorPeerOpeningSignatureBindsEveryAuthorityField(t *testing.T) {
	entry := publicURLPeerOpeningFixture()
	initial := []byte("exact initial TLS bytes")
	message, err := ConnectorPeerProofMessage(entry, initial)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(key, message)
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("original public URL opening signature did not verify")
	}
	// mutate otherwise valid messages, not only fields compared to the checked
	// session. every field must remain bound when the expected session changes.
	for name, edit := range map[string]func(*ConnectorPeerVisitorEntry){
		"public URL":          func(e *ConnectorPeerVisitorEntry) { e.PublicURLID = "url_abcdefghijklmnopqrstuv" },
		"publish run":         func(e *ConnectorPeerVisitorEntry) { e.PublishRunID = "pr_abcdefghijklmnopqrstuv" },
		"publish run number":  func(e *ConnectorPeerVisitorEntry) { e.PublishRunNumber++ },
		"pair":                func(e *ConnectorPeerVisitorEntry) { e.PairID = "cpp_abcdefghijklmnopqrstuv" },
		"delivery":            func(e *ConnectorPeerVisitorEntry) { e.DeliveryID = "AgICAgICAgICAgICAgICAg" },
		"delivery generation": func(e *ConnectorPeerVisitorEntry) { e.DeliveryGeneration++ },
		"subject":             func(e *ConnectorPeerVisitorEntry) { e.Subject.DeviceID = "vdev_abcdefghijklmnopqrstuv" },
		"visitor":             func(e *ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "vc_abcdefghijklmnopqrstuv" },
		"metadata revision":   func(e *ConnectorPeerVisitorEntry) { e.MetadataRevision++ },
		"token":               func(e *ConnectorPeerVisitorEntry) { e.Permission.Token = "other-token" },
		"source":              func(e *ConnectorPeerVisitorEntry) { e.SourceIP = "198.51.100.1" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := entry
			edit(&changed)
			next, err := ConnectorPeerProofMessage(changed, initial)
			if err != nil {
				t.Fatal("mutation did not produce another valid opening", err)
			}
			if ed25519.Verify(public, next, signature) {
				t.Fatal("changed authority retained the public URL opening signature")
			}
		})
	}
	next, err := ConnectorPeerProofMessage(entry, []byte("changed TLS bytes"))
	if err != nil || ed25519.Verify(public, next, signature) {
		t.Fatal("initial application bytes were not signature-bound", err)
	}
	domain := []byte("tnl public URL connector peer visitor opening v1\x00")
	if ed25519.Verify(public, append([]byte("tnl connector peer visitor opening v1\x00"), message[len(domain):]...), signature) {
		t.Fatal("opening signature did not bind its public URL signing domain")
	}
	service, err := ConnectorPeerProofMessage(peerOpeningFixture(), initial)
	if err != nil || ed25519.Verify(public, service, signature) {
		t.Fatal("public URL opening signature authorized a service", err)
	}
}

func TestPublicURLConnectorPeerOpeningRetainsExactPublicationAndFraming(t *testing.T) {
	entry := publicURLPeerOpeningFixture()
	assertGoldenFrame(t, "public-url-connector-peer-visitor-entry", entry, WriteConnectorPeerVisitorEntry, ReadConnectorPeerVisitorEntry)
	if entry.Session().Scope() != (visitorscope.Scope{Kind: visitorscope.PublicURL, ID: entry.PublicURLID}) {
		t.Fatal("opening changed the saved resource kind")
	}
	initial := []byte("exact initial TLS bytes")
	var wire bytes.Buffer
	if sent, err := WriteConnectorPeerVisitorOpening(&wire, entry, initial); err != nil || !sent {
		t.Fatal(err)
	}
	headerLength := binary.BigEndian.Uint32(wire.Bytes()[:4])
	header := wire.Bytes()[4 : 4+headerLength]
	if bytes.Contains(header, []byte(`"service_id"`)) || bytes.Contains(header, []byte(`"service_run_id"`)) || bytes.Contains(header, []byte(`"run_number"`)) ||
		!bytes.Contains(header, []byte(`"public_url_id":"`+entry.PublicURLID+`"`)) || !bytes.Contains(header, []byte(`"publish_run_number":4`)) {
		t.Fatal("public URL opening invented a service identity", string(header))
	}
	framed := bytes.Clone(wire.Bytes())
	reader := bytes.NewReader(append(bytes.Clone(framed), []byte("next application bytes")...))
	got, received, err := ReadConnectorPeerVisitorOpening(reader)
	if err != nil || got != entry || !bytes.Equal(received, initial) {
		t.Fatal("public URL opening did not round trip", err)
	}
	remainder, err := io.ReadAll(reader)
	if err != nil || string(remainder) != "next application bytes" {
		t.Fatal("opening consumed subsequent application bytes", err)
	}
	for size := range len(framed) {
		if _, _, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(framed[:size])); err == nil {
			t.Fatalf("accepted truncated public URL opening at %d", size)
		}
	}
	message, err := ConnectorPeerProofMessage(entry, initial)
	if err != nil || !bytes.HasPrefix(message, []byte("tnl public URL connector peer visitor opening v1\x00")) {
		t.Fatal("public URL opening reused service signing authority", err)
	}
	for _, edit := range []func(*ConnectorPeerVisitorEntry){
		func(e *ConnectorPeerVisitorEntry) { e.ServiceID = "svc_1234567890123456789012" },
		func(e *ConnectorPeerVisitorEntry) { e.ServiceRunID = "srun_1234567890123456789012" },
		func(e *ConnectorPeerVisitorEntry) { e.RunNumber = 1 },
		func(e *ConnectorPeerVisitorEntry) { e.PublicURLID = "" },
		func(e *ConnectorPeerVisitorEntry) { e.PublicURLID = "svc_1234567890123456789012" },
		func(e *ConnectorPeerVisitorEntry) { e.PublishRunID = "srun_1234567890123456789012" },
		func(e *ConnectorPeerVisitorEntry) { e.PublishRunNumber = 0 },
		func(e *ConnectorPeerVisitorEntry) { e.PublishRunNumber = math.MaxUint64 },
	} {
		bad := entry
		edit(&bad)
		wire.Reset()
		if _, err := WriteConnectorPeerVisitorOpening(&wire, bad, nil); !errors.Is(err, ErrConnectorPeerVisitorOpening) || wire.Len() != 0 {
			t.Fatal("mixed or incomplete public URL opening reached the stream", err)
		}
		payload, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConnectorPeerVisitorEntry(frame(string(payload))); !errors.Is(err, ErrConnectorPeerVisitorOpening) {
			t.Fatal("mixed public URL opening was decoded as authority", err)
		}
	}
}
