package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"os"
	"testing"
	"time"
)

func publicURLLegProofFixture() ConnectorPairLegProof {
	p := connectorLegProofFixture()
	p.ServiceID, p.ServiceRunID, p.RunNumber = "", "", 0
	p.PublicURLID, p.PublishRunID, p.PublishRunNumber = "url_1234567890123456789012", "pr_1234567890123456789012", 4
	return p
}

func publicURLRebindFixture(t testing.TB, phase string) ConnectorPeerPairRebindProof {
	t.Helper()
	p := connectorRebindFixture(t, phase)
	p.ServiceID, p.ServiceRunID, p.RunNumber = "", "", 0
	p.PublicURLID, p.PublishRunID, p.PublishRunNumber = "url_1234567890123456789012", "pr_1234567890123456789012", 2
	return p
}

func TestServiceConnectorLegSigningBytesRemainUnchanged(t *testing.T) {
	p := connectorLegProofFixture()
	const body = `["cpp_1234567890123456789012",3,"svc_1234567890123456789012","srun_1234567890123456789012",4,"pub_1234567890123456789012",1,"pc_1234567890123456789012",7,"relay-b","relay-1","process-1",2,"2026-01-01T00:00:00Z","AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="]`
	want := append([]byte("tnl connector pair leg claim v1\x00"), body...)
	got, err := p.Message()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("service leg signing bytes changed", err)
	}
	source := netip.MustParseAddr("192.0.2.1")
	want = append([]byte("tnl relay connector pair leg claim v1\x00"), want...)
	want = append(want, p.Signature...)
	want = append(want, source.AsSlice()...)
	got, err = p.RelayClaimMessage(source)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("service relay signing bytes changed", err)
	}
}

func TestPublicURLConnectorLegProofGoldenAndFraming(t *testing.T) {
	p := publicURLLegProofFixture()
	var wire bytes.Buffer
	if err := WriteConnectorPairLegProof(&wire, p); err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/public-url-connector-leg-proof.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, golden); err != nil {
		t.Fatal(err)
	}
	frame := wire.Bytes()
	if binary.BigEndian.Uint32(frame[:4]) != uint32(compact.Len()) || !bytes.Equal(frame[4:], compact.Bytes()) {
		t.Fatal("public URL leg wire changed")
	}
	got, err := ReadConnectorPairLegProof(bytes.NewReader(frame))
	if err != nil || !got.SameLeg(p) || got.ServiceID != "" || got.ServiceRunID != "" || got.RunNumber != 0 {
		t.Fatal("public URL leg lost its typed publication", err)
	}
	for _, kind := range []MessageType{Hello, ConnectorLegRenew} {
		message := Message{Type: kind, ProtocolVersion: Version, Role: Connector, ConnectorPairLegProof: &p}
		if kind == ConnectorLegRenew {
			message.RequestID = "leg-renewal"
		}
		var control bytes.Buffer
		if err := WriteControl(&control, message); err != nil {
			t.Fatal("public URL leg was rejected by control framing", err)
		}
		read, err := ReadControl(&control)
		if err != nil || read.ConnectorPairLegProof == nil || !read.ConnectorPairLegProof.SameLeg(p) {
			t.Fatal("control framing changed public URL leg identity", err)
		}
	}
	for n := range len(frame) {
		got, err := ReadConnectorPairLegProof(bytes.NewReader(frame[:n]))
		if err == nil || got.PairID != "" {
			t.Fatal("truncated proof retained claim authority", n)
		}
	}
	raw := bytes.Replace(compact.Bytes(), []byte(`"nonce":`), []byte(`"source_ip":"192.0.2.10","nonce":`), 1)
	unknown := append(binary.BigEndian.AppendUint32(nil, uint32(len(raw))), raw...)
	if got, err := ReadConnectorPairLegProof(bytes.NewReader(unknown)); err == nil || got.PairID != "" {
		t.Fatal("public URL leg accepted a client-supplied source")
	}
}

func TestPublicURLConnectorLegProofBindsPublicationRelayAndObservedSource(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	p := publicURLLegProofFixture()
	message, err := p.Message()
	if err != nil {
		t.Fatal(err)
	}
	domain := []byte("tnl public URL connector pair leg claim v1\x00")
	if !bytes.HasPrefix(message, domain) {
		t.Fatal("public URL leg has no separate signing domain")
	}
	p.Signature = ed25519.Sign(key, message)
	for name, edit := range map[string]func(*ConnectorPairLegProof){
		"public URL":    func(p *ConnectorPairLegProof) { p.PublicURLID = "url_abcdefghijklmnopqrstuv" },
		"publish run":   func(p *ConnectorPairLegProof) { p.PublishRunID = "pr_abcdefghijklmnopqrstuv" },
		"run number":    func(p *ConnectorPairLegProof) { p.PublishRunNumber++ },
		"pair":          func(p *ConnectorPairLegProof) { p.PairID = "cpp_abcdefghijklmnopqrstuv" },
		"delivery":      func(p *ConnectorPairLegProof) { p.DeliveryGeneration++ },
		"publisher":     func(p *ConnectorPairLegProof) { p.PublisherIdentityID = "pub_abcdefghijklmnopqrstuv" },
		"slot":          func(p *ConnectorPairLegProof) { p.ConnectionSlot = 0 },
		"connection":    func(p *ConnectorPairLegProof) { p.PublisherConnectionID = "pc_abcdefghijklmnopqrstuv" },
		"assignment":    func(p *ConnectorPairLegProof) { p.AssignmentRevision++ },
		"relay service": func(p *ConnectorPairLegProof) { p.RelayServiceID = "other-service" },
		"relay":         func(p *ConnectorPairLegProof) { p.RelayID = "other-relay" },
		"relay run":     func(p *ConnectorPairLegProof) { p.RelayRunID = "other-run" },
		"relay lease":   func(p *ConnectorPairLegProof) { p.RelayLeaseRevision++ },
	} {
		t.Run(name, func(t *testing.T) {
			next := p
			edit(&next)
			changed, err := next.Message()
			if err != nil || ed25519.Verify(public, changed, p.Signature) || p.SameLeg(next) {
				t.Fatal("changed publication or delivery retained claim authority", err)
			}
		})
	}
	for name, edit := range map[string]func(*ConnectorPairLegProof){
		"time":  func(p *ConnectorPairLegProof) { p.RequestedAt = p.RequestedAt.Add(time.Microsecond) },
		"nonce": func(p *ConnectorPairLegProof) { p.Nonce = bytes.Repeat([]byte{3}, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			next := p
			edit(&next)
			changed, err := next.Message()
			if err != nil || ed25519.Verify(public, changed, p.Signature) || !p.SameLeg(next) {
				t.Fatal("freshness was not signed separately from immutable leg identity", err)
			}
		})
	}
	service := connectorLegProofFixture()
	other, err := service.Message()
	if err != nil || ed25519.Verify(public, other, p.Signature) || p.SameLeg(service) {
		t.Fatal("public URL leg proof crossed publication families", err)
	}
	other = append([]byte("tnl connector pair leg claim v1\x00"), message[len(domain):]...)
	if ed25519.Verify(public, other, p.Signature) {
		t.Fatal("public URL leg signature did not bind its domain")
	}
	relayKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	relayPublic := relayKey.Public().(ed25519.PublicKey)
	source := netip.MustParseAddr("192.0.2.1")
	relay, err := p.RelayClaimMessage(source)
	if err != nil || !bytes.HasPrefix(relay, []byte("tnl public URL relay connector pair leg claim v1\x00")) {
		t.Fatal("public URL relay attestation lacks its own domain", err)
	}
	signature := ed25519.Sign(relayKey, relay)
	serviceRelay, err := service.RelayClaimMessage(source)
	if err != nil || ed25519.Verify(relayPublic, serviceRelay, signature) {
		t.Fatal("public URL relay attestation crossed publication families", err)
	}
	relayDomain := []byte("tnl public URL relay connector pair leg claim v1\x00")
	changedDomain := append([]byte("tnl relay connector pair leg claim v1\x00"), relay[len(relayDomain):]...)
	if ed25519.Verify(relayPublic, changedDomain, signature) {
		t.Fatal("relay attestation did not sign its public URL domain")
	}
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::1")} {
		next, err := p.RelayClaimMessage(address)
		if err != nil || ed25519.Verify(relayPublic, next, signature) {
			t.Fatal("relay attestation did not bind the observed source", err)
		}
	}
	mapped, err := p.RelayClaimMessage(netip.MustParseAddr("::ffff:192.0.2.1"))
	if err != nil || !bytes.Equal(mapped, relay) {
		t.Fatal("equivalent observed IPv4 addresses signed different sources", err)
	}
	p.Signature = bytes.Repeat([]byte{4}, ed25519.SignatureSize)
	next, err := p.RelayClaimMessage(source)
	if err != nil || ed25519.Verify(relayPublic, next, signature) {
		t.Fatal("relay attestation did not bind connector possession", err)
	}
	if _, err := p.RelayClaimMessage(netip.MustParseAddr("fe80::1%en0")); !errors.Is(err, ErrConnectorPairLegProof) {
		t.Fatal("zoned relay source accepted", err)
	}
}

func TestPublicURLConnectorLegProofRejectsMixedAndIncompleteFamilies(t *testing.T) {
	for name, edit := range map[string]func(*ConnectorPairLegProof){
		"service":                    func(p *ConnectorPairLegProof) { p.ServiceID = "svc_1234567890123456789012" },
		"service run":                func(p *ConnectorPairLegProof) { p.ServiceRunID = "srun_1234567890123456789012" },
		"service number":             func(p *ConnectorPairLegProof) { p.RunNumber = 1 },
		"missing URL":                func(p *ConnectorPairLegProof) { p.PublicURLID = "" },
		"missing run":                func(p *ConnectorPairLegProof) { p.PublishRunID = "" },
		"missing number":             func(p *ConnectorPairLegProof) { p.PublishRunNumber = 0 },
		"negative number":            func(p *ConnectorPairLegProof) { p.PublishRunNumber = -1 },
		"service in URL":             func(p *ConnectorPairLegProof) { p.PublicURLID = "svc_1234567890123456789012" },
		"service run in publish run": func(p *ConnectorPairLegProof) { p.PublishRunID = "srun_1234567890123456789012" },
	} {
		t.Run(name, func(t *testing.T) {
			p := publicURLLegProofFixture()
			edit(&p)
			if _, err := p.Message(); !errors.Is(err, ErrConnectorPairLegProof) {
				t.Fatal("invalid publication was signed", err)
			}
			var wire bytes.Buffer
			if err := WriteConnectorPairLegProof(&wire, p); !errors.Is(err, ErrConnectorPairLegProof) || wire.Len() != 0 {
				t.Fatal("invalid publication was framed", err)
			}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			frame := append(binary.BigEndian.AppendUint32(nil, uint32(len(raw))), raw...)
			if got, err := ReadConnectorPairLegProof(bytes.NewReader(frame)); !errors.Is(err, ErrConnectorPairLegProof) || got.PairID != "" {
				t.Fatal("wire reader accepted an invalid publication", err)
			}
		})
	}
}

func TestPublicURLConnectorRebindProofGoldenAndPhases(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))
	for _, phase := range []string{"inspect", "prepare", "activate", "abort"} {
		t.Run(phase, func(t *testing.T) {
			p := publicURLRebindFixture(t, phase)
			message, err := p.Message()
			if err != nil {
				t.Fatal(err)
			}
			domain := []byte("tnl public URL connector peer rebind v1\x00")
			if !bytes.HasPrefix(message, domain) {
				t.Fatal("public URL rebind proof lacks its own domain")
			}
			if phase == "inspect" {
				golden, err := os.ReadFile("testdata/public-url-connector-rebind-proof.json")
				if err != nil {
					t.Fatal(err)
				}
				var compact bytes.Buffer
				if err := json.Compact(&compact, golden); err != nil || !bytes.Equal(message[len(domain):], compact.Bytes()) {
					t.Fatal("public URL rebind golden changed", err)
				}
			}
			signature := ed25519.Sign(key, message)
			for name, edit := range map[string]func(*ConnectorPeerPairRebindProof){
				"URL":      func(p *ConnectorPeerPairRebindProof) { p.PublicURLID = "url_abcdefghijklmnopqrstuv" },
				"run":      func(p *ConnectorPeerPairRebindProof) { p.PublishRunID = "pr_abcdefghijklmnopqrstuv" },
				"number":   func(p *ConnectorPeerPairRebindProof) { p.PublishRunNumber++ },
				"delivery": func(p *ConnectorPeerPairRebindProof) { p.ExpectedGeneration++ },
				"trust":    func(p *ConnectorPeerPairRebindProof) { p.TrustRevision++ },
				"owner":    func(p *ConnectorPeerPairRebindProof) { p.IdempotencyKey = "other-owner" },
			} {
				t.Run(name, func(t *testing.T) {
					next := p
					edit(&next)
					changed, err := next.Message()
					if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), changed, signature) {
						t.Fatal("changed public URL rebind authority retained its signature", err)
					}
				})
			}
			service, err := connectorRebindFixture(t, phase).Message()
			if err != nil || ed25519.Verify(key.Public().(ed25519.PublicKey), service, signature) {
				t.Fatal("public URL rebind crossed publication families", err)
			}
			changed := append([]byte("tnl connector peer rebind v1\x00"), message[len(domain):]...)
			if ed25519.Verify(key.Public().(ed25519.PublicKey), changed, signature) {
				t.Fatal("public URL rebind did not sign its domain")
			}
		})
	}
}

func TestPublicURLConnectorRebindProofRejectsMixedFamiliesInEveryPhase(t *testing.T) {
	for _, phase := range []string{"inspect", "prepare", "activate", "abort"} {
		for name, edit := range map[string]func(*ConnectorPeerPairRebindProof){
			"service":         func(p *ConnectorPeerPairRebindProof) { p.ServiceID = "svc_1234567890123456789012" },
			"service run":     func(p *ConnectorPeerPairRebindProof) { p.ServiceRunID = "srun_1234567890123456789012" },
			"service number":  func(p *ConnectorPeerPairRebindProof) { p.RunNumber = 1 },
			"missing URL":     func(p *ConnectorPeerPairRebindProof) { p.PublicURLID = "" },
			"missing run":     func(p *ConnectorPeerPairRebindProof) { p.PublishRunID = "" },
			"missing number":  func(p *ConnectorPeerPairRebindProof) { p.PublishRunNumber = 0 },
			"negative number": func(p *ConnectorPeerPairRebindProof) { p.PublishRunNumber = math.MinInt64 },
		} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				p := publicURLRebindFixture(t, phase)
				edit(&p)
				if _, err := p.Message(); !errors.Is(err, ErrConnectorPeerPairRebindProof) {
					t.Fatal("invalid publication entered a rebind phase", err)
				}
			})
		}
	}
}

func FuzzConnectorPairLegProof(f *testing.F) {
	for _, proof := range []ConnectorPairLegProof{connectorLegProofFixture(), publicURLLegProofFixture()} {
		var wire bytes.Buffer
		if err := WriteConnectorPairLegProof(&wire, proof); err != nil {
			f.Fatal(err)
		}
		f.Add(wire.Bytes())
	}
	f.Add(binary.BigEndian.AppendUint32(nil, MaxConnectorPairLegProofBytes+1))
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, err := ReadConnectorPairLegProof(bytes.NewReader(wire))
		if err != nil {
			if p.PairID != "" {
				t.Fatal("failed read retained a pair")
			}
			return
		}
		if err := p.Validate(); err != nil {
			t.Fatal("read admitted an invalid proof", err)
		}
	})
}
