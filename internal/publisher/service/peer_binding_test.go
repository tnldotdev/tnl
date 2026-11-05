package service

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerBindingRejectsInvalidStructure(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*PeerBinding)
	}{
		{"pair", func(b *PeerBinding) { b.pairID = "invalid" }},
		{"generation", func(b *PeerBinding) { b.generation = 0 }},
		{"delivery", func(b *PeerBinding) { b.delivery = [16]byte{} }},
		{"subject", func(b *PeerBinding) { b.subject = tunnelv1.VisitorSubject{} }},
		{"source", func(b *PeerBinding) { b.source = netip.IPv4Unspecified() }},
		{"key", func(b *PeerBinding) { b.key = [32]byte{} }},
		{"expiry", func(b *PeerBinding) { b.until = time.Now().Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
			before := p.bindingSnapshot()
			incoming := before
			// a distinct pair keeps the replay fence from masking validation.
			incoming.pairID = "cpp_" + strings.Repeat("V", 22)
			test.change(&incoming)
			if next, err := b.BindPeer(t.Context(), incoming); !errors.Is(err, ErrPrivateStream) {
				if next != nil {
					next.Close()
				}
				t.Fatal("invalid binding admitted a peer", err)
			}
			incoming = before
			test.change(&incoming)
			if err := p.Renew(incoming); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("invalid binding renewed a peer", err)
			}
			if p.bindingSnapshot() != before {
				t.Fatal("rejected binding changed retained identity or lease")
			}
		})
	}
}

func TestConnectorPeerBindingRetainsCallerValue(t *testing.T) {
	b, _, _, _, control := connectorPeerFixture(t, "127.0.0.1:1")
	delivery := *control
	delivery.delivery.PairId = "cpp_" + strings.Repeat("V", 22)
	d := delivery.delivery
	binding, err := PreparePeerBinding(t.Context(), &delivery, d.ServiceId, d.ServiceRunId, d.PairId, d.DeliveryGeneration, "run-token")
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.BindPeer(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	before := p.bindingSnapshot()
	binding.pairID, binding.serviceID, binding.runID, binding.publisherID = "", "", "", ""
	binding.generation, binding.number = 0, 0
	binding.delivery[0]++
	binding.key[0]++
	binding.subject.DeviceID = ""
	binding.source = netip.IPv4Unspecified()
	binding.relays[0].PublisherConnectionId = ""
	binding.relays[0].RelayLease.RelayId = ""
	binding.until, binding.authorityUntil = time.Time{}, time.Time{}
	if p.bindingSnapshot() != before {
		t.Fatal("caller mutation changed the retained binding")
	}
	b.mu.Lock()
	callerCurrent, current := b.peerCurrentLocked(binding), p.currentLocked()
	b.mu.Unlock()
	if callerCurrent || !current {
		t.Fatal("caller mutation did not stay separate from the retained peer")
	}
}
