package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type peerDeliveryFixture struct {
	response controlv1.NativePeerPairDelivery
	called   bool
	delay    time.Duration
}

func (f *peerDeliveryFixture) DeliverNativePeerPair(_ context.Context, service, run, pair string, generation int64, token credentials.ServiceRunToken) (controlv1.NativePeerPairDelivery, error) {
	f.called = true
	time.Sleep(f.delay)
	if service != "svc_0123456789ABCDEFGHIJKL" || run != "srun_0123456789ABCDEFGHIJKL" || pair != "npp_0123456789ABCDEFGHIJKL" || generation != 5 || token != "run-token" {
		return controlv1.NativePeerPairDelivery{}, ErrPrivateStream
	}
	return f.response, nil
}

func TestPreparePeerBindingRedactsAndCopies(t *testing.T) {
	service, run, pair := "svc_0123456789ABCDEFGHIJKL", "srun_0123456789ABCDEFGHIJKL", "npp_0123456789ABCDEFGHIJKL"
	key := bytes.Repeat([]byte{7}, 32)
	id := bytes.Repeat([]byte{9}, 16)
	identity, device := "ident_0123456789ABCDEFGHIJKL", "vdev_0123456789ABCDEFGHIJKL"
	f := &peerDeliveryFixture{response: controlv1.NativePeerPairDelivery{ServiceId: service, ServiceRunId: run, PairId: pair,
		DeliveryGeneration: 5, RunNumber: 2, PublisherIdentityId: "pub_0123456789ABCDEFGHIJKL",
		DeliveryId: base64.RawURLEncoding.EncodeToString(id), Key: base64.RawURLEncoding.EncodeToString(key), SourceIp: "192.0.2.10",
		Subject: controlv1.VisitorSubject{Kind: "human_device", IdentityId: &identity, DeviceId: &device},
		Relays: []controlv1.NativePeerPairRelay{
			{PublisherConnectionId: "pc_0123456789ABCDEFGHIJKL", AssignmentRevision: 1, RelayAddress: "a.example.test:443", TlsServerName: "a.example.test", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "a", RelayId: "a-1", RelayRunId: "run-a", RelayLeaseRevision: 1}},
			{PublisherConnectionId: "pc_0123456789ABCDEFGHIJKM", AssignmentRevision: 2, RelayAddress: "b.example.test:443", TlsServerName: "b.example.test", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "b", RelayId: "b-1", RelayRunId: "run-b", RelayLeaseRevision: 1}},
		}, ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}}
	if _, err := PreparePeerBinding(t.Context(), f, service, run, pair, 6, "run-token"); err == nil || !f.called {
		t.Fatal("unexpected delivery for a different generation")
	}
	f.called = false
	binding, err := PreparePeerBinding(t.Context(), f, service, run, pair, 5, "run-token")
	gotKey, gotID := binding.Key(), binding.DeliveryID()
	if err != nil || !f.called || binding.ServiceRunID() != run || binding.SourceIP() != netip.MustParseAddr("192.0.2.10") || !bytes.Equal(gotID[:], id) || !bytes.Equal(gotKey[:], key) {
		t.Fatal("binding lost the exact delivery", err)
	}
	if bytes.Contains([]byte(fmt.Sprint(binding)+fmt.Sprintf("%#v", binding)), key) || bytes.Contains([]byte(fmt.Sprint(binding)), []byte(f.response.Key)) {
		t.Fatal("binding formatted its key")
	}
	*binding.Subject().IdentityId = "changed"
	f.response.Relays[0].PublisherConnectionId = "changed"
	if *binding.Subject().IdentityId != identity || binding.Relays()[0].PublisherConnectionId != "pc_0123456789ABCDEFGHIJKL" {
		t.Fatal("caller changed a prepared binding")
	}
	f.response.SourceIp = "198.51.100.1"
	f.response.ServiceRunId = "srun_0123456789ABCDEFGHIJKM"
	if _, err := PreparePeerBinding(t.Context(), f, service, run, pair, 5, "run-token"); err == nil {
		t.Fatal("accepted a delivery from a different run")
	}
}

func TestPeerBindingDeadlineIsConservativeAcrossClockSkewAndDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		identity, device := "ident_0123456789ABCDEFGHIJKL", "vdev_0123456789ABCDEFGHIJKL"
		f := &peerDeliveryFixture{delay: 3 * time.Second, response: controlv1.NativePeerPairDelivery{
			PairId: "npp_0123456789ABCDEFGHIJKL", ServiceId: "svc_0123456789ABCDEFGHIJKL", ServiceRunId: "srun_0123456789ABCDEFGHIJKL", RunNumber: 2,
			PublisherIdentityId: "pub_0123456789ABCDEFGHIJKL", DeliveryGeneration: 5,
			DeliveryId: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), Key: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)), SourceIp: "192.0.2.10",
			Subject:    controlv1.VisitorSubject{Kind: "human_device", IdentityId: &identity, DeviceId: &device},
			ObservedAt: now.Add(time.Hour), ExpiresAt: now.Add(time.Hour + 10*time.Second),
			Relays: []controlv1.NativePeerPairRelay{
				{PublisherConnectionId: "pc_0123456789ABCDEFGHIJKL", AssignmentRevision: 1, RelayAddress: "a:443", TlsServerName: "a", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "a", RelayId: "a-1", RelayRunId: "run-a", RelayLeaseRevision: 1}},
				{PublisherConnectionId: "pc_0123456789ABCDEFGHIJKM", AssignmentRevision: 1, RelayAddress: "b:443", TlsServerName: "b", RelayLease: controlv1.NativePeerRelayLease{RelayServiceId: "b", RelayId: "b-1", RelayRunId: "run-b", RelayLeaseRevision: 1}},
			},
		}}
		binding, err := PreparePeerBinding(t.Context(), f, f.response.ServiceId, f.response.ServiceRunId, f.response.PairId, 5, "run-token")
		if err != nil || !binding.ExpiresAt().Equal(now.Add(10*time.Second)) || time.Until(binding.ExpiresAt()) != 7*time.Second {
			t.Fatal("control clock or transit delay extended pair authority", err)
		}
		for _, change := range []func(*controlv1.NativePeerPairDelivery){
			func(d *controlv1.NativePeerPairDelivery) {
				d.Key = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			},
			func(d *controlv1.NativePeerPairDelivery) { d.Subject.Kind = "browser" },
			func(d *controlv1.NativePeerPairDelivery) { d.SourceIp = "0.0.0.0" },
			func(d *controlv1.NativePeerPairDelivery) { d.Relays[1] = d.Relays[0] },
			func(d *controlv1.NativePeerPairDelivery) { d.ExpiresAt = d.ObservedAt.Add(6 * time.Minute) },
			func(d *controlv1.NativePeerPairDelivery) { d.ObservedAt = time.Time{} },
		} {
			copy := f.response
			copy.Relays = append([]controlv1.NativePeerPairRelay(nil), copy.Relays...)
			change(&copy)
			invalid := &peerDeliveryFixture{response: copy}
			if _, err := PreparePeerBinding(t.Context(), invalid, copy.ServiceId, copy.ServiceRunId, copy.PairId, 5, "run-token"); err == nil {
				t.Fatal("invalid authority became a prepared peer binding")
			}
		}
	})
}
