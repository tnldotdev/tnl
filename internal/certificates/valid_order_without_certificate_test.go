package certificates

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayWorkerRetiresValidOrderWithoutCertificateURL(t *testing.T) {
	now := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	const hostname = "relay-a.example.test"
	api := &acmeStub{order: acmeclient.Order{
		URL: "https://acme.example.test/order/1", Status: "valid",
		Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}},
		Finalize:    "https://acme.example.test/finalize/1",
	}}
	store := &relayStoreStub{work: controlstate.RelayCertificateOrderWork{
		State: "finalizing", TLSServerName: hostname, OrderURL: api.order.URL,
		Account: controlstate.ACMEAccount{AccountURL: "https://acme.example.test/account/1"},
	}}
	worker := &RelayWorker{store: store, now: func() time.Time { return now }, client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }}
	for range 2 {
		if found, err := worker.processOne(t.Context()); !found || err != nil {
			t.Fatalf("process valid order: found=%t error=%v", found, err)
		}
		store.work = store.saved
		now = now.Add(time.Minute)
	}
	if store.saved.State != "failed" {
		t.Fatalf("valid order without required certificate URL remains active: state=%q attempts=%d error=%q", store.saved.State, store.saves, store.saved.LastError)
	}
}

func TestPublicURLWorkerRetiresValidOrderWithoutCertificateURL(t *testing.T) {
	now := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	const hostname = "api.example.test"
	api := &acmeStub{order: acmeclient.Order{
		URL: "https://acme.example.test/order/1", Status: "valid",
		Identifiers: []acmeclient.Identifier{{Type: "dns", Value: hostname}},
		Finalize:    "https://acme.example.test/finalize/1",
	}}
	store := &certificateStoreStub{work: controlstate.ACMEOrderWork{
		State: "finalizing", ChallengeMethod: "tls-alpn-01", CertificateIdentifiers: []string{hostname}, OrderURL: api.order.URL,
		Account: controlstate.ACMEAccount{AccountURL: "https://acme.example.test/account/1"},
	}}
	worker := &PublicURLWorker{store: store, now: func() time.Time { return now }, client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }}
	for range 2 {
		if found, err := worker.processOne(t.Context()); !found || err != nil {
			t.Fatalf("process valid order: found=%t error=%v", found, err)
		}
		store.work = store.saved
		now = now.Add(time.Minute)
	}
	if store.saved.State != "failed" {
		t.Fatalf("valid order without required certificate URL remains active: state=%q attempts=%d error=%q", store.saved.State, store.saves, store.saved.LastError)
	}
}
