package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestRelayWorkerRetiresAuthorizationWithIncompleteDNSChallenge(t *testing.T) {
	now := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	const hostname = "relay-a.example.test"
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "pending",
			Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Authorizations: []string{"https://acme.example.test/authz/1"},
			Finalize:       "https://acme.example.test/finalize/1",
		},
		authorization: acmeclient.Authorization{
			URL: "https://acme.example.test/authz/1", Status: "pending",
			Identifier: acmeclient.Identifier{Type: "dns", Value: hostname},
			Challenges: []acmeclient.Challenge{{Type: "dns-01", URL: "https://acme.example.test/challenge/1"}},
		},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := acmeclient.New(http.DefaultClient, "https://acme.example.test/directory", key, "https://acme.example.test/account/1")
	if err != nil {
		t.Fatal(err)
	}
	_, api.keyAuthorizationErr = client.KeyAuthorization("")
	if api.keyAuthorizationErr == nil {
		t.Fatal("ACME client unexpectedly accepted a missing challenge token")
	}
	store := &relayStoreStub{work: controlstate.RelayCertificateOrderWork{
		State: "authorizing", TLSServerName: hostname, OrderURL: api.order.URL,
		Account: controlstate.ACMEAccount{AccountURL: "https://acme.example.test/account/1"},
	}}
	worker := &RelayWorker{store: store, config: RelayConfig{DNSChallenges: &relayDNSChallengesStub{}, FailedRetryInterval: time.Hour}, now: func() time.Time { return now }, client: func(controlstate.ACMEAccount) (acmeAPI, error) { return api, nil }}
	metrics := observability.New("control")
	worker.config.Observer = metrics
	for range 2 {
		if found, err := worker.processOne(t.Context()); !found || err != nil {
			t.Fatalf("process incomplete challenge: found=%t error=%v", found, err)
		}
		store.work = store.saved
		now = now.Add(time.Minute)
	}
	if store.saved.State != "failed" {
		t.Fatalf("authorization with no DNS challenge token remains active: state=%q fetches=%d error=%q", store.saved.State, len(api.authorizationURLs), store.saved.LastError)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{
		`tnl_control_certificate_claims_total{kind="relay",outcome="claimed"} 2`,
		`tnl_control_certificate_transitions_total{kind="relay",state="failed"} 1`,
		`tnl_control_certificate_work_duration_seconds_count{kind="relay",outcome="terminal",stage="failed"} 1`,
	} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("missing relay certificate metric %q", want)
		}
	}
}
