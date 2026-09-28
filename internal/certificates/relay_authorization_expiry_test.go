package certificates

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestRelayWorkerRetiresExpiredAuthorizationWhileWaitingForDNS(t *testing.T) {
	start := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	expires := start.Add(time.Minute)
	const hostname = "relay-a.example.test"
	api := &acmeStub{
		order: acmeclient.Order{
			URL: "https://acme.example.test/order/1", Status: "pending", Expires: &expires,
			Identifiers:    []acmeclient.Identifier{{Type: "dns", Value: hostname}},
			Authorizations: []string{"https://acme.example.test/authz/1"},
			Finalize:       "https://acme.example.test/finalize/1",
		},
		authorization: acmeclient.Authorization{
			URL: "https://acme.example.test/authz/1", Status: "pending", Expires: &expires,
			Identifier: acmeclient.Identifier{Type: "dns", Value: hostname},
			Challenges: []acmeclient.Challenge{{Type: "dns-01", URL: "https://acme.example.test/challenge/1", Token: "token-1"}},
		},
	}
	dns := &relayDNSChallengesStub{verified: false}
	worker := &RelayWorker{config: RelayConfig{Profile: "tlsserver", PollInterval: time.Second, DNSChallenges: dns}}
	work := controlstate.RelayCertificateOrderWork{State: "pending", TLSServerName: hostname}
	for _, at := range []time.Time{start, start.Add(time.Second), start.Add(2 * time.Second)} {
		if err := worker.advance(t.Context(), api, &work, at); err != nil {
			t.Fatal(err)
		}
	}
	if work.State != "presented" || len(dns.presentCalls) != 1 {
		t.Fatalf("DNS challenge was not presented: state=%q presents=%d", work.State, len(dns.presentCalls))
	}
	for _, at := range []time.Time{expires.Add(time.Second), expires.Add(time.Hour)} {
		err := worker.advance(t.Context(), api, &work, at)
		if err != nil {
			worker.applyFailure(&work, err, at)
		}
		if work.State == "failed_cleaning" {
			break
		}
	}
	if work.State != "failed_cleaning" {
		t.Fatalf("expired authorization kept polling DNS: state=%q verifies=%d accepts=%d", work.State, len(dns.verifyCalls), api.acceptCalls)
	}
}
