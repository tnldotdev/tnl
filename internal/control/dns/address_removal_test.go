package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func TestExactAddressRemovalWaitsForProviderAndAuthority(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                  string
		providerGone, dnsGone bool
	}{
		{name: "delete accepted but not read back", dnsGone: true},
		{name: "marker still authoritative", providerGone: true},
		{name: "removed even if wildcard addresses still answer", providerGone: true, dnsGone: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := testServiceDNSWork(now)
			work.State = controlstate.ServiceEndpointDNSRemoving
			store := &dnsStoreStub{serviceEndpointWork: work}
			provider := &providerStub{exactRecordsRemain: !test.providerGone}
			verifier := &verifierStub{addressVerified: test.dnsGone}
			worker := testDNSWorker(t, store, provider, verifier, now)
			worker.config.ManagedDomain, worker.config.ManagedZoneID = "tunnels.example.test", "ZMANAGED"
			if found, err := worker.processServiceEndpoint(t.Context(), now); err != nil || !found {
				t.Fatal(found, err)
			}
			want := controlstate.ServiceEndpointDNSRemoving
			if test.providerGone && test.dnsGone {
				want = controlstate.ServiceEndpointDNSRemoved
			}
			if store.serviceEndpointSaved.State != want || verifier.addressCalls != 0 ||
				(verifier.removalCalls == 1) != test.providerGone {
				t.Fatalf("saved state %s, verifier %+v; want %s", store.serviceEndpointSaved.State, verifier, want)
			}
		})
	}
}

func TestAuthoritativeAddressRemovalChecksMarkerNotAddresses(t *testing.T) {
	const (
		zone = "example.test"
		host = "p-example.live.example.test"
		name = "_tnl-owner." + host
		soa  = "example.test. 60 IN SOA ns-1.example.test. hostmaster.example.test. 1 60 60 60 60"
	)
	for _, test := range []struct {
		name    string
		rcode   int
		answers []string
		soa     string
		noAA    bool
		want    bool
		wantErr bool
	}{
		{name: "wildcard A with no marker TXT", soa: soa, want: true},
		{name: "no wildcard", rcode: dns.RcodeNameError, soa: soa, want: true},
		{name: "foreign wildcard TXT", answers: []string{name + `. 60 IN TXT "external"`}, want: true},
		{name: "owned receipt still present", answers: []string{name + `. 60 IN TXT "tnl-service:" "svc_1"`}},
		{name: "referral", noAA: true, wantErr: true},
		{name: "unrelated zone", soa: "other.test. 60 IN SOA ns.other.test. hostmaster.other.test. 1 60 60 60 60", wantErr: true},
		{name: "alias not absence", answers: []string{name + ". 60 IN CNAME other.test."}, wantErr: true},
		{name: "server failure", rcode: dns.RcodeServerFailure, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			address := verifierDNS(t, func(_ string, request *dns.Msg) *dns.Msg {
				if request.Question[0].Qtype == dns.TypeA {
					return verifierResponse(t, request, true, dns.RcodeSuccess, host+". 60 IN A 192.0.2.11")
				}
				response := verifierResponse(t, request, !test.noAA, test.rcode, test.answers...)
				if test.soa != "" {
					rr, err := dns.NewRR(test.soa)
					if err != nil {
						t.Error(err)
					}
					response.Ns = []dns.RR{rr}
				}
				return response
			})
			v := &AuthoritativeVerifier{}
			if test.name == "wildcard A with no marker TXT" {
				if ready, err := v.queryAddresses(t.Context(), address, host, dns.TypeA, nil); err != nil || ready {
					t.Fatal("address absence should not be verifiable under the wildcard", ready, err)
				}
			}
			response, err := v.exchange(t.Context(), address, name, dns.TypeTXT)
			if err != nil {
				t.Fatal(err)
			}
			removed, err := verifyRemovedAddressMarker(response, name, zone, "tnl-service:svc_1")
			if (err != nil) != test.wantErr || removed != test.want {
				t.Fatalf("removed = %t, want %t; error %v", removed, test.want, err)
			}
		})
	}
}
