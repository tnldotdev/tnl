package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	dnscontroller "github.com/tnldotdev/tnl/internal/control/dns"
)

func TestLocalProviderMatchesRoute53WireAndOwnedCleanup(t *testing.T) {
	f := &fixture{domain: "routes.example.test.", address: "127.0.0.1", records: map[string]record{}}
	server := httptest.NewServer(http.HandlerFunc(f.route53))
	defer server.Close()
	api := route53.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("tnl-local-only", "fixture-only", ""), HTTPClient: server.Client()}, func(options *route53.Options) { options.BaseEndpoint = aws.String(server.URL) })
	provider, err := dnscontroller.NewRoute53Provider(api)
	if err != nil {
		t.Fatal(err)
	}
	challenge := dnscontroller.ChallengeRecord{ZoneID: "local", ZoneDomain: "routes.example.test", RecordName: "_acme-challenge.app.routes.example.test", DesiredOwnedValues: []string{"owned-value"}}
	zone, err := provider.ReconcileChallenge(t.Context(), challenge)
	if err != nil || len(zone.Nameservers) != 2 || zone.ChangeID == "" {
		t.Fatalf("present local DNS: %+v %v", zone, err)
	}
	if ready, err := provider.ChangeReady(t.Context(), zone.ChangeID); err != nil || !ready {
		t.Fatalf("change readiness: %t %v", ready, err)
	}
	challenge.PreviouslyOwnedValues, challenge.DesiredOwnedValues = challenge.DesiredOwnedValues, nil
	if _, err := provider.ReconcileChallenge(t.Context(), challenge); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) != 0 {
		t.Fatal("local DNS retained cleaned challenge records")
	}
}
