package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDomainReleaseStatusNeverClaimsReadiness(t *testing.T) {
	var domain authorityv1.Domain
	if err := json.Unmarshal([]byte(`{"id":"dom_0123456789abcdefghijkl","canonical_domain":"release.example.test","kind":"custom","state":"releasing","release":{"observed_at":"2026-11-16T10:00:00Z","blockers":["endpoint_dns","uncertain_issuance","certificate","dns_authority"],"certificate_expires_at":"2027-01-04T12:34:56Z","completion_unknown":true}}`), &domain); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := writeDomainStatus(&output, domain, false); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"releasing", "DNS removal", "issuance outcome", "2027-01-04T12:34:56Z", "unknown", "tnl domain status"} {
		if !strings.Contains(text, want) {
			t.Fatalf("release status missing %q:\n%s", want, text)
		}
	}
	for _, wrong := range []string{"ready for public URLs", "domain released", "release on 2027"} {
		if strings.Contains(text, wrong) {
			t.Fatalf("release status made a false completion promise:\n%s", text)
		}
	}
}

func TestDomainReleaseAcknowledgementIsNotCompletion(t *testing.T) {
	testDomainReleaseAcknowledgement(t, http.StatusOK)
}

func TestDomainReleaseMissingObservationIsNotCompletion(t *testing.T) {
	testDomainReleaseAcknowledgement(t, http.StatusNotFound)
}

func testDomainReleaseAcknowledgement(t *testing.T, readStatus int) {
	t.Helper()
	const team = "tm_0123456789abcdefghijkl"
	const domainID = "dom_0123456789abcdefghijkl"
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	released, reads := false, 0
	domain := authorityv1.Domain{Id: domainID, CanonicalDomain: "release.example.test", Kind: "custom", State: "ready"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("domain operation did not use its management session")
		}
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example.test", LoginFlow: "device_code"}}})
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: team}}})
		case "/v1/teams/" + team:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: team})
		case "/v1/teams/" + team + "/domains":
			domains := []authorityv1.Domain{}
			if !released {
				domains = append(domains, domain)
			}
			_ = json.NewEncoder(w).Encode(authorityv1.DomainPage{Domains: domains})
		case "/v1/teams/" + team + "/domains/" + domainID:
			if r.Method == http.MethodDelete {
				released = true
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if !released {
				t.Error("release status read preceded the mutation")
			}
			reads++
			if readStatus != http.StatusOK {
				w.WriteHeader(readStatus)
				_, _ = io.WriteString(w, `{"type":"https://tnl.dev/p/not-found","title":"resource not found","status":404,"code":"not_found","detail":"resource not found","request_id":"req_fixture","details":{}}`)
				return
			}
			_, _ = io.WriteString(w, `{"id":"`+domainID+`","canonical_domain":"release.example.test","kind":"custom","state":"releasing","authority_revision":"2","required_records":[],"created_at":"2026-11-16T10:00:00Z","updated_at":"2026-11-16T10:00:00Z","release":{"observed_at":"2026-11-16T10:00:00Z","blockers":["dns_authority"],"completion_unknown":true}}`)
		default:
			t.Errorf("unexpected domain request: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	flags := domainReleaseCommand{Domain: domain.CanonicalDomain, scopedTeamFlags: scopedTeamFlags{
		remoteFlags:        remoteFlags{ServerURL: server.URL, AccessToken: access.String(), StateDir: filepath.Join(t.TempDir(), "state")},
		teamSelectionFlags: teamSelectionFlags{Team: team},
	}}
	var output bytes.Buffer
	err = runDomainRelease(t.Context(), flags, &output, io.Discard)
	if (err == nil) != (readStatus == http.StatusOK) {
		t.Fatalf("release status read failure was lost or invented: %v", err)
	}
	if !released || reads != 1 || !strings.Contains(output.String(), "releasing") ||
		!strings.Contains(output.String(), "unknown") || strings.Contains(output.String(), "domain released") {
		t.Fatalf("release acknowledgement was presented as final completion (reads=%d):\n%s", reads, &output)
	}
	for _, want := range []string{"tnl domain status " + domainID, "--server=" + server.URL, "--team=" + team} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("release follow-up lost its exact context %q:\n%s", want, &output)
		}
	}
	if readStatus == http.StatusOK {
		output.Reset()
		if err := runDomainStatus(t.Context(), domainStatusCommand{Domain: domainID, scopedTeamFlags: flags.scopedTeamFlags}, &output, io.Discard); err != nil {
			t.Fatal("exact-ID follow-up required the domain to remain in the available list", err)
		}
		if reads != 2 || !strings.Contains(output.String(), "releasing") {
			t.Fatalf("exact-ID follow-up did not observe current owner state:\n%s", &output)
		}
	}
}

func TestDomainReleaseStatusRequiresFinalOwnerConfirmation(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		receipt   *authorityv1.DomainRelease
		confirmed bool
	}{
		{},
		{receipt: &authorityv1.DomainRelease{ObservedAt: now}},
		{receipt: &authorityv1.DomainRelease{ObservedAt: now, ReleasedAt: &now, CompletionUnknown: true}},
		{receipt: &authorityv1.DomainRelease{ObservedAt: now, ReleasedAt: &now, Blockers: []authorityv1.DomainReleaseBlocker{authorityv1.DnsAuthority}}},
		{receipt: &authorityv1.DomainRelease{ObservedAt: now, ReleasedAt: &now}, confirmed: true},
	} {
		domain := authorityv1.Domain{Id: "dom_0123456789abcdefghijkl", CanonicalDomain: "release.example.test",
			Kind: "custom", State: authorityv1.DomainStateReleased, Release: test.receipt}
		var output bytes.Buffer
		if err := writeDomainStatus(&output, domain, false); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if strings.Contains(text, "ready for public URLs") {
			t.Fatal("released domain was presented as usable", text)
		}
		if test.confirmed != strings.HasPrefix(text, domain.CanonicalDomain+"  released\n") || test.confirmed != strings.Contains(text, "DNS authority release confirmed") {
			t.Fatalf("release confirmation=%t did not match owner evidence:\n%s", test.confirmed, text)
		}
		if !test.confirmed && (!strings.Contains(text, "unknown") || !strings.Contains(text, "tnl domain status "+domain.Id)) {
			t.Fatal("missing owner receipt became known completion", text)
		}
	}
}
