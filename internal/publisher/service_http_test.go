package publisher

import (
	"crypto/ed25519"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/visitorpolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceHTTPClassificationRejectsTypedNilProblem(t *testing.T) {
	var problem *clientcontrol.ProblemError
	if got := serviceHTTPDecisionStatus(problem); got != http.StatusServiceUnavailable {
		t.Fatalf("typed-nil control error classified as %d", got)
	}
}

func TestServiceHTTPCredentialPrecedenceFailsClosed(t *testing.T) {
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	now := time.Now()
	permission := visitortoken.Permission{Scope: scope, Hostname: "app.example", Port: 12000, VisitorPolicyRevision: 1,
		Subject: visitortoken.Grant{GrantID: "shg_0123456789abcdefghijkl", Kind: "token"}, ExpiresAt: now.Add(time.Minute)}
	signed, err := visitortoken.Sign("https://control.example", "fixture", key, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	binding, digest, err := visitortoken.CredentialBinding(permission.Subject)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	update := visitorlease.Update{Snapshot: true, KeyRevision: 1, Enabled: true, View: visitortoken.View{Scope: scope,
		Issuer: "https://control.example", Hostname: permission.Hostname, Port: permission.Port,
		VisitorPolicyRevision: 1, MetadataRevision: 1, Public: true, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.
		WithVerificationKeys(map[string]ed25519.PublicKey{"fixture": key.Public().(ed25519.PublicKey)}).
		WithCredentialLeases(map[string]visitortoken.CredentialLease{binding: {SubjectSHA256: digest, ExpiresAt: permission.ExpiresAt}})}
	if err := lease.Apply(lease.Begin(), update); err != nil {
		t.Fatal(err)
	}
	f := ServiceHTTP{Subject: scope, MetadataRevision: 1, Header: tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{SourceIP: "192.0.2.44"}},
		Runtime: &ServiceHTTPRuntime{policy: &visitorpolicy.Policy{Lease: lease}}}
	for _, test := range []struct {
		name    string
		header  http.Header
		allowed bool
	}{
		{"signed token", http.Header{visitorTokenHeader: {signed.Reveal()}}, true},
		{"signed cookie", http.Header{"Cookie": {visitorTokenCookie + "=" + signed.Reveal()}}, true},
		{"browser fact with signed cookie", http.Header{"Cookie": {visitorTokenCookie + "=" + signed.Reveal() + "; " + browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, true},
		{"no credential", nil, false},
		{"browser fact without permission", http.Header{"Cookie": {browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, false},
		{"invalid token", http.Header{visitorTokenHeader: {"invalid"}}, false},
		{"empty token", http.Header{visitorTokenHeader: {""}}, false},
		{"duplicate token", http.Header{visitorTokenHeader: {signed.Reveal(), signed.Reveal()}}, false},
		{"header and cookie", http.Header{visitorTokenHeader: {signed.Reveal()}, "Cookie": {visitorTokenCookie + "=" + signed.Reveal()}}, false},
		{"retired service token header", http.Header{"Tnl-Access-Token": {signed.Reveal()}}, false},
		{"retired share header over browser", http.Header{shareAccessHeaderName: {"invalid"}, "Cookie": {browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, false},
		{"unparsed browser fact", http.Header{"Cookie": {browserAccessCookieName + "=\x7f"}}, false},
		{"duplicate browser facts", http.Header{"Cookie": {browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; " + browserAccessCookieName + "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, false},
		{"public URL share", http.Header{shareAccessHeaderName: {"shr_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = "app.example:12000"
			if test.header != nil {
				r.Header = test.header
			}
			r.TLS = &tls.ConnectionState{ServerName: "app.example", HandshakeComplete: true}
			got, supplied, err := f.localPermission(r, *r.TLS)
			if (err == nil) != test.allowed || got.anonymous || got.source != netip.MustParseAddr("192.0.2.44") && err == nil || !supplied && test.name != "no credential" {
				t.Fatalf("selected permission=%v supplied=%t error=%v", test.allowed, supplied, err)
			}
		})
	}
}
