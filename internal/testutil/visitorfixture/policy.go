// package visitorfixture provides signed policy, request, and TLS fixtures for
// publisher HTTP authorization and its public URL and service consumers.
package visitorfixture

import (
	"crypto/ed25519"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

const BrowserCookie = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func Policy(t *testing.T, anonymous bool) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, "preview.example.test", 443, anonymous)
}

func PolicyClock(t *testing.T, anonymous bool, clock func() time.Time) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return ScopePolicyClock(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, "preview.example.test", 443, anonymous, clock)
}

func ScopePolicy(t *testing.T, scope visitorscope.Scope, hostname string, port uint16, anonymous bool) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return ScopePolicyClock(t, scope, hostname, port, anonymous, nil)
}

func ScopePolicyClock(t *testing.T, scope visitorscope.Scope, hostname string, port uint16, anonymous bool, clock func() time.Time) (*visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
	policy, err := visitorlease.New(scope, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	now := time.Now()
	update := visitorlease.Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: hostname, Port: port,
		VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.WithVerificationKeys(map[string]ed25519.PublicKey{"http": key.Public().(ed25519.PublicKey)}),
		KeyRevision: 1, Enabled: true, Anonymous: anonymous, Snapshot: true}
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	token, err := visitortoken.Sign(update.View.Issuer, "http", key, visitortoken.Permission{Scope: scope, Hostname: update.View.Hostname, Port: port, VisitorPolicyRevision: 1,
		Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)}, ExpiresAt: time.Now().Add(5 * time.Minute)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return policy, update, token
}

func Request() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "preview.example.test"
	r.TLS = &tls.ConnectionState{ServerName: "preview.example.test"}
	r.RemoteAddr = "192.0.2.1:1234"
	return r
}

func SourceKeyBytes() *[]byte {
	key := [32]byte{1}
	return new(key[:])
}
