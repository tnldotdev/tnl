package httpaccess

import (
	"crypto/ed25519"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

func TestWorkloadIdentityPolicyRenewsTheSameHTTPRequestGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, update, _ := visitorfixture.ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}, "preview.example.test", 443, false)
		// the fixture already installed a ten-second observation. this later
		// control observation may grant five minutes; repeating the old one may not.
		time.Sleep(time.Second)
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
		digest, err := visitortoken.KeyDigest(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		workload := visitortoken.Workload{SessionID: "wls_" + strings.Repeat("W", 22), KeySHA256: digest}
		apply := func(revoke bool) {
			t.Helper()
			update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(5*time.Minute)
			parents := map[string]visitortoken.WorkloadLease{}
			if !revoke {
				parents[workload.SessionID] = visitortoken.WorkloadLease{KeySHA256: digest, ExpiresAt: time.Now().Add(90 * time.Second)}
			}
			update.View = update.View.WithWorkloadLeases(parents)
			if err := policy.Apply(policy.Begin(), update); err != nil {
				t.Fatal(err)
			}
		}
		apply(false)
		token, err := visitortoken.SignWorkloadIdentity(update.View.Issuer, "http", key, visitortoken.WorkloadIdentity{
			Scope: update.View.Scope, Hostname: update.View.Hostname, Port: update.View.Port,
			Certificate: visitortoken.Certificate{Serial: "1", KeySHA256: digest, Source: workload}, ExpiresAt: start.Add(time.Hour)}, start)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := visitortoken.CertificateURI(token)
		if err != nil {
			t.Fatal(err)
		}
		request := visitorfixture.Request()
		request.TLS.HandshakeComplete = true
		request.TLS.PeerCertificates = []*x509.Certificate{{PublicKey: key.Public(), SerialNumber: big.NewInt(1),
			NotBefore: start.Add(-time.Second), NotAfter: start.Add(time.Hour), URIs: []*url.URL{uri}}}
		authorization, guard, original, err := AuthorizeRequest(httptest.NewRecorder(), request, policy, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, typed := authorization.Permission().WorkloadPermission(); !typed {
			t.Fatal("HTTP authorization dropped the explicit workload permission type")
		}
		for range 4 {
			time.Sleep(30 * time.Second)
			apply(false)
			synctest.Wait()
			if original.Context().Err() != nil {
				t.Fatal("current policy did not sustain the same admitted HTTP request", original.Context().Err())
			}
		}
		apply(true)
		synctest.Wait()
		if original.Context().Err() == nil {
			t.Fatal("workload revocation retained the original application request")
		}
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("expired original response did not abort its consumer")
			}
		}()
		guard.Finish()
	})
}
