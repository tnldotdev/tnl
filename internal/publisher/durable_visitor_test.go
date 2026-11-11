package publisher

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestDurableVisitorOriginalBearerSurvivesPublisherRestartAndFullAdvertisedLifetime(t *testing.T) {
	for _, kind := range []string{"share", "service token", "service share"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
				port := uint16(443)
				secret := bytes.Repeat([]byte{7}, 32)
				id := "shr_" + strings.Repeat("A", 22)
				token, _ := visitortoken.ShareToken(id, secret)
				digest := sha256.Sum256(secret)
				if kind != "share" {
					scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
					port = 25443
					id = "shg_" + strings.Repeat("A", 22)
					token, _ = visitortoken.GrantToken(id, secret)
					_, digest, _ = visitortoken.GrantTokenDigest(token)
				}
				until := time.Now().Add(7 * 24 * time.Hour)
				var policy *visitorlease.Lease
				var update visitorlease.Update
				prepare := func() {
					t.Helper()
					if policy != nil {
						policy.Close()
					}
					policy, update, _ = httpPermissionScopeFixture(t, scope, "preview.example.test", port, false)
					if kind == "share" {
						update.View = update.View.WithShareVerifiers(map[string]visitortoken.ShareVerifier{id: {Digest: digest, ExpiresAt: until}})
					} else {
						grantKind := "token"
						if kind == "service share" {
							grantKind = "share"
						}
						update.View = update.View.WithGrantVerifiers(map[string]visitortoken.GrantVerifier{id: {Digest: digest, Kind: grantKind, ExpiresAt: until}})
					}
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Fatal(err)
					}
				}
				request := func(cookie bool) *http.Request {
					r := permissionRequest()
					if port != 443 {
						r.Host = net.JoinHostPort(update.View.Hostname, strconv.Itoa(int(port)))
					}
					r.Header.Set("Authorization", "Bearer application-secret")
					r.Header.Set("Cookie", "application=unchanged")
					if cookie {
						r.AddCookie(&http.Cookie{Name: visitorTokenCookie, Value: token.Reveal()})
					} else {
						r.Header.Set(visitorTokenHeader, token.Reveal())
					}
					return r
				}
				prepare()
				for _, step := range []time.Duration{0, 6 * time.Minute, 25 * time.Hour, 7*24*time.Hour - time.Microsecond} {
					at := until.Add(-7 * 24 * time.Hour).Add(step)
					time.Sleep(time.Until(at))
					// each preparation models a replacement run with no browser renewal
					// source or alias state carried from the previous publisher.
					prepare()
					for _, cookie := range []bool{false, true} {
						r := request(cookie)
						permission, err := localHTTPPermission(r, policy, nil)
						if err != nil {
							t.Fatal("original credential needed exchange after restart", err)
						}
						guard, bound, err := guardLocalHTTPRequest(httptest.NewRecorder(), r, policy, permission)
						if err != nil {
							t.Fatal(err)
						}
						bound = stripTnlCookies(bound)
						if bound.Header.Get(visitorTokenHeader) != "" || bound.Header.Get("Cookie") != "application=unchanged" || bound.Header.Get("Authorization") != "Bearer application-secret" {
							t.Fatal("visitor authentication leaked or consumed application authentication")
						}
						guard.finish()
					}
				}
				time.Sleep(time.Until(until))
				prepare()
				if _, err := localHTTPPermission(request(false), policy, nil); !errors.Is(err, visitortoken.ErrToken) {
					t.Fatal("credential survived exact expiry", err)
				}
			})
		})
	}
}

func TestDurableVisitorCurrentPolicyRevokesActiveRequestsWithoutAnonymousFallback(t *testing.T) {
	for _, kind := range []string{"share", "service"} {
		for _, fault := range []string{"revocation", "shortened deadline", "disabled", "outage"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					policy, update, _ := httpPermissionFixture(t, true)
					id := "shr_" + strings.Repeat("A", 22)
					secret := bytes.Repeat([]byte{7}, 32)
					token, _ := visitortoken.ShareToken(id, secret)
					digest := sha256.Sum256(secret)
					until := time.Now().Add(7 * 24 * time.Hour)
					if kind == "service" {
						policy.Close()
						scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
						policy, update, _ = httpPermissionScopeFixture(t, scope, "preview.example.test", 25443, true)
						id = "shg_" + strings.Repeat("A", 22)
						token, _ = visitortoken.GrantToken(id, secret)
						_, digest, _ = visitortoken.GrantTokenDigest(token)
					}
					install := func(deadline time.Time) {
						if kind == "share" {
							update.View = update.View.WithShareVerifiers(map[string]visitortoken.ShareVerifier{id: {Digest: digest, ExpiresAt: deadline}})
						} else {
							update.View = update.View.WithGrantVerifiers(map[string]visitortoken.GrantVerifier{id: {Digest: digest, Kind: "token", ExpiresAt: deadline}})
						}
					}
					install(until)
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Fatal(err)
					}
					r := permissionRequest()
					if kind == "service" {
						r.Host = "preview.example.test:25443"
					}
					r.Header.Set(visitorTokenHeader, token.Reveal())
					permission, err := localHTTPPermission(r, policy, nil)
					if err != nil {
						t.Fatal(err)
					}
					var stopped atomic.Int64
					guard, err := permission.bind(policy, func() { stopped.Add(1) })
					if err != nil {
						t.Fatal(err)
					}
					defer guard.Close()
					update.View.VisitorPolicyRevision++
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Fatal(err)
					}
					if stopped.Load() != 0 {
						t.Fatal("unrelated revision revoked durable request")
					}
					switch fault {
					case "revocation":
						update.View = update.View.WithShareVerifiers(nil).WithGrantVerifiers(nil)
					case "disabled":
						update.Enabled = false
					case "shortened deadline":
						install(time.Now().Add(time.Second))
					}
					if fault != "outage" {
						if err := policy.Apply(policy.Begin(), update); err != nil {
							t.Fatal(err)
						}
					}
					if fault == "outage" {
						time.Sleep(visitortoken.PolicyLifetime)
					} else if fault == "shortened deadline" {
						time.Sleep(time.Second)
					}
					synctest.Wait()
					if stopped.Load() != 1 {
						t.Fatal("active request outlived current authority")
					}
					if _, err := localHTTPPermission(r, policy, nil); err == nil {
						t.Fatal("revoked bearer fell back to anonymous")
					}
					if kind == "service" {
						r.TLS = &tls.ConnectionState{ServerName: update.View.Hostname, PeerCertificates: []*x509.Certificate{{}}}
						if _, err := localHTTPPermission(r, policy, nil); err == nil {
							t.Fatal("HTTP bearer replaced native TLS identity")
						}
					}
				})
			})
		}
	}
}
