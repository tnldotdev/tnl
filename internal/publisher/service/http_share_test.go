package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPSharePreparationDoesNotAdmitApplicationTraffic(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			var admissions, redemptions, forwarded atomic.Int32
			shareID := "shr_" + strings.Repeat("S", 22)
			secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
			cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
			client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				if r.Header.Get("Cookie") != "app_session=value" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
					t.Error("service target received a tnl visitor credential")
				}
				w.WriteHeader(http.StatusNoContent)
			}), h2, true, func(f *HTTP) {
				key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
				f.Token = "run-secret"
				policy, err := httpaccess.PreparePolicy(t.Context(), &visitorfixture.PolicyClient{Key: key}, f.Subject, f.RunID, f.Number, f.Token.String(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(policy.Close)
				tokens, err := httpaccess.StartTokens(t.Context(), &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
					t.Error("share preparation requested another visitor permission")
					return controlv1.VisitorTokenResponse{}, visitortoken.ErrToken
				}}, policy.Lease(), nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(tokens.Close)
				service, run, runToken, number := f.Subject.ID, f.RunID, f.Token, f.Number
				f.ReserveCapacity = func(context.Context) error {
					admissions.Add(1)
					return nil
				}
				control := serviceHTTPShareControl{
					redeem: func(_ context.Context, gotService, gotRun string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
						redemptions.Add(1)
						if gotService != service || gotRun != run || token != runToken || request.RunNumber != number ||
							request.ShareId == nil || *request.ShareId != shareID || request.Secret == nil || *request.Secret != secret || request.HandoffToken != nil {
							t.Error("share redemption changed the service run or link")
							return controlv1.ShareRedemption{}, visitortoken.ErrBinding
						}
						view, _, _ := policy.Lease().Current()
						facts := visitortoken.Permission{Scope: f.Subject, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
							Subject: visitortoken.Share{ShareID: shareID}, ExpiresAt: time.Now().Add(5 * time.Minute).Truncate(time.Second)}
						signed, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
						return controlv1.ShareRedemption{ShareId: shareID, CookieSecret: cookie, ExpiresAt: time.Now().Add(time.Hour),
							NextUrl: "https://preview.example.test/",
							Permission: controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Hostname: facts.Hostname, Port: int(facts.Port),
								VisitorPolicyRevision: facts.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt, VisitorToken: signed.Reveal()}}, err
					},
				}
				f.Control, f.Policy = control, policy.Lease()
				f.browser = &httpaccess.Browser{Subject: f.Subject, Client: control, RunID: run, Number: number, Token: runToken, Policy: policy, Tokens: tokens}
			})
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			visit := func(path string, want int) []*http.Cookie {
				t.Helper()
				response, err := client.Get("https://preview.example.test" + path)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if _, err := io.Copy(io.Discard, response.Body); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != want {
					t.Fatalf("%s returned %d, want %d", path, response.StatusCode, want)
				}
				return response.Cookies()
			}
			visit("/", http.StatusForbidden)
			visit("/__tnl/share/invalid", http.StatusForbidden)
			if admissions.Load() != 0 || redemptions.Load() != 0 || forwarded.Load() != 0 {
				t.Fatal("denied request spent ingress admission or reached the target")
			}
			cookies := visit("/__tnl/share/"+shareID+"."+secret, http.StatusSeeOther)
			if len(cookies) != 2 || admissions.Load() != 0 || redemptions.Load() != 1 || forwarded.Load() != 0 {
				t.Fatal("share preparation spent ingress admission or reached the target", admissions.Load(), redemptions.Load(), forwarded.Load())
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodGet, "https://preview.example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(request.URL, append(cookies, &http.Cookie{Name: "app_session", Value: "value", Path: "/"}))
			client.Jar = jar
			visit("/", http.StatusNoContent)
			visit("/", http.StatusNoContent)
			if admissions.Load() < 1 || redemptions.Load() != 1 || forwarded.Load() != 2 {
				t.Fatal("prepared share permission did not authorize application requests", admissions.Load(), redemptions.Load(), forwarded.Load())
			}
		})
	}
}
