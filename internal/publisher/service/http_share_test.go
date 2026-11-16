package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPShareRedemptionKeepsOneTLSConnection(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(2), Concurrency: new(1),
				Rate: &controlv1.ProjectApplicationRate{Count: 2, Per: "1h", Burst: new(2)}})
			if err != nil {
				t.Fatal(err)
			}
			var dials, redemptions, capacity, admissions, forwarded atomic.Int32
			shareID := "shr_" + strings.Repeat("S", 22)
			secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
			cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
			client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				if r.URL.RequestURI() != "/" || r.Header.Get("Cookie") != "app_session=ok" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
					t.Error("shared application request changed its path or retained a tnl credential")
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
				scope, run, runToken, number := f.Subject, f.RunID, f.Token, f.Number
				control := serviceHTTPShareControl{
					redeem: func(_ context.Context, service, gotRun string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
						redemptions.Add(1)
						if service != scope.ID || gotRun != run || token != runToken || request.RunNumber != number ||
							request.ShareId == nil || *request.ShareId != shareID || request.Secret == nil || *request.Secret != secret || request.HandoffToken != nil {
							t.Error("share redemption changed the service run or link")
							return controlv1.ShareRedemption{}, visitortoken.ErrBinding
						}
						view, _, _ := policy.Lease().Current()
						facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
							Subject: visitortoken.Share{ShareID: shareID}, ExpiresAt: time.Now().Add(5 * time.Minute).Truncate(time.Second)}
						signed, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
						return controlv1.ShareRedemption{ShareId: shareID, CookieSecret: cookie, ExpiresAt: time.Now().Add(time.Hour),
							NextUrl: "https://preview.example.test/",
							Permission: controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Hostname: facts.Hostname, Port: int(facts.Port),
								VisitorPolicyRevision: facts.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt, VisitorToken: signed.Reveal()}}, err
					},
				}
				f.Control, f.Policy, f.Requests = control, policy.Lease(), budget
				f.browser = &httpaccess.Browser{Subject: scope, Client: control, RunID: run, Number: number, Token: runToken, Policy: policy, Tokens: tokens}
				f.ReserveCapacity = func(context.Context) error {
					capacity.Add(1)
					return nil
				}
				f.AdmitRequest = func(*http.Request) error {
					admissions.Add(1)
					return nil
				}
			})
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			protocol := 1
			if h2 {
				protocol = 2
			}
			visit := func(path string, want int) []*http.Cookie {
				t.Helper()
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil || response.StatusCode != want || response.ProtoMajor != protocol ||
					response.TLS == nil || !response.TLS.HandshakeComplete {
					t.Fatal("share visit changed its response or TLS protocol", path, response.Status, response.Proto, readErr, closeErr)
				}
				return response.Cookies()
			}
			visit("/", http.StatusForbidden)
			visit("/__tnl/share/invalid", http.StatusForbidden)
			if capacity.Load() != 0 || redemptions.Load() != 0 || forwarded.Load() != 0 {
				t.Fatal("denied request spent admission or reached control or the target")
			}
			deniedAdmissions := admissions.Load()
			// HTTP/1 denial closes its connection. start one fresh TLS socket
			// for redemption and both application requests in either protocol.
			transport := client.Transport.(*http.Transport)
			transport.CloseIdleConnections()
			transport = transport.Clone()
			client.Transport = transport
			t.Cleanup(transport.CloseIdleConnections)
			dial := transport.DialContext
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if dials.Add(1) != 1 {
					t.Error("share redemption or its application requests tried to redial")
					return nil, net.ErrClosed
				}
				return dial(ctx, network, address)
			}
			cookies := visit("/__tnl/share/"+shareID+"."+secret, http.StatusSeeOther)
			if len(cookies) != 2 || dials.Load() != 1 || redemptions.Load() != 1 || capacity.Load() != 0 || admissions.Load() != deniedAdmissions || forwarded.Load() != 0 {
				t.Fatal("share preparation spent application admission or changed its connection", dials.Load(), redemptions.Load(), capacity.Load(), admissions.Load(), forwarded.Load())
			}
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequest(http.MethodGet, "https://preview.example.test/", nil)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(request.URL, append(cookies, &http.Cookie{Name: "app_session", Value: "ok", Path: "/"}))
			client.Jar = jar
			for i := range 2 {
				select {
				case <-budget.Completed():
					t.Fatal("share preparation or the first request spent the two-request total")
				default:
				}
				visit("/", http.StatusNoContent)
				if dials.Load() != 1 || redemptions.Load() != 1 || capacity.Load() != 1 || admissions.Load() != deniedAdmissions+int32(i+1) || forwarded.Load() != int32(i+1) {
					t.Fatal("shared application requests changed connection, admission, or forwarding counts", dials.Load(), redemptions.Load(), capacity.Load(), admissions.Load(), forwarded.Load())
				}
			}
			serviceHTTPAwait(t, budget.Completed())
		})
	}
}
