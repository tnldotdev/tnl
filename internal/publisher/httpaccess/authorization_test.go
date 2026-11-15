package httpaccess

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAuthorizeRequestReturnsSelectedBearerProof(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "header", true: "cookie"}[cookie], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy, _, token := visitorfixture.ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}, "preview.example.test", 443, true)
				request := visitorfixture.Request()
				request.Header.Set("Authorization", "application-secret")
				request.AddCookie(&http.Cookie{Name: BrowserCookieName, Value: visitorfixture.BrowserCookie})
				if cookie {
					request.AddCookie(&http.Cookie{Name: VisitorTokenCookie, Value: token.Reveal()})
				} else {
					request.Header.Set(VisitorTokenHeader, token.Reveal())
				}
				response := httptest.NewRecorder()
				authorization, guard, guarded, err := AuthorizeRequest(response, request, policy, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer guard.Finish()
				selected, ok := authorization.BearerToken()
				view, _, _ := policy.Current()
				verified, err := visitortoken.VerifyBearer(token, view, time.Now())
				if err != nil || !ok || selected != token || authorization.Permission().Facts() != verified.Facts() {
					t.Fatal("authorization lost the selected bearer token or its verified permission", err)
				}
				if guarded.Header.Get(VisitorTokenHeader) != "" || guarded.Header.Get("Authorization") != "application-secret" ||
					guarded.Header.Get("Cookie") != request.Header.Get("Cookie") || guarded.Context().Err() != nil {
					t.Fatal("returning proof changed guarded request semantics")
				}
				if len(response.Result().Cookies()) != 0 {
					t.Fatal("selecting the supplied proof wrote a replacement cookie")
				}
			})
		})
	}
}

func TestAuthorizeRequestAnonymousHasNoBearerProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, _, _ := visitorfixture.Policy(t, true)
		authorization, guard, _, err := AuthorizeRequest(httptest.NewRecorder(), visitorfixture.Request(), policy, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Finish()
		if token, ok := authorization.BearerToken(); ok || token != "" || authorization.Permission().Valid() {
			t.Fatal("anonymous authorization exposed a signed permission or bearer proof")
		}
	})
}

func TestAuthorizeRequestBindFailureKeepsVerifiedPermissionWithoutBearer(t *testing.T) {
	base, armed, checks := time.Now(), false, 0
	policy, _, token := visitorfixture.PolicyClock(t, false, func() time.Time {
		if armed {
			checks++
			if checks > 1 {
				return base.Add(time.Minute)
			}
		}
		return base
	})
	request := visitorfixture.Request()
	request.Header.Set(VisitorTokenHeader, token.Reveal())
	armed = true
	authorization, guard, guarded, err := AuthorizeRequest(httptest.NewRecorder(), request, policy, nil)
	if bearer, ok := authorization.BearerToken(); !errors.Is(err, visitortoken.ErrPolicy) || !authorization.Permission().Valid() ||
		ok || bearer != "" || guard != nil || guarded != nil {
		t.Fatal("failed bind lost its verified permission observation or exposed accepted bearer proof", err)
	}
}

func TestAuthorizeRequestReturnsAcceptedRenewalProof(t *testing.T) {
	for _, cookie := range []bool{false, true} {
		for _, revision := range []bool{false, true} {
			name := fmt.Sprintf("cookie=%t/revision=%t", cookie, revision)
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					policy, key, subject := browserTokensFixture(t)
					client := &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
						t.Error("request authorization fetched visitor authority")
						return controlv1.VisitorTokenResponse{}, clientcontrol.ErrUnavailable
					}}
					tokens, err := StartTokens(t.Context(), client, policy.Lease(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tokens.Close()
					source, parent := browserSourceFixture(visitorfixture.BrowserCookie), time.Now().Add(30*time.Minute)
					initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(time.Minute))
					if err := tokens.install(source, initial, parent); err != nil {
						t.Fatal(err)
					}
					if revision {
						policy.client.(*visitorfixture.PolicyClient).Revision.Store(2)
						if err := policy.Refresh(t.Context()); err != nil {
							t.Fatal(err)
						}
					}
					replacement := signedBrowserPermission(t, policy, key, subject, time.Now().Add(2*time.Minute))
					if err := tokens.install(source, replacement, parent); err != nil {
						t.Fatal(err)
					}
					request := visitorfixture.Request()
					if cookie {
						request.AddCookie(&http.Cookie{Name: VisitorTokenCookie, Value: initial.VisitorToken})
					} else {
						request.Header.Set(VisitorTokenHeader, initial.VisitorToken)
					}
					response := httptest.NewRecorder()
					authorization, guard, guarded, err := AuthorizeRequest(response, request, policy.Lease(), tokens)
					if err != nil {
						t.Fatal(err)
					}
					defer guard.Finish()
					selected, ok := authorization.BearerToken()
					view, _, _ := policy.Lease().Current()
					verified, err := visitortoken.VerifyBearer(selected, view, time.Now())
					if err != nil || !ok || selected.Reveal() != replacement.VisitorToken ||
						authorization.Permission().Facts() != verified.Facts() || !verified.Facts().ExpiresAt.Equal(replacement.ExpiresAt) {
						t.Fatal("accepted renewal returned a mismatched token and permission", err)
					}
					cookies := response.Result().Cookies()
					if len(cookies) != 1 || cookies[0].Name != VisitorTokenCookie || cookies[0].Value != selected.Reveal() ||
						guarded.Header.Get(VisitorTokenHeader) != "" || client.Calls.Load() != 0 {
						t.Fatal("accepted proof did not match the replacement cookie or changed request admission")
					}
				})
			})
		}
	}
}

func TestAuthorizeRequestRejectedRenewalRetainsOriginalProof(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		policy, key, subject := browserTokensFixture(t)
		client := &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			return controlv1.VisitorTokenResponse{}, clientcontrol.ErrUnavailable
		}}
		tokens, err := StartTokens(t.Context(), client, policy.Lease(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		source, parent := browserSourceFixture(visitorfixture.BrowserCookie), time.Now().Add(30*time.Minute)
		initial := signedBrowserPermission(t, policy, key, subject, time.Now().Add(5*time.Minute))
		if err := tokens.install(source, initial, parent); err != nil {
			t.Fatal(err)
		}
		// a newer response can expire before a still-valid earlier alias.
		replacement := signedBrowserPermission(t, policy, key, subject, time.Now().Add(3*time.Second))
		if err := tokens.install(source, replacement, parent); err != nil {
			t.Fatal(err)
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		request := visitorfixture.Request()
		request.Header.Set(VisitorTokenHeader, initial.VisitorToken)
		_, probe, _, err := authorizeHTTPRequest(httptest.NewRecorder(), request, policy.Lease(), tokens)
		if err != nil {
			t.Fatal(err)
		}
		prepared, accepted, release, found := tokens.use(visitortoken.Token(initial.VisitorToken), probe.local)
		probe.release = release
		probe.Finish()
		if found || prepared.VisitorToken != "" || accepted.Valid() {
			t.Fatal("failed guard renewal exposed its replacement token or permission")
		}
		response := httptest.NewRecorder()
		authorization, guard, guarded, err := AuthorizeRequest(response, request, policy.Lease(), tokens)
		if err != nil {
			t.Fatal(err)
		}
		selected, ok := authorization.BearerToken()
		view, _, _ := policy.Lease().Current()
		verified, err := visitortoken.VerifyBearer(selected, view, time.Now())
		if err != nil || !ok || selected.Reveal() != initial.VisitorToken || authorization.Permission().Facts() != verified.Facts() {
			t.Fatal("rejected guard renewal selected the expired replacement proof", err)
		}
		if len(response.Result().Cookies()) != 0 || guarded.Context().Err() != nil {
			t.Fatal("rejected renewal wrote a replacement cookie or canceled valid original permission")
		}
		// rejection must retain the original guard's renewal/revocation owner.
		tokens.mu.Lock()
		entry := tokens.sources[sha256.Sum256(source)]
		_, registered := entry.guards[guard.local]
		tokens.mu.Unlock()
		if !registered {
			t.Fatal("rejected renewal detached its original guard from its source")
		}
		guard.Finish()
		tokens.mu.Lock()
		_, registered = entry.guards[guard.local]
		tokens.mu.Unlock()
		if registered {
			t.Fatal("finished request retained its renewal registration")
		}
	})
}

func TestAuthorizationRedactsFormatting(t *testing.T) {
	policy, _, token := visitorfixture.Policy(t, false)
	view, _, _ := policy.Current()
	permission, err := visitortoken.VerifyBearer(token, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, authorization := range []Authorization{{}, {permission: permission, bearer: token}} {
		for _, value := range []any{authorization, &authorization, struct{ Access Authorization }{authorization}} {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				formatted := fmt.Sprintf(format, value)
				if !strings.Contains(formatted, "HTTP authorization") || strings.Contains(formatted, token.Reveal()) ||
					strings.Contains(formatted, permission.Facts().Subject.(visitortoken.Browser).SessionID) {
					t.Fatal("authorization formatting exposed credential or permission details")
				}
			}
		}
	}
}
