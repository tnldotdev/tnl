package httpaccess

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareTestClient struct {
	redeem func(context.Context, string, string, controlv1.RedeemServiceShareRequest, credentials.ServiceRunToken) (controlv1.ShareRedemption, error)
}

func (c shareTestClient) RedeemServiceShare(ctx context.Context, service, run string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	return c.redeem(ctx, service, run, request, token)
}

func TestSharesRedeemOnlyForBoundServiceRun(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("S", 22)}
	runID := "srun_" + strings.Repeat("R", 22)
	shareID := "shr_" + strings.Repeat("H", 22)
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	policy, err := PreparePolicy(t.Context(), &visitorfixture.PolicyClient{Key: key}, scope, runID, 7, "run-secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Close()
	tokens, err := StartTokens(t.Context(), &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
		t.Error("initial share preparation tried to mint another permission")
		return controlv1.VisitorTokenResponse{}, visitortoken.ErrToken
	}}, policy.Lease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tokens.Close()
	browser := &Browser{Subject: scope, RunID: runID, Number: 7, Token: "run-secret", Policy: policy, Tokens: tokens}
	access := Shares{Browser: browser}
	expires := time.Now().Add(time.Hour)
	for _, handoff := range []bool{false, true} {
		path := "/__tnl/share/" + shareID + "." + secret
		if handoff {
			path = "/__tnl/share/handoff/" + secret
		}
		calls := 0
		access.Client = shareTestClient{redeem: func(_ context.Context, service, run string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
			calls++
			if service != scope.ID || run != runID || request.RunNumber != 7 || token != browser.Token {
				t.Fatal("share redemption changed the authenticated service run")
			}
			if handoff {
				if request.HandoffToken == nil || *request.HandoffToken != secret || request.Secret != nil || request.ShareId != nil {
					t.Fatal("handoff was converted into a fresh share link")
				}
			} else if request.ShareId == nil || *request.ShareId != shareID || request.Secret == nil || *request.Secret != secret || request.HandoffToken != nil {
				t.Fatal("share link was converted into a handoff")
			}
			view, _, _ := policy.Lease().Current()
			facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
				Subject: visitortoken.Share{ShareID: shareID}, ExpiresAt: time.Now().Add(5 * time.Minute).Truncate(time.Second)}
			tokenValue, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
			return controlv1.ShareRedemption{ShareId: shareID, CookieSecret: cookie, ExpiresAt: expires, NextUrl: "https://preview.example.test/",
				Permission: controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, Hostname: facts.Hostname, Port: int(facts.Port),
					VisitorPolicyRevision: facts.VisitorPolicyRevision, VisitorToken: tokenValue.Reveal(), ExpiresAt: facts.ExpiresAt}}, err
		}}
		result, err := access.Redeem(t.Context(), path)
		if err != nil || calls != 1 || result.ShareId != shareID {
			t.Fatal("valid share redemption failed", err, calls)
		}
		for _, invalid := range []string{
			"/__tnl/share/vrf1.shg_" + strings.Repeat("G", 22) + "." + secret,
			"/__tnl/share/" + shareID + ".invalid",
			"/__tnl/share/" + shareID + "." + secret + "/extra",
			"/__tnl/share/handoff/invalid",
			"/__tnl/team/handoff/" + secret,
		} {
			if _, err := access.Redeem(t.Context(), invalid); err == nil || calls != 1 {
				t.Fatal("invalid share path reached control", invalid, err, calls)
			}
		}
		wrong := access
		wrongBrowser := *browser
		wrongBrowser.Subject.ID = "svc_" + strings.Repeat("X", 22)
		wrong.Browser = &wrongBrowser
		if _, err := wrong.Redeem(t.Context(), path); !errors.Is(err, visitortoken.ErrBinding) || calls != 1 {
			t.Fatal("share redemption used another service's browser preparation", err)
		}
	}
}

func TestShareHandoffBridgeResetsLongRedirectChains(t *testing.T) {
	redemption := controlv1.ShareRedemption{
		ShareId:      "shr_0123456789abcdefghijkl",
		CookieSecret: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))),
		NextUrl:      "https://api.example.test/__tnl/share/handoff/token?step=8&next=9",
		ExpiresAt:    time.Now().Add(time.Hour), Bridge: true,
		Permission: controlv1.VisitorTokenResponse{VisitorToken: "signed-share-permission", ExpiresAt: time.Now().Add(5 * time.Minute)},
	}
	response := httptest.NewRecorder()
	ShareRedirect(response, redemption)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `step=8&amp;next=9`) ||
		!strings.Contains(response.Body.String(), "http-equiv=\"refresh\"") ||
		response.Header().Get("Referrer-Policy") != "no-referrer" || len(response.Result().Cookies()) != 2 {
		t.Fatalf("long handoff bridge = %d, %q, %#v", response.Code, response.Body.String(), response.Header())
	}
	for _, cookie := range response.Result().Cookies() {
		if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatal("share handoff installed a cookie outside its host", cookie.Name)
		}
	}
}

func TestBrowserRenewalRejectsRetiredShareGrantSources(t *testing.T) {
	source := []byte(`{"kind":"grant","credential":"vrf1.shg_0123456789abcdefghijkl.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)
	if _, err := canonicalBrowserTokenSource(source); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("browser renewal retained the duplicate share-grant path", err)
	}
}

func TestSharePreparationFailureDoesNotLogCauses(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("private detail: %w", context.DeadlineExceeded), "policy refresh timed out"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrPolicy), "visitor policy unavailable"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrKey), "verification key unavailable"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrToken), "visitor token invalid"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrBinding), "visitor token binding invalid"},
		{errors.New("private detail"), "visitor permission unavailable"},
	} {
		if got := sharePreparationFailure(test.err); got != test.want {
			t.Fatalf("share preparation reason = %q, want %q", got, test.want)
		}
	}
}
