package public

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationVisitorTokenAPIHasOneSourceAndNoManagementAuthority(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "visitor_token_api")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now()
	session, err := controltest.Session(t.Context(), d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(t.Context(), session.Identity.Identity.ID, member.TeamID)
	if err != nil || len(domains) == 0 {
		t.Fatal("missing managed domain", err)
	}
	url, err := d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "token-api", RequestDigest: sha256.Sum256([]byte("token-api")), CanonicalHostname: "token." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	mux := testHandler(t, Config{ControlURL: "https://control.example.test", ManagedDomain: "example.test"}, d, d, nil)
	request := func(path, body, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	body := `{"resource":{"kind":"public_url","id":"` + url.ID + `"},"source":{"kind":"control_session"}}`
	response := request("/v1/visitor-tokens", body, session.AccessToken.String())
	var permission controlv1.VisitorTokenResponse
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &permission) != nil || permission.VisitorToken == "" || len(permission.VisitorToken) > 2048 || permission.Resource.Id != url.ID || permission.VisitorPolicyRevision < 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("visitor token response: status=%d", response.Code)
	}
	if _, err := d.AuthenticateAccessToken(t.Context(), credentials.AccessToken(permission.VisitorToken), time.Now()); !errors.Is(err, controlstate.ErrControlAuthentication) {
		t.Fatal("visitor token authenticated a control session", err)
	}
	management := httptest.NewRequest(http.MethodGet, "/v1/public-urls?team_id="+member.TeamID, nil)
	management.Header.Set("Authorization", "Bearer "+permission.VisitorToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, management)
	if w.Code != 401 {
		t.Fatalf("visitor token granted management reads: status=%d", w.Code)
	}
	for name, source := range map[string]string{
		"mixed":          `{"kind":"control_session","secret":"ignored"}`,
		"publisher":      `{"kind":"publisher"}`,
		"wrong-resource": `{"kind":"control_session"}`,
	} {
		t.Run(name, func(t *testing.T) {
			resource := `{"kind":"public_url","id":"` + url.ID + `"}`
			if name == "wrong-resource" {
				resource = `{"kind":"service","id":"` + url.ID + `"}`
			}
			if response := request("/v1/visitor-tokens", `{"resource":`+resource+`,"source":`+source+`}`, session.AccessToken.String()); response.Code != 400 {
				t.Fatalf("invalid source returned %d", response.Code)
			}
		})
	}
	secret := strings.Repeat("A", 43)
	response = request("/v1/visitor-tokens", `{"resource":{"kind":"public_url","id":"`+url.ID+`"},"source":{"kind":"browser_session","secret":"`+secret+`"}}`, session.AccessToken.String())
	if response.Code != 400 || bytes.Contains(response.Body.Bytes(), []byte(secret)) {
		t.Fatal("mixed authority sources were accepted or exposed")
	}
}
