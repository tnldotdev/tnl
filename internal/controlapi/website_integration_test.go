package controlapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationWebsiteIdentityDoesNotIssuePublishingCredentials(t *testing.T) {
	url := testutil.NewDisposablePostgresDatabaseURL(t, "website_api")
	if err := controlstate.Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	const secret = "website-secret-01234567890123456789"
	h, err := authorityapi.NewHandler(authorityapi.Config{ManagedDomain: "routes.example.test", OIDCIssuer: "https://account.example", WebServiceSecret: secret}, database)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/service/identity-context", "/v1/auth/logout"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"subject":"sam","display_name":"Sam"}`))
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 200
		if path == "/v1/auth/logout" {
			want = 401
		}
		if w.Code != want || strings.Contains(w.Body.String(), "access_token") {
			t.Fatalf("website operation %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
