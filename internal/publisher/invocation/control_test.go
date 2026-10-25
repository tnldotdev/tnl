package invocation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicationControlPreparesVisitorsWithoutManagementAuthentication(t *testing.T) {
	policyCalls, tokenCalls := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/visitor-policy":
			policyCalls++
			if r.Header.Get("Authorization") != "Bearer exact-run-token" {
				t.Error("policy preparation lost its scoped run credential")
			}
			_ = json.NewEncoder(w).Encode(controlv1.VisitorPolicyUpdate{})
		case "/v1/visitor-tokens":
			tokenCalls++
			if r.Header.Get("Authorization") != "" {
				t.Error("explicit visitor source borrowed management authentication")
			}
			_ = json.NewEncoder(w).Encode(controlv1.VisitorTokenResponse{VisitorToken: "prepared"})
		default:
			t.Errorf("visitor preparation called %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("management-token"))
	if err != nil {
		t.Fatal(err)
	}
	control := nativePublicationControl(nil, client)
	if _, err := control.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{}, "exact-run-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := control.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Source: json.RawMessage(`{"kind":"browser_session","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)}); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 || tokenCalls != 1 {
		t.Fatal("publication wrapper hid visitor preparation capabilities")
	}
}
