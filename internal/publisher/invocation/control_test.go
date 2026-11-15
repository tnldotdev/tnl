package invocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicationClientsPrepareVisitorsWithoutManagementAuthentication(t *testing.T) {
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
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := serviceTestID(t, opaqueid.ServicePrefix)
	native, err := publisheridentity.NewNative(publisheridentity.NativeControl{Services: client}, authority, authorityv1.PublisherEnrollmentResult{
		ClientId: serviceTestID(t, opaqueid.PublisherIdentityPrefix), GrantId: serviceTestID(t, opaqueid.PublisherGrantPrefix),
		KeyId: serviceTestID(t, opaqueid.PublisherIdentityKeyPrefix), TeamId: serviceTestID(t, opaqueid.TeamPrefix),
		Kind: authorityv1.Service, ServiceId: &id,
	}, signing)
	if err != nil {
		t.Fatal(err)
	}
	scope := controlv1.VisitorResourceScope{Kind: "service", Id: id}
	if _, err := native.ReadPublisherVisitorPolicy(t.Context(), controlv1.PublisherVisitorPolicyRequest{
		Resource: scope, RunId: serviceTestID(t, opaqueid.ServiceRunPrefix), RunNumber: 1,
	}, "exact-run-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := native.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{
		Resource: scope, Source: json.RawMessage(`{"kind":"browser_session","secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 || tokenCalls != 1 {
		t.Fatal("publication clients did not prepare both visitor capabilities")
	}
}
