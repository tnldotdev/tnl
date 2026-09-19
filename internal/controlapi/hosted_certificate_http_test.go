package controlapi_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationHostedCertificateIssuanceHTTP(t *testing.T) {
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "controlstate_hosted_http")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)

	const (
		directory    = "https://acme.example.test/directory"
		hostname     = "api.member.routes.example.test"
		namespace    = "member.routes.example.test"
		hostedSecret = "0123456789abcdef0123456789abcdef"
		accessToken  = "external-access-token"
	)
	membershipID := "external_membership"
	now := time.Now()
	if _, err := database.EnsureACMEAccount(t.Context(), directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		name := fmt.Sprintf("relay-%d", index)
		if _, err := database.RegisterRelay(t.Context(), controlstate.RelayRegistration{
			RelayServiceID: name, RelayID: name, RelayRunID: name + "-run", ProtocolVersion: 1,
			RelayAddress: name + ".infra.example.test:443", TLSServerName: name + ".infra.example.test",
			InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10,
		}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	plan := authorityv1.CertificatePlan{
		CacheKey: namespace, Scope: namespace, Identifiers: []string{namespace, "*." + namespace},
		ChallengeMethod: authorityv1.Dns01,
	}
	slices.Sort(plan.Identifiers)

	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/identity":
			if r.Header.Get("Authorization") != "Bearer "+accessToken {
				t.Error("identity request did not use the publisher access token")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{
				Identity: authorityv1.Identity{Id: "external_identity"}, PersonalTeamId: "external_team",
				Memberships: []authorityv1.Membership{{Id: membershipID, TeamId: "external_team"}},
			})
		case "/v1/service/authorize":
			var request authorityv1.ServiceAuthorizationRequest
			if r.Header.Get("Authorization") != "Bearer "+hostedSecret || json.NewDecoder(r.Body).Decode(&request) != nil ||
				request.AccessToken != accessToken || request.TeamId != "external_team" ||
				request.DomainId != "external_domain" || request.CanonicalHostname != hostname {
				t.Error("unexpected service authorization request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			decision := authorityv1.ServiceAuthorizationDecision{
				IdentityId: "external_identity", TeamId: request.TeamId, DomainId: request.DomainId,
				ActingMembershipId: membershipID, RouteMembershipId: &membershipID, ActingRole: authorityv1.TeamRoleMember,
				PolicyRevision: 1, CanonicalHostname: hostname, RouteScope: authorityv1.RouteScopeMember,
				DnsAuthorityReference: "managed:routes.example.test",
			}
			if request.Operation == authorityv1.RouteSessionCreate {
				decision.CertificatePlan = &plan
			} else if request.Operation != authorityv1.RouteCreate {
				t.Errorf("unexpected operation %q", request.Operation)
			}
			_ = json.NewEncoder(w).Encode(decision)
		default:
			t.Errorf("unexpected authority path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(authority.Close)
	handler := controlapi.NewHandler(controlapi.Config{
		AuthorityEndpoint: authority.URL, HostedSecret: hostedSecret, HTTPClient: authority.Client(),
		DNSAutomation: true, CertificateIssuance: true, ACMEDirectoryURL: directory,
	}, database, nil, nil)
	post := func(t *testing.T, path, token, idempotencyKey string, body any, wantStatus int, result any) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(wire))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", idempotencyKey)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != wantStatus {
			t.Fatalf("POST %s = HTTP %d: %s; want HTTP %d", path, response.Code, response.Body.String(), wantStatus)
		}
		if err := json.Unmarshal(response.Body.Bytes(), result); err != nil {
			t.Fatal(err)
		}
	}

	var route controlv1.Route
	post(t, "/v1/routes", accessToken, "route", controlv1.CreateRouteRequest{
		TeamId: "external_team", DomainId: "external_domain", CanonicalHostname: hostname,
		RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000", AllowedIpPrefixes: &[]string{},
	}, http.StatusCreated, &route)
	var setup controlv1.RouteSessionSetup
	post(t, "/v1/routes/"+route.Id+"/sessions", accessToken, "session", struct{}{}, http.StatusCreated, &setup)
	if setup.CertificatePlan.CacheKey != plan.CacheKey || setup.CertificatePlan.Scope != plan.Scope ||
		!slices.Equal(setup.CertificatePlan.Identifiers, plan.Identifiers) ||
		string(setup.CertificatePlan.ChallengeMethod) != string(plan.ChallengeMethod) {
		t.Fatalf("route session did not preserve the authority plan: %#v", setup.CertificatePlan)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/route-sessions/" + setup.RouteSession.Id + "/certificate-issuances"
	for _, test := range []struct {
		name        string
		identifiers []string
		wantStatus  int
	}{
		{"exact_host_rejected", []string{hostname}, http.StatusBadRequest},
		{"complete_namespace_accepted", plan.Identifiers, http.StatusCreated},
	} {
		t.Run(test.name, func(t *testing.T) {
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: test.identifiers}, key)
			if err != nil {
				t.Fatal(err)
			}
			body := controlv1.CreateCertificateIssuanceRequest{RouteVersion: setup.RouteSession.RouteVersion, Csr: csr}
			if test.wantStatus == http.StatusBadRequest {
				var problem controlv1.Problem
				post(t, path, setup.RouteSessionToken, test.name, body, test.wantStatus, &problem)
				if problem.Code != controlv1.InvalidRequest {
					t.Fatalf("exact-host CSR rejection = %#v", problem)
				}
				return
			}
			var issuance controlv1.CertificateIssuance
			post(t, path, setup.RouteSessionToken, test.name, body, test.wantStatus, &issuance)
			if issuance.Id == "" || issuance.CertificatePlan.CacheKey != plan.CacheKey ||
				issuance.CertificatePlan.Scope != plan.Scope ||
				!slices.Equal(issuance.CertificatePlan.Identifiers, plan.Identifiers) ||
				string(issuance.CertificatePlan.ChallengeMethod) != string(plan.ChallengeMethod) {
				t.Fatalf("issuance did not preserve the persisted authority plan: %#v", issuance)
			}
		})
	}
}
