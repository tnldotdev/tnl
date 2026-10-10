package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type scopedCredentialStoreStub struct {
	PublicURLPublishCredentialStore
	credential  controlstate.PublicURLPublishCredential
	validations int
}

func (s *scopedCredentialStoreStub) CreatePublicURLPublishCredential(_ context.Context, _ controlstate.CreatePublicURLPublishCredentialRequest) (controlstate.PublicURLPublishCredential, credentials.PublicURLPublishCredential, error) {
	return s.credential, "tnl_publish_one_time_secret", nil
}

func (s *scopedCredentialStoreStub) ListPublicURLPublishCredentials(_ context.Context, _ string) ([]controlstate.PublicURLPublishCredential, error) {
	return []controlstate.PublicURLPublishCredential{s.credential}, nil
}

func (s *scopedCredentialStoreStub) AuthenticatePublicURLPublishCredential(_ context.Context, _ credentials.PublicURLPublishCredential, _ time.Time) (controlstate.PublicURLPublishCredential, []byte, error) {
	return s.credential, make([]byte, 32), nil
}

func (s *scopedCredentialStoreStub) ValidatePublicURLPublishCredential(_ context.Context, _ controlstate.PublicURLPublishCredential, _ controlstate.PublicURL) error {
	s.validations++
	return nil
}

func TestPublishCredentialCannotStartAnotherPublicURL(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "app.example", Target: "http://app:3000", Purpose: controlstate.PublicURLPurposeApp,
		LifecycleState: controlstate.PublicURLLifecycleEnabled, PublicURLScope: controlstate.PublicURLScopeMember,
		MutationRevision: 1, AuthorizationPublishRunNumber: 1,
	}}
	credential := &scopedCredentialStoreStub{credential: controlstate.PublicURLPublishCredential{
		ID: "upc_1", PublicURLID: "public_url_1", IdentityID: "identity_1", MembershipID: "membership_1",
		PolicyRevision: 1, Target: "http://app:3000", CertificatePlan: authorization.CertificatePlan{
			CacheKey: "app.example", Scope: "app.example", Identifiers: []string{"app.example"}, ChallengeMethod: "tls-alpn-01",
		},
	}}
	h := &handler{store: store, publishCredentials: credential}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_2/publish-runs", nil)
	request.Header.Set("Authorization", "Bearer tnl_publish_example")
	request.Header.Set("Idempotency-Key", "attempt")
	response := httptest.NewRecorder()
	h.CreatePublishRun(response, request, "public_url_2", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusNotFound || store.sessions != 0 || store.sessionLookup != [2]string{} {
		t.Fatalf("cross-URL publish = %d, requests = %d, lookup = %#v", response.Code, store.sessions, store.sessionLookup)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/publish-credentials/current", nil)
	request.Header.Set("Authorization", "Bearer tnl_publish_example")
	response = httptest.NewRecorder()
	h.GetPublicURLForPublishCredential(response, request)
	var route controlv1.PublicURL
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &route) != nil || route.Id != "public_url_1" || credential.validations != 2 {
		t.Fatalf("bound URL = %d %s", response.Code, response.Body.String())
	}
	store.sessionSetup = controlstate.PublishRunSetup{
		PublishRunID: "publish_run_1", PublicURLID: "public_url_1", TeamID: "team_1", MembershipID: "membership_1",
		PublishRunNumber: 1, PolicyRevision: 1, PublishRunToken: "tnl_session_test", State: controlstate.PublishRunStarting,
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-runs", nil)
	request.Header.Set("Authorization", "Bearer tnl_publish_example")
	request.Header.Set("Idempotency-Key", "run-1")
	response = httptest.NewRecorder()
	h.CreatePublishRun(response, request, "public_url_1", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusCreated || store.sessions != 1 || store.sessionRequest.PublishCredentialID != "upc_1" ||
		store.sessionRequest.ActingIdentityID != "identity_1" || store.sessionRequest.IdempotencyKey != "run-1" {
		t.Fatalf("scoped run = %d %s, request = %#v", response.Code, response.Body.String(), store.sessionRequest)
	}
}

func TestPublishCredentialIsReturnedOnlyAtIssuance(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "app.example", Target: "http://app:3000", Purpose: controlstate.PublicURLPurposeApp,
		PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
		NextPublishRunNumber: 1, MutationRevision: 1, AuthorizationPublishRunNumber: 1,
	}}
	credential := &scopedCredentialStoreStub{credential: controlstate.PublicURLPublishCredential{
		ID: "upc_1", PublicURLID: "public_url_1", ExpiresAt: time.Now().Add(time.Hour),
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1", PolicyRevision: 1,
		CertificatePlan: &authorization.CertificatePlan{CacheKey: "app.example", Scope: "app.example", Identifiers: []string{"app.example"}, ChallengeMethod: "tls-alpn-01"},
	}}
	h := &handler{store: store, publishCredentials: credential, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-credentials", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.CreatePublicURLPublishCredential(response, request, "public_url_1")
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("issue response = %d %s", response.Code, response.Body.String())
	}
	var issued controlv1.IssuedPublicURLPublishCredential
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil || issued.Credential != "tnl_publish_one_time_secret" {
		t.Fatalf("issued credential = %#v, %v", issued, err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/public-urls/public_url_1/publish-credentials", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response = httptest.NewRecorder()
	h.ListPublicURLPublishCredentials(response, request, "public_url_1")
	if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) ||
		strings.Contains(response.Body.String(), "tnl_publish_one_time_secret") {
		t.Fatalf("list disclosed credential = %d %s", response.Code, response.Body.String())
	}
}
