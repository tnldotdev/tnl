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
	credential     controlstate.PublicURLPublishCredential
	issuedScope    controlstate.CreateEphemeralCredentialRequest
	page           controlstate.PublicURLPublishCredentialPage
	validations    int
	revocations    int
	issuedLifetime time.Duration
}

func (s *scopedCredentialStoreStub) CreatePublicURLPublishCredential(_ context.Context, request controlstate.CreatePublicURLPublishCredentialRequest) (controlstate.PublicURLPublishCredential, credentials.PublicURLPublishCredential, error) {
	s.issuedLifetime = request.ExpiresAt.Sub(request.Now)
	return s.credential, "tnl_publish_one_time_secret", nil
}

func (s *scopedCredentialStoreStub) CreateEphemeralCredential(_ context.Context, request controlstate.CreateEphemeralCredentialRequest) (controlstate.PublicURLPublishCredential, credentials.EphemeralCredential, error) {
	s.issuedScope = request
	return controlstate.PublicURLPublishCredential{
		ID: "upc_ephemeral", Kind: controlstate.PublishCredentialEphemeral, TeamID: request.TeamID,
		DomainID: request.DomainID, Namespace: request.Namespace, CreatedAt: request.Now, ExpiresAt: request.ExpiresAt,
	}, "tnl_eph_one_time_secret", nil
}

func (s *scopedCredentialStoreStub) RevokeEphemeralCredential(_ context.Context, teamID, id string, now time.Time) (controlstate.PublicURLPublishCredential, error) {
	s.revocations++
	s.credential.RevokedAt = &now
	return s.credential, nil
}

func (s *scopedCredentialStoreStub) ListPublicURLPublishCredentials(_ context.Context, _ string) ([]controlstate.PublicURLPublishCredential, error) {
	return []controlstate.PublicURLPublishCredential{s.credential}, nil
}

func (s *scopedCredentialStoreStub) ListTeamPublicURLPublishCredentials(_ context.Context, _, _ string) (controlstate.PublicURLPublishCredentialPage, error) {
	return s.page, nil
}

func (s *scopedCredentialStoreStub) PublicURLPublishCredentialByID(_ context.Context, _ string) (controlstate.PublicURLPublishCredential, error) {
	return s.credential, nil
}

func (s *scopedCredentialStoreStub) RevokePublicURLPublishCredential(_ context.Context, _, _ string, now time.Time) (controlstate.PublicURLPublishCredential, error) {
	s.revocations++
	s.credential.RevokedAt = &now
	return s.credential, nil
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
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" || credential.issuedLifetime != 90*24*time.Hour {
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
	for _, test := range []struct {
		body     string
		status   int
		lifetime time.Duration
	}{
		{`{"expires_in_seconds":604800}`, http.StatusCreated, 7 * 24 * time.Hour},
		{`{"expires_in_seconds":0}`, http.StatusBadRequest, 0},
		{`{"expires_in_seconds":7776001}`, http.StatusBadRequest, 0},
	} {
		request = httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-credentials", strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer access-token")
		response = httptest.NewRecorder()
		h.CreatePublicURLPublishCredential(response, request, "public_url_1")
		if response.Code != test.status || test.lifetime != 0 && credential.issuedLifetime != test.lifetime {
			t.Fatalf("lifetime %q = status %d, duration %s", test.body, response.Code, credential.issuedLifetime)
		}
	}
}

func TestEphemeralCredentialRequiresDNSWildcardAndDoesNotCreateURL(t *testing.T) {
	namespace := "member.example.test"
	store := &scopedCredentialStoreStub{}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", DomainID: "domain_1", ActingMembershipID: "membership_1",
		ActingRole: "member", PolicyRevision: 1, Namespace: namespace,
		CertificatePlan: &authorization.CertificatePlan{CacheKey: namespace, Scope: namespace,
			Identifiers: []string{"*." + namespace}, ChallengeMethod: "dns-01"},
	}}
	h := &handler{publishCredentials: store, authorizer: authorizer, config: Config{DNSAutomation: true}}
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/v1/publish-credentials", strings.NewReader(`{"team_id":"team_1","domain_id":"domain_1","public_url_scope":"member","expires_in_seconds":604800}`))
		request.Header.Set("Authorization", "Bearer access-token")
		return request
	}
	response := httptest.NewRecorder()
	h.CreateEphemeralPublishCredential(response, newRequest())
	if response.Code != http.StatusCreated || response.Header().Get("Cache-Control") != "no-store" ||
		store.issuedScope.Namespace != namespace || store.issuedScope.ExpiresAt.Sub(store.issuedScope.Now) != 7*24*time.Hour ||
		strings.Contains(response.Body.String(), "public_url_id") {
		t.Fatalf("ad-hoc issuance = %d %s, scope = %#v", response.Code, response.Body.String(), store.issuedScope)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0].Operation != authorization.OperationCredentialCreate {
		t.Fatalf("ad-hoc authorization = %#v", authorizer.requests)
	}
	h.config.DNSAutomation = false
	response = httptest.NewRecorder()
	h.CreateEphemeralPublishCredential(response, newRequest())
	if response.Code != http.StatusConflict {
		t.Fatalf("manual DNS issuance = %d", response.Code)
	}
	h.config.DNSAutomation = true
	authorizer.decision.CertificatePlan.ChallengeMethod = "tls-alpn-01"
	response = httptest.NewRecorder()
	h.CreateEphemeralPublishCredential(response, newRequest())
	if response.Code != http.StatusForbidden {
		t.Fatalf("exact-certificate issuance = %d", response.Code)
	}
}

func TestTeamCanListAndRevokeAdHocCredentialWithoutAURL(t *testing.T) {
	now := time.Now()
	credential := &scopedCredentialStoreStub{credential: controlstate.PublicURLPublishCredential{
		ID: "upc_ephemeral", Kind: controlstate.PublishCredentialEphemeral,
		TeamID: "team_1", DomainID: "domain_1", Namespace: "member.example.test", MembershipID: "membership_1",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, page: controlstate.PublicURLPublishCredentialPage{Credentials: []controlstate.PublicURLPublishCredentialSummary{
		{ID: "upc_ephemeral", Kind: controlstate.PublishCredentialEphemeral,
			TeamID: "team_1", DomainID: "domain_1", Namespace: "member.example.test", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
	}}
	h := &handler{store: &publicURLMutationStoreStub{}, publishCredentials: credential, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodGet, "/v1/publish-credentials?team_id=team_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.ListTeamPublicURLPublishCredentials(response, request, controlv1.ListTeamPublicURLPublishCredentialsParams{TeamId: "team_1"})
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "public_url_id") ||
		!strings.Contains(response.Body.String(), `"kind":"ephemeral"`) {
		t.Fatalf("team ad-hoc list = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/publish-credentials/upc_ephemeral?team_id=team_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response = httptest.NewRecorder()
	h.RevokePublishCredentialByID(response, request, "upc_ephemeral", controlv1.RevokePublishCredentialByIDParams{TeamId: "team_1"})
	if response.Code != http.StatusOK || credential.revocations != 1 ||
		len(authorizer.requests) != 1 || authorizer.requests[0].Operation != authorization.OperationCredentialRevoke ||
		strings.Contains(response.Body.String(), "public_url_id") {
		t.Fatalf("ad-hoc revoke = %d %s, requests = %#v", response.Code, response.Body.String(), authorizer.requests)
	}
}

func TestTeamCredentialManagementKeepsTeamBoundaryAndSecretPrivate(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "app.example", Target: "http://app:3000", Purpose: controlstate.PublicURLPurposeApp,
		PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
		MutationRevision: 1,
	}}
	credential := &scopedCredentialStoreStub{
		credential: controlstate.PublicURLPublishCredential{ID: "upc_1", PublicURLID: "public_url_1"},
		page: controlstate.PublicURLPublishCredentialPage{Credentials: []controlstate.PublicURLPublishCredentialSummary{
			{ID: "upc_1", PublicURLID: "public_url_1", PublicURL: "https://app.example", ExpiresAt: time.Now().Add(time.Hour)},
		}},
	}
	h := &handler{store: store, publishCredentials: credential, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	request := httptest.NewRequest(http.MethodGet, "/v1/publish-credentials?team_id=team_2", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.ListTeamPublicURLPublishCredentials(response, request, controlv1.ListTeamPublicURLPublishCredentialsParams{TeamId: "team_2"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("other team list = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/publish-credentials?team_id=team_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response = httptest.NewRecorder()
	h.ListTeamPublicURLPublishCredentials(response, request, controlv1.ListTeamPublicURLPublishCredentialsParams{TeamId: "team_1"})
	var page controlv1.PublicURLPublishCredentialPage
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Credentials) != 1 ||
		page.Credentials[0].PublicUrl == nil || *page.Credentials[0].PublicUrl != "https://app.example" || strings.Contains(response.Body.String(), "tnl_publish_") {
		t.Fatalf("team credential list = %d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/publish-credentials/upc_1?team_id=team_2", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response = httptest.NewRecorder()
	h.RevokePublishCredentialByID(response, request, "upc_1", controlv1.RevokePublishCredentialByIDParams{TeamId: "team_2"})
	if response.Code != http.StatusNotFound || credential.revocations != 0 {
		t.Fatalf("cross-team revoke = %d, calls = %d", response.Code, credential.revocations)
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/publish-credentials/upc_1?team_id=team_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response = httptest.NewRecorder()
	h.RevokePublishCredentialByID(response, request, "upc_1", controlv1.RevokePublishCredentialByIDParams{TeamId: "team_1"})
	var revoked controlv1.PublicURLPublishCredential
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &revoked) != nil || revoked.RevokedAt == nil || credential.revocations != 1 {
		t.Fatalf("revoke by ID = %d %s", response.Code, response.Body.String())
	}
}
