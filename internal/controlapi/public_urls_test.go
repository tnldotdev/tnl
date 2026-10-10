package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestListRoutesUsesCurrentRouteReadAuthorization(t *testing.T) {
	store := &publicURLMutationStoreStub{page: controlstate.PublicURLPage{PublicURLs: []controlstate.PublicURL{{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
	}}}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal()}
	h := &handler{store: store, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodGet, "/v1/public-urls?team_id=team_1&cursor=public_url_0", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.ListPublicURLs(response, request, controlv1.ListPublicURLsParams{})
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if store.listTeamID != "team_1" || store.listCursor != "public_url_0" {
		t.Fatalf("list team = %q, cursor = %q", store.listTeamID, store.listCursor)
	}
	if !slices.Equal(authorizer.readTokens, []string{"access-token"}) || len(authorizer.requests) != 0 {
		t.Fatalf("authorization = %#v", authorizer)
	}
}

func TestGetRouteDoesNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{ID: "public_url_1", TeamID: "team_other"}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	request := httptest.NewRequest(http.MethodGet, "/v1/public-urls/public_url_1", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.GetPublicURL(response, request, "public_url_1")
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
		t.Fatalf("response = %d: %s", response.Code, response.Body.String())
	}
}

func TestUpdateRouteAuthorizesExactRouteAndCanonicalMutation(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember,
		PolicyRevision: 3, LifecycleState: controlstate.PublicURLLifecycleEnabled,
		AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MutationRevision: 4,
		Ephemeral: true,
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
		ActingRole: "owner", PublicURLMembershipID: "membership_1", PolicyRevision: 7,
		DomainID: "domain_1", CanonicalHostname: "demo.example", PublicURLScope: "member",
	}}
	h := &handler{store: store, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(`{
		"target":"http://127.0.0.1:4000",
		"allowed_ip_prefixes":["2001:db8::1/64","192.0.2.9/24"]
	}`))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.UpdatePublicURL(response, request, "public_url_1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	wantPrefixes := []string{"192.0.2.0/24", "2001:db8::/64"}
	if len(authorizer.requests) != 1 || !slices.Equal(authorizer.readTokens, []string{"access-token"}) || !slices.Equal(store.authorizationPublicURLIDs, []string{"public_url_1"}) {
		t.Fatalf("authorization calls = %#v; route lookups = %v", authorizer, store.authorizationPublicURLIDs)
	}
	authorized := authorizer.requests[0]
	if authorized.AccessToken != "access-token" || authorized.Operation != authorization.OperationPublicURLUpdate || authorized.PublicURLID != store.route.ID ||
		authorized.TeamID != store.route.TeamID || authorized.DomainID != store.route.DomainID ||
		authorized.PublicURLMembershipID != store.route.MembershipID || authorized.CanonicalHostname != store.route.CanonicalHostname ||
		authorized.PublicURLScope != authorization.PublicURLScope(store.route.PublicURLScope) || !authorized.Ephemeral ||
		authorized.PublicURLMutationRevision != store.route.MutationRevision ||
		authorized.Target != "http://127.0.0.1:4000" || !slices.Equal(authorized.AllowedIPPrefixes, wantPrefixes) {
		t.Fatalf("authorization request = %#v", authorized)
	}
	if store.update.PublicURLID != store.route.ID || store.update.TeamID != store.route.TeamID ||
		store.update.ActingIdentityID != "identity_1" || store.update.PolicyRevision != 7 ||
		store.update.ExpectedMutationRevision != store.route.MutationRevision ||
		store.update.Target != authorized.Target || !slices.Equal(store.update.AllowedIPPrefixes, wantPrefixes) {
		t.Fatalf("stored update = %#v", store.update)
	}
}

func TestUpdateRouteAcceptsLargeIPPolicyRequest(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
		PolicyRevision: 3, MutationRevision: 4,
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
		ActingRole: "owner", PublicURLMembershipID: "membership_1", PolicyRevision: 3,
		DomainID: "domain_1", CanonicalHostname: "demo.example", PublicURLScope: "member",
	}}
	prefixes := make([]string, 4096)
	for index := range prefixes {
		prefixes[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)}), 32).String()
	}
	body, err := json.Marshal(controlv1.UpdatePublicURLRequest{
		Target: "http://127.0.0.1:3000", AllowedIpPrefixes: prefixes,
	})
	if err != nil || len(body) <= 64<<10 {
		t.Fatalf("large policy request body = %d bytes, %v", len(body), err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	(&handler{store: store, authorizer: authorizer}).UpdatePublicURL(response, request, "public_url_1")
	if response.Code != http.StatusOK || len(store.update.AllowedIPPrefixes) != len(prefixes) || len(response.Body.Bytes()) <= 64<<10 {
		t.Fatalf("large policy update: status = %d, stored = %d, response = %d bytes", response.Code, len(store.update.AllowedIPPrefixes), len(response.Body.Bytes()))
	}
}

func TestUpdateRouteRequiresCompleteDesiredState(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"missing IP policy", `{"target":"http://127.0.0.1:4000"}`},
		{"missing target", `{"allowed_ip_prefixes":[]}`},
		{"null IP policy", `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":null}`},
		{"invalid target", `{"target":"https://127.0.0.1:4000/path","allowed_ip_prefixes":[]}`},
		{"duplicate canonical prefix", `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":["192.0.2.1/24","192.0.2.0/24"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &publicURLMutationStoreStub{}
			h := &handler{store: store}
			request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.UpdatePublicURL(response, request, "public_url_1")
			if response.Code != http.StatusBadRequest || store.authorizationReads != 0 {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsRequireBearerSyntaxBeforeLookup(t *testing.T) {
	for _, test := range publicURLMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &publicURLMutationStoreStub{}
			h := &handler{store: store}
			request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1", strings.NewReader(`{}`))
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsAuthenticateBeforeLookup(t *testing.T) {
	for _, test := range publicURLMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &publicURLMutationStoreStub{}
			authorizer := &recordingAuthorizer{readErr: authorization.ErrUnauthenticated}
			h := &handler{store: store, authorizer: authorizer}
			request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(`{
			"target":"http://127.0.0.1:4000",
			"allowed_ip_prefixes":[]
		}`))
			request.Header.Set("Authorization", "Bearer invalid-access-token")
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusUnauthorized || store.authorizationReads != 0 || len(authorizer.requests) != 0 || !slices.Equal(authorizer.readTokens, []string{"invalid-access-token"}) {
				t.Fatalf("response = %d, authorization reads = %d", response.Code, store.authorizationReads)
			}
		})
	}
}

func TestRouteMutationsDoNotRevealRoutesOutsideCurrentTeams(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_other", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, MutationRevision: 1,
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal()}
	h := &handler{store: store, authorizer: authorizer}
	calls := []struct {
		method string
		body   string
		call   func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPatch, `{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":[]}`, func(response http.ResponseWriter, request *http.Request) {
			h.UpdatePublicURL(response, request, "public_url_1")
		}},
		{http.MethodDelete, "", func(response http.ResponseWriter, request *http.Request) {
			h.DeletePublicURL(response, request, "public_url_1")
		}},
		{http.MethodPost, "", func(response http.ResponseWriter, request *http.Request) {
			h.CreatePublishRun(response, request, "public_url_1", controlv1.CreatePublishRunParams{})
		}},
	}
	for _, test := range calls {
		request := httptest.NewRequest(test.method, "/v1/public-urls/public_url_1", strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer access-token")
		response := httptest.NewRecorder()
		test.call(response, request)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
			t.Fatalf("%s response = %d: %s", test.method, response.Code, response.Body.String())
		}
	}
	if len(authorizer.requests) != 0 {
		t.Fatalf("mutation authorizations = %v", authorizer.requests)
	}
}

func TestUpdateRouteMapsOpenSessionConflict(t *testing.T) {
	response := httptest.NewRecorder()
	writeControlStateProblem(response, "update route", controlstate.ErrPublishRunOpen)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"publish_run_open"`) {
		t.Fatalf("response = %d: %s", response.Code, response.Body.String())
	}
}

func TestCreatePublishRunReturnsAuthoritativeRouteState(t *testing.T) {
	expiresAt := time.Date(2026, 9, 5, 12, 2, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := &publicURLMutationStoreStub{
		route: controlstate.PublicURL{
			ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
			PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
			MutationRevision: 4, AuthorizationPublishRunNumber: 7, Ephemeral: true,
		},
		postSessionPublicURL: &controlstate.PublicURL{
			ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000",
			PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
			NextPublishRunNumber: 8, MutationRevision: 5, Ephemeral: true, ExpiresAt: &expiresAt,
			OpenPublishRunID: "session_1", UpdatedAt: updatedAt,
		},
		sessionSetup: controlstate.PublishRunSetup{
			PublishRunID: "session_1", PublicURLID: "public_url_1", TeamID: "team_1", MembershipID: "membership_1",
			PublishRunNumber: 7, PolicyRevision: 9, PublishRunToken: credentials.PublishRunToken("session-token"),
			State: controlstate.PublishRunStarting,
		},
	}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1",
		ActingRole: "member", PublicURLMembershipID: "membership_1", PolicyRevision: 9,
		DomainID: "domain_1", CanonicalHostname: "demo.example", PublicURLScope: "member", RetrySecret: [32]byte{1, 2, 3},
		CertificatePlan: &authorization.CertificatePlan{
			CacheKey: "member.example", Scope: "member.example", Identifiers: []string{"member.example", "*.member.example"},
			ChallengeMethod: certificateidentity.ChallengeDNS01,
		},
	}}
	h := &handler{config: Config{DNSAutomation: true}, store: store, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-runs", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Idempotency-Key", "session-idempotency")
	response := httptest.NewRecorder()
	h.CreatePublishRun(response, request, "public_url_1", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var setup controlv1.PublishRunSetup
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.PublicUrl.OpenPublishRunId == nil || *setup.PublicUrl.OpenPublishRunId != "session_1" ||
		setup.PublicUrl.ExpiresAt == nil || !setup.PublicUrl.ExpiresAt.Equal(expiresAt) || !setup.PublicUrl.UpdatedAt.Equal(updatedAt) ||
		setup.PublicUrl.NextPublishRunNumber != 8 || store.authorizationReads != 2 {
		t.Fatalf("route = %#v, authorization reads = %d", setup.PublicUrl, store.authorizationReads)
	}
	if len(authorizer.requests) != 1 || authorizer.requests[0].AccessToken != "access-token" ||
		authorizer.requests[0].Operation != authorization.OperationPublishRunCreate || authorizer.requests[0].PublicURLID != "public_url_1" ||
		authorizer.requests[0].PublishRunNumber != 7 || authorizer.requests[0].PublicURLMutationRevision != 4 ||
		store.sessionLookup != [2]string{"public_url_1", "session-idempotency"} || store.sessionRequest.IdempotencyKey != "session-idempotency" ||
		store.sessionRequest.ExpectedMutationRevision != 4 || store.sessionRequest.ActingIdentityID != "identity_1" ||
		store.sessionRequest.PolicyRevision != 9 || !reflect.DeepEqual(store.sessionRequest.RetrySecret, authorizer.decision.RetrySecret[:]) ||
		store.sessionRequest.RequestDigest == ([32]byte{}) {
		t.Fatalf("session authorization = %#v, store = %#v", authorizer, store)
	}
}

func TestCreatePublishRunRejectsUnconfiguredDNSPlan(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{ID: "public_url_1", TeamID: "team_1"}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{CertificatePlan: &authorization.CertificatePlan{ChallengeMethod: "dns-01"}}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1/publish-runs", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.CreatePublishRun(response, request, "public_url_1", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "requires DNS-01 automation") {
		t.Fatalf("unsupported plan = %d: %s", response.Code, response.Body.String())
	}
}

func testPublicURLReadPrincipal() publicURLReadPrincipal {
	return publicURLReadPrincipal{identityID: "identity_1", teamIDs: map[string]struct{}{"team_1": {}}}
}

type publicURLMutationStoreStub struct {
	Store
	route                      controlstate.PublicURL
	postSessionPublicURL       *controlstate.PublicURL
	sessionSetup               controlstate.PublishRunSetup
	update                     controlstate.AuthorizedPublicURLUpdateRequest
	authorizationReads         int
	page                       controlstate.PublicURLPage
	listTeamID                 string
	listCursor                 string
	authorizationPublicURLIDs  []string
	sessionLookup              [2]string
	sessionRequest             controlstate.PublishRunRequest
	updates, sessions, deletes int
}

func (s *publicURLMutationStoreStub) GetPublicURLForFeedbackAuthorization(ctx context.Context, id string) (controlstate.PublicURL, error) {
	return s.GetPublicURLForAuthorization(ctx, id)
}

func (s *publicURLMutationStoreStub) ListAuthorizedPublicURLs(
	_ context.Context,
	teamID, cursor string,
) (controlstate.PublicURLPage, error) {
	s.listTeamID, s.listCursor = teamID, cursor
	return s.page, nil
}

func (s *publicURLMutationStoreStub) GetPublicURLForAuthorization(_ context.Context, publicURLID string) (controlstate.PublicURL, error) {
	s.authorizationReads++
	s.authorizationPublicURLIDs = append(s.authorizationPublicURLIDs, publicURLID)
	if s.postSessionPublicURL != nil {
		return *s.postSessionPublicURL, nil
	}
	return s.route, nil
}

func (s *publicURLMutationStoreStub) GetPublicURLForPublishRunAuthorization(_ context.Context, publicURLID, key string) (controlstate.PublicURL, error) {
	s.authorizationReads++
	s.sessionLookup = [2]string{publicURLID, key}
	return s.route, nil
}

func (s *publicURLMutationStoreStub) CreatePublishRun(
	_ context.Context,
	request controlstate.PublishRunRequest,
	_ time.Time,
	_ time.Duration,
	_ time.Duration,
) (controlstate.PublishRunSetup, error) {
	s.sessions++
	s.sessionRequest = request
	return s.sessionSetup, nil
}

func (s *publicURLMutationStoreStub) UpdateAuthorizedPublicURL(
	_ context.Context,
	request controlstate.AuthorizedPublicURLUpdateRequest,
	now time.Time,
) (controlstate.PublicURL, error) {
	s.update = request
	s.updates++
	s.route.Target = request.Target
	s.route.PolicyRevision = int64(request.PolicyRevision)
	s.route.AllowedIPPrefixes = make([]netip.Prefix, len(request.AllowedIPPrefixes))
	for index, value := range request.AllowedIPPrefixes {
		s.route.AllowedIPPrefixes[index] = netip.MustParsePrefix(value)
	}
	s.route.UpdatedAt = now
	return s.route, nil
}

func (s *publicURLMutationStoreStub) DeleteAuthorizedPublicURL(context.Context, controlstate.AuthorizedPublicURLDeleteRequest, time.Time) error {
	s.deletes++
	return nil
}

type recordingAuthorizer struct {
	principal            publicURLReadPrincipal
	decision             authorization.Decision
	readErr, mutationErr error
	readTokens           []string
	requests             []authorization.Request
}

func (a *recordingAuthorizer) Authorize(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	a.requests = append(a.requests, request)
	return a.decision, a.mutationErr
}

func (a *recordingAuthorizer) AuthorizePublicURLReads(_ context.Context, token string) (publicURLReadPrincipal, error) {
	a.readTokens = append(a.readTokens, token)
	return a.principal, a.readErr
}

type publicURLMutationCall struct {
	name string
	call func(*handler, http.ResponseWriter, *http.Request)
}

func publicURLMutationCalls() []publicURLMutationCall {
	return []publicURLMutationCall{
		{"update", func(h *handler, w http.ResponseWriter, r *http.Request) { h.UpdatePublicURL(w, r, "public_url_1") }},
		{"delete", func(h *handler, w http.ResponseWriter, r *http.Request) { h.DeletePublicURL(w, r, "public_url_1") }},
		{"session", func(h *handler, w http.ResponseWriter, r *http.Request) {
			h.CreatePublishRun(w, r, "public_url_1", controlv1.CreatePublishRunParams{})
		}},
	}
}

func TestRouteMutationRejectionDoesNotReachStore(t *testing.T) {
	for _, test := range publicURLMutationCalls() {
		t.Run(test.name, func(t *testing.T) {
			store := &publicURLMutationStoreStub{route: controlstate.PublicURL{ID: "public_url_1", TeamID: "team_1", MutationRevision: 7}}
			authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), mutationErr: authorization.ErrForbidden}
			h := &handler{store: store, authorizer: authorizer}
			request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/public_url_1", strings.NewReader(`{"target":"http://127.0.0.1:4000","allowed_ip_prefixes":[]}`))
			request.Header.Set("Authorization", "Bearer exact-access-token")
			response := httptest.NewRecorder()
			test.call(h, response, request)
			if response.Code != http.StatusForbidden || len(authorizer.requests) != 1 || authorizer.requests[0].AccessToken != "exact-access-token" ||
				store.authorizationReads != 1 || store.updates != 0 || store.deletes != 0 || store.sessions != 0 {
				t.Fatalf("response = %d: %s, authorizer = %#v, store = %#v", response.Code, response.Body.String(), authorizer, store)
			}
		})
	}
}

func TestCreateRouteCanonicalEquivalenceAndIdempotency(t *testing.T) {
	store := &publicURLCreationStore{result: controlstate.PublicURL{ID: "public_url_created", CanonicalHostname: "demo.example", Purpose: controlstate.PublicURLPurposeApp}}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "demo.example", PublicURLScope: "member", PolicyRevision: 9, DNSAuthorityReference: "dns_authority_1",
	}}
	h := &handler{store: store, authorizer: authorizer, config: Config{DNSAutomation: true}}
	for _, test := range []struct{ name, prefixes, target string }{
		{"unmasked unordered prefixes", `["2001:db8::1/64","192.0.2.9/24"]`, "http://127.0.0.1:3000"},
		{"canonical prefixes", `["192.0.2.0/24","2001:db8::/64"]`, "http://127.0.0.1:3000"},
		{"changed target", `["192.0.2.0/24","2001:db8::/64"]`, "http://127.0.0.1:4000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(`{"team_id":"team_1","membership_id":"membership_1","domain_id":"domain_1","canonical_hostname":"demo.example","public_url_scope":"member","purpose":"app","target":"`+test.target+`","allowed_ip_prefixes":`+test.prefixes+`,"ephemeral":true}`))
			request.Header.Set("Authorization", "Bearer exact-access-token")
			request.Header.Set("Idempotency-Key", "create-key")
			response := httptest.NewRecorder()
			h.CreatePublicURL(response, request, controlv1.CreatePublicURLParams{})
			if response.Code != http.StatusCreated {
				t.Fatalf("response = %d: %s", response.Code, response.Body.String())
			}
		})
	}
	if len(store.requests) != 3 || len(authorizer.requests) != 3 || len(authorizer.readTokens) != 0 {
		t.Fatalf("calls = %#v, %#v", store, authorizer)
	}
	want := controlstate.CreatePublicURLRequest{
		TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1", ActingIdentityID: "identity_1", IdempotencyKey: "create-key",
		CanonicalHostname: "demo.example", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp,
		AllowedIPPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"}, DNSState: controlstate.PublicURLDNSPending,
		DNSAuthorityReference: "dns_authority_1", PolicyRevision: 9, Ephemeral: true,
	}
	got := store.requests[0]
	got.RequestDigest = [32]byte{}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(store.requests[0], store.requests[1]) ||
		store.requests[0].RequestDigest == ([32]byte{}) || store.requests[0].RequestDigest == store.requests[2].RequestDigest {
		t.Fatalf("canonical requests = %#v", store.requests)
	}
	for _, request := range authorizer.requests {
		if request.AccessToken != "exact-access-token" || request.Operation != authorization.OperationPublicURLCreate || !slices.Equal(request.AllowedIPPrefixes, want.AllowedIPPrefixes) {
			t.Fatalf("authorization = %#v", request)
		}
	}
}

func TestCreateSavedAppPublicURLWithoutATarget(t *testing.T) {
	store := &publicURLCreationStore{result: controlstate.PublicURL{
		ID: "public_url_created", CanonicalHostname: "demo.example", Purpose: controlstate.PublicURLPurposeApp,
	}}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "demo.example", PublicURLScope: "member", PolicyRevision: 9,
	}}
	h := &handler{store: store, authorizer: authorizer}
	for _, test := range []struct {
		name, purpose, suffix string
		want                  int
	}{
		{"saved app", "app", "", http.StatusCreated},
		{"ephemeral app", "app", `,"ephemeral":true`, http.StatusBadRequest},
		{"saved demo", "demo", "", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"team_id":"team_1","membership_id":"membership_1","domain_id":"domain_1","canonical_hostname":"demo.example","public_url_scope":"member","target":"","purpose":"` + test.purpose + `"` + test.suffix + `}`
			request := httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer exact-access-token")
			request.Header.Set("Idempotency-Key", "create-key")
			response := httptest.NewRecorder()
			h.CreatePublicURL(response, request, controlv1.CreatePublicURLParams{})
			if response.Code != test.want {
				t.Fatalf("targetless create status = %d: %s", response.Code, response.Body.String())
			}
		})
	}
	if len(store.requests) != 1 || store.requests[0].Target != "" || len(authorizer.requests) != 1 {
		t.Fatalf("targetless creation = %#v, authorization = %#v", store.requests, authorizer.requests)
	}
}

func TestCreateDatabasePublicURLReturnsAssignedAddress(t *testing.T) {
	port := uint16(15432)
	store := &publicURLCreationStore{result: controlstate.PublicURL{
		ID: "url_created", CanonicalHostname: "orders.example", Purpose: controlstate.PublicURLPurposeApp,
		ServiceProtocol: controlstate.PublicURLServicePostgres, PublicPort: &port,
	}}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "orders.example", PublicURLScope: "member", PolicyRevision: 9,
	}}
	h := &handler{store: store, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(`{"team_id":"team_1","membership_id":"membership_1","domain_id":"domain_1","canonical_hostname":"orders.example","public_url_scope":"member","target":"","purpose":"app","service_protocol":"postgres"}`))
	request.Header.Set("Authorization", "Bearer exact-access-token")
	request.Header.Set("Idempotency-Key", "create-db")
	response := httptest.NewRecorder()
	h.CreatePublicURL(response, request, controlv1.CreatePublicURLParams{})
	if response.Code != http.StatusCreated || !strings.Contains(response.Body.String(), `"service_protocol":"postgres"`) ||
		!strings.Contains(response.Body.String(), `"public_port":15432`) || len(store.requests) != 1 ||
		store.requests[0].ServiceProtocol != controlstate.PublicURLServicePostgres || store.requests[0].Target != "" {
		t.Fatalf("database URL create = %d %s, requests=%#v", response.Code, response.Body.String(), store.requests)
	}
}

func TestTargetlessSavedAppPublicURLCanUpdateOnlyItsVisitorPolicy(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "public_url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "demo.example", PublicURLScope: controlstate.PublicURLScopeMember,
		Purpose: controlstate.PublicURLPurposeApp, MutationRevision: 4,
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", ActingMembershipID: "membership_1", PolicyRevision: 7,
		DomainID: "domain_1", CanonicalHostname: "demo.example", PublicURLScope: "member",
	}}
	request := httptest.NewRequest(http.MethodPatch, "/v1/public-urls/public_url_1", strings.NewReader(`{"target":"","allowed_ip_prefixes":[]}`))
	request.Header.Set("Authorization", "Bearer exact-access-token")
	response := httptest.NewRecorder()
	(&handler{store: store, authorizer: authorizer}).UpdatePublicURL(response, request, "public_url_1")
	if response.Code != http.StatusOK || store.updates != 1 || store.update.Target != "" {
		t.Fatalf("targetless policy update = %d: %s, store = %#v", response.Code, response.Body.String(), store)
	}
}

func TestCreateRouteRequiresPurpose(t *testing.T) {
	for _, purpose := range []string{"", "unknown", "stripe"} {
		body := `{"team_id":"team_1","domain_id":"domain_1","canonical_hostname":"demo.example","public_url_scope":"member","target":"http://127.0.0.1:3000","purpose":"` + purpose + `"}`
		response := httptest.NewRecorder()
		(&handler{}).CreatePublicURL(response, httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(body)), controlv1.CreatePublicURLParams{})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("purpose %q was accepted: %d", purpose, response.Code)
		}
	}
}

func TestCreateRouteAcceptsLargeIPPolicyRequest(t *testing.T) {
	store := &publicURLCreationStore{result: controlstate.PublicURL{ID: "public_url_created", CanonicalHostname: "demo.example", Purpose: controlstate.PublicURLPurposeApp}}
	authorizer := &recordingAuthorizer{decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PublicURLMembershipID: "membership_1",
		DomainID: "domain_1", CanonicalHostname: "demo.example", PublicURLScope: "member", PolicyRevision: 9,
	}}
	prefixes := make([]string, 4096)
	for index := range prefixes {
		prefixes[index] = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)}), 32).String()
	}
	body, err := json.Marshal(controlv1.CreatePublicURLRequest{
		TeamId: "team_1", DomainId: "domain_1", CanonicalHostname: "demo.example",
		PublicUrlScope: controlv1.Member, Purpose: controlv1.App, Target: "http://127.0.0.1:3000", AllowedIpPrefixes: &prefixes,
	})
	if err != nil || len(body) <= 64<<10 {
		t.Fatalf("large create request body = %d bytes, %v", len(body), err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	(&handler{store: store, authorizer: authorizer}).CreatePublicURL(response, request, controlv1.CreatePublicURLParams{})
	if response.Code != http.StatusCreated || len(store.requests) != 1 || len(store.requests[0].AllowedIPPrefixes) != len(prefixes) {
		t.Fatalf("large policy create: status = %d, stored = %d", response.Code, len(store.requests))
	}
}

type publicURLCreationStore struct {
	PublicURLStore
	result   controlstate.PublicURL
	requests []controlstate.CreatePublicURLRequest
}

func (s *publicURLCreationStore) CreatePublicURL(_ context.Context, request controlstate.CreatePublicURLRequest, _ time.Time) (controlstate.PublicURL, error) {
	s.requests = append(s.requests, request)
	return s.result, nil
}
