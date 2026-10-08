package authorityapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/problemtype"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestInvitationCreationCanonicalRequestAndSecret(t *testing.T) {
	expires := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	wantDigest := sha256.Sum256([]byte(`{"member_slug":"new-member","initial_role":"admin","expires_at":"2026-09-18T12:00:00Z","email_restriction":"user@example.test"}`))
	for _, test := range []struct{ name, body string }{
		{"UTC", `{"member_slug":"new-member","initial_role":"admin","expires_at":"2026-09-18T12:00:00Z","email_restriction":"user@example.test"}`},
		{"equivalent email and timezone", `{"email_restriction":"  USER@EXAMPLE.TEST  ","expires_at":"2026-09-18T08:00:00-04:00","initial_role":"admin","member_slug":"new-member"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &invitationCreationStore{authorityAuthenticationStub: newAuthorityAuthenticationStub()}
			store.result = controlstate.InvitationSecret{Secret: "invitation-secret", Invitation: controlstate.Invitation{
				ID: "invitation_result", TeamID: "team_path", MemberSlug: "new-member", InitialRole: "admin", State: "pending",
				ExpiresAt: expires, NormalizedEmailRestriction: "user@example.test",
			}}
			response := serveAuthorityMutation(testHandler(t, Config{LoginToken: testLoginToken}, store), http.MethodPost, "/v1/teams/team_path/invitations", test.body, "Bearer exact-access-token", "invitation-idempotency")
			if response.Code != http.StatusCreated {
				t.Fatalf("response = %d: %s", response.Code, response.Body.String())
			}
			assertAuthorityAuthentication(t, store.authorityAuthenticationStub)
			if store.calls != 1 {
				t.Fatalf("create calls = %d", store.calls)
			}
			got := store.request
			if got.IdentityID != "identity_actor" || got.TeamID != "team_path" || got.IdempotencyKey != "invitation-idempotency" ||
				got.RequestDigest != wantDigest || got.MemberSlug != "new-member" || got.InitialRole != "admin" ||
				!got.ExpiresAt.Equal(expires) || got.EmailRestriction != "user@example.test" || !reflect.DeepEqual(got.RetrySecret, store.principal.RetrySecret[:]) {
				t.Fatalf("invitation request = %#v", got)
			}
			var body authorityv1.InvitationSecret
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Secret != "invitation-secret" || body.Invitation.Id != "invitation_result" || body.Invitation.TeamId != "team_path" ||
				body.Invitation.MemberSlug != "new-member" || body.Invitation.InitialRole != authorityv1.TeamRoleAdmin ||
				!body.Invitation.ExpiresAt.Equal(expires) || body.Invitation.NormalizedEmailRestriction == nil || string(*body.Invitation.NormalizedEmailRestriction) != "user@example.test" {
				t.Fatalf("invitation response = %#v", body)
			}
		})
	}
}

func TestDomainClaimCanonicalDefaultAndIdempotency(t *testing.T) {
	for _, test := range []struct {
		name, body, canonical string
		makeDefault           bool
	}{
		{"omitted default", `{"domain":"claim.example.test"}`, `{"domain":"claim.example.test","make_default":false}`, false},
		{"explicit false", `{"make_default":false,"domain":"claim.example.test"}`, `{"domain":"claim.example.test","make_default":false}`, false},
		{"make default", `{"domain":"claim.example.test","make_default":true}`, `{"domain":"claim.example.test","make_default":true}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &domainClaimStore{authorityAuthenticationStub: newAuthorityAuthenticationStub(), result: controlstate.Domain{
				ID: "domain_result", TeamID: "team_path", Kind: "claimed", CanonicalDomain: "claim.example.test", State: "pending", AuthorityRevision: 8,
				RequiredRecords: []controlstate.DNSRecord{{Name: "claim.example.test", Type: "NS", Value: "ns.example.test"}},
			}}
			response := serveAuthorityMutation(testHandler(t, Config{DNSAutomation: true, CustomDomainsEnabled: true, LoginToken: testLoginToken}, store), http.MethodPost, "/v1/teams/team_path/domains", test.body, "Bearer exact-access-token", "domain-idempotency")
			if response.Code != http.StatusCreated {
				t.Fatalf("response = %d: %s", response.Code, response.Body.String())
			}
			assertAuthorityAuthentication(t, store.authorityAuthenticationStub)
			want := controlstate.ClaimDomainRequest{IdentityID: "identity_actor", TeamID: "team_path", IdempotencyKey: "domain-idempotency",
				RequestDigest: sha256.Sum256([]byte(test.canonical)), Domain: "claim.example.test", MakeDefault: test.makeDefault}
			if store.calls != 1 || !reflect.DeepEqual(store.request, want) {
				t.Fatalf("claim = %#v, want %#v", store.request, want)
			}
			var body authorityv1.Domain
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Id != "domain_result" || body.TeamId == nil || *body.TeamId != "team_path" || body.CanonicalDomain != "claim.example.test" ||
				body.AuthorityRevision != 8 || len(body.RequiredRecords) != 1 || body.RequiredRecords[0].Value != "ns.example.test" {
				t.Fatalf("domain response = %#v", body)
			}
		})
	}
}

func TestAuthorityResourceMutationsUseActorAndPath(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body     string
		want                         resourceMutation
		status                       int
		responseField, responseValue string
	}{
		{"membership role", http.MethodPatch, "/v1/teams/team_path/memberships/member_path", `{"role":"admin"}`, resourceMutation{"role", "identity_actor", "team_path", "member_path", "admin"}, http.StatusOK, "id", "membership_result"},
		{"membership removal", http.MethodDelete, "/v1/teams/team_path/memberships/member_path", "", resourceMutation{"remove", "identity_actor", "team_path", "member_path", ""}, http.StatusNoContent, "", ""},
		{"invitation revoke", http.MethodDelete, "/v1/teams/team_path/invitations/invitation_path", "", resourceMutation{"revoke", "identity_actor", "team_path", "invitation_path", ""}, http.StatusNoContent, "", ""},
		{"invitation accept", http.MethodPost, "/v1/invitations/accept", `{"secret":"exact-invitation-token"}`, resourceMutation{"accept", "identity_actor", "", "", "exact-invitation-token"}, http.StatusOK, "id", "membership_result"},
		{"domain default", http.MethodPost, "/v1/teams/team_path/domains/domain_path/default", "", resourceMutation{"default", "identity_actor", "team_path", "domain_path", ""}, http.StatusOK, "default_domain_id", "domain_result"},
		{"domain release", http.MethodDelete, "/v1/teams/team_path/domains/domain_path", "", resourceMutation{"release", "identity_actor", "team_path", "domain_path", ""}, http.StatusNoContent, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &authorityResourceStore{authorityAuthenticationStub: newAuthorityAuthenticationStub()}
			response := serveAuthorityMutation(testHandler(t, Config{LoginToken: testLoginToken}, store), test.method, test.path, test.body, "Bearer exact-access-token", "")
			if response.Code != test.status {
				t.Fatalf("response = %d: %s, want %d", response.Code, response.Body.String(), test.status)
			}
			assertAuthorityAuthentication(t, store.authorityAuthenticationStub)
			if !reflect.DeepEqual(store.mutations, []resourceMutation{test.want}) {
				t.Fatalf("mutations = %#v", store.mutations)
			}
			if test.responseField != "" {
				var body map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body[test.responseField] != test.responseValue {
					t.Fatalf("response = %#v", body)
				}
			}
		})
	}
}

func TestAuthorityMutationsRejectAuthenticationBeforeStoreMutation(t *testing.T) {
	for _, operation := range []struct{ name, method, path, body, key string }{
		{"invitation create", http.MethodPost, "/v1/teams/team_path/invitations", `{"member_slug":"member","initial_role":"member","expires_at":"2026-09-18T12:00:00Z"}`, "invite"},
		{"invitation accept", http.MethodPost, "/v1/invitations/accept", `{"secret":"secret"}`, ""},
		{"invitation revoke", http.MethodDelete, "/v1/teams/team_path/invitations/invitation_path", "", ""},
		{"membership role", http.MethodPatch, "/v1/teams/team_path/memberships/member_path", `{"role":"admin"}`, ""},
		{"membership remove", http.MethodDelete, "/v1/teams/team_path/memberships/member_path", "", ""},
		{"domain claim", http.MethodPost, "/v1/teams/team_path/domains", `{"domain":"claim.example.test"}`, "claim"},
		{"domain default", http.MethodPost, "/v1/teams/team_path/domains/domain_path/default", "", ""},
		{"domain release", http.MethodDelete, "/v1/teams/team_path/domains/domain_path", "", ""},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, auth := range []struct {
				name, header string
				calls        int
			}{{"missing", "", 0}, {"malformed", "Basic token", 0}, {"rejected", "Bearer exact-access-token", 1}} {
				t.Run(auth.name, func(t *testing.T) {
					store := &rejectedMutationStore{authorityResourceStore: &authorityResourceStore{authorityAuthenticationStub: newAuthorityAuthenticationStub()}}
					store.err = controlstate.ErrControlAuthentication
					response := serveAuthorityMutation(testHandler(t, Config{DNSAutomation: true, CustomDomainsEnabled: true, LoginToken: testLoginToken}, store), operation.method, operation.path, operation.body, auth.header, operation.key)
					if response.Code != http.StatusUnauthorized || len(store.tokens) != auth.calls || len(store.mutations) != 0 {
						t.Fatalf("response = %d: %s; authentications %v, mutations %#v", response.Code, response.Body.String(), store.tokens, store.mutations)
					}
					if auth.calls != 0 {
						assertAuthorityAuthentication(t, store.authorityAuthenticationStub)
					}
				})
			}
		})
	}
}

func serveAuthorityMutation(h http.Handler, method, path, body, authorization, key string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", authorization)
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

type authorityAuthenticationStub struct {
	Store
	principal controlstate.ControlPrincipal
	err       error
	tokens    []credentials.AccessToken
	revisions []int64
}

func newAuthorityAuthenticationStub() *authorityAuthenticationStub {
	return &authorityAuthenticationStub{principal: controlstate.ControlPrincipal{IdentityID: "identity_actor", RetrySecret: [32]byte{1, 7, 9}}}
}

func (s *authorityAuthenticationStub) AuthenticateAccessToken(_ context.Context, token credentials.AccessToken, revision int64, _ time.Time) (controlstate.ControlPrincipal, error) {
	s.tokens, s.revisions = append(s.tokens, token), append(s.revisions, revision)
	return s.principal, s.err
}

func assertAuthorityAuthentication(t *testing.T, s *authorityAuthenticationStub) {
	t.Helper()
	verifier, err := credentials.ParseLoginToken(credentials.LoginToken(testLoginToken))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.tokens, []credentials.AccessToken{"exact-access-token"}) || !reflect.DeepEqual(s.revisions, []int64{verifier.SourceRevision()}) {
		t.Fatalf("authentication tokens = %v, revisions = %v", s.tokens, s.revisions)
	}
}

type invitationCreationStore struct {
	*authorityAuthenticationStub
	request controlstate.CreateInvitationRequest
	result  controlstate.InvitationSecret
	calls   int
}

func (s *invitationCreationStore) CreateTeamInvitation(_ context.Context, request controlstate.CreateInvitationRequest, _ time.Time) (controlstate.InvitationSecret, error) {
	s.request, s.calls = request, s.calls+1
	return s.result, nil
}

type domainClaimStore struct {
	*authorityAuthenticationStub
	request controlstate.ClaimDomainRequest
	result  controlstate.Domain
	calls   int
}

func (s *domainClaimStore) ClaimTeamDomain(_ context.Context, request controlstate.ClaimDomainRequest, _ time.Time) (controlstate.Domain, error) {
	s.request, s.calls = request, s.calls+1
	return s.result, nil
}

type resourceMutation struct{ operation, actor, team, resource, value string }
type authorityResourceStore struct {
	*authorityAuthenticationStub
	mutations   []resourceMutation
	mutationErr error
}

func (s *authorityResourceStore) SetMembershipRole(_ context.Context, actor, team, member string, role controlstate.TeamRole, _ time.Time) (controlstate.Membership, error) {
	s.mutations = append(s.mutations, resourceMutation{"role", actor, team, member, string(role)})
	return controlstate.Membership{ID: "membership_result", Role: "admin"}, s.mutationErr
}
func (s *authorityResourceStore) RemoveMembership(_ context.Context, actor, team, member string, _ time.Time) error {
	s.mutations = append(s.mutations, resourceMutation{"remove", actor, team, member, ""})
	return s.mutationErr
}
func (s *authorityResourceStore) RevokeTeamInvitation(_ context.Context, actor, team, invitation string, _ time.Time) error {
	s.mutations = append(s.mutations, resourceMutation{"revoke", actor, team, invitation, ""})
	return s.mutationErr
}
func (s *authorityResourceStore) AcceptInvitation(_ context.Context, actor string, token credentials.InvitationToken, _ time.Time) (controlstate.Membership, error) {
	s.mutations = append(s.mutations, resourceMutation{"accept", actor, "", "", string(token)})
	return controlstate.Membership{ID: "membership_result"}, s.mutationErr
}
func (s *authorityResourceStore) SetTeamDefaultDomain(_ context.Context, actor, team, domain string, _ time.Time) (controlstate.Team, error) {
	s.mutations = append(s.mutations, resourceMutation{"default", actor, team, domain, ""})
	return controlstate.Team{DefaultDomainID: "domain_result"}, s.mutationErr
}
func (s *authorityResourceStore) ReleaseTeamDomain(_ context.Context, actor, team, domain string, _ time.Time) error {
	s.mutations = append(s.mutations, resourceMutation{"release", actor, team, domain, ""})
	return s.mutationErr
}

type rejectedMutationStore struct{ *authorityResourceStore }

func (s *rejectedMutationStore) CreateTeamInvitation(_ context.Context, request controlstate.CreateInvitationRequest, _ time.Time) (controlstate.InvitationSecret, error) {
	s.mutations = append(s.mutations, resourceMutation{operation: "invite", actor: request.IdentityID, team: request.TeamID})
	return controlstate.InvitationSecret{}, nil
}
func (s *rejectedMutationStore) ClaimTeamDomain(_ context.Context, request controlstate.ClaimDomainRequest, _ time.Time) (controlstate.Domain, error) {
	s.mutations = append(s.mutations, resourceMutation{operation: "claim", actor: request.IdentityID, team: request.TeamID})
	return controlstate.Domain{}, nil
}

func TestAuthorityResourceMutationProblems(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
		err                      error
		status                   int
		code                     authorityv1.ProblemCode
	}{
		{"role forbidden", http.MethodPatch, "/v1/teams/team_path/memberships/member_path", `{"role":"admin"}`, controlstate.ErrAuthorityAccess, http.StatusForbidden, authorityv1.Forbidden},
		{"last owner removal", http.MethodDelete, "/v1/teams/team_path/memberships/member_path", "", controlstate.ErrAuthorityConflict, http.StatusConflict, authorityv1.Conflict},
		{"invitation missing", http.MethodDelete, "/v1/teams/team_path/invitations/invitation_path", "", controlstate.ErrInvitationNotFound, http.StatusNotFound, authorityv1.NotFound},
		{"invitation invalid", http.MethodPost, "/v1/invitations/accept", `{"secret":"exact-invitation-token"}`, controlstate.ErrAuthorityInvalid, http.StatusBadRequest, authorityv1.InvalidRequest},
		{"default domain missing", http.MethodPost, "/v1/teams/team_path/domains/domain_path/default", "", controlstate.ErrDomainNotFound, http.StatusNotFound, authorityv1.NotFound},
		{"release forbidden", http.MethodDelete, "/v1/teams/team_path/domains/domain_path", "", controlstate.ErrAuthorityAccess, http.StatusForbidden, authorityv1.Forbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &authorityResourceStore{authorityAuthenticationStub: newAuthorityAuthenticationStub(), mutationErr: test.err}
			response := serveAuthorityMutation(testHandler(t, Config{}, store), test.method, test.path, test.body, "Bearer exact-access-token", "")
			var problem authorityv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != test.status || problem.Status != test.status || problem.Code != test.code || problem.Type != problemtype.URL(string(test.code)) ||
				len(store.mutations) != 1 || strings.Contains(response.Body.String(), "exact-invitation-token") {
				t.Fatalf("response = %d: %s; calls %#v", response.Code, response.Body.String(), store.mutations)
			}
		})
	}
}
