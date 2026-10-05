package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type selectiveShareAuthorizer struct {
	principal publicURLReadPrincipal
	requests  []authorization.Request
}

func (a *selectiveShareAuthorizer) AuthorizePublicURLReads(_ context.Context, _ string) (publicURLReadPrincipal, error) {
	return a.principal, nil
}

func (a *selectiveShareAuthorizer) Authorize(_ context.Context, request authorization.Request) (authorization.Decision, error) {
	a.requests = append(a.requests, request)
	if request.PublicURLID == "url_2" {
		return authorization.Decision{}, authorization.ErrForbidden
	}
	return authorization.Decision{IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 7}, nil
}

type shareRoutesStub struct {
	PublicURLStore
}

func (*shareRoutesStub) GetPublicURLForAuthorization(_ context.Context, id string) (controlstate.PublicURL, error) {
	return controlstate.PublicURL{
		ID: id, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "web.example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, MutationRevision: 3,
		LifecycleState: controlstate.PublicURLLifecycleEnabled,
	}, nil
}

type shareStoreStub struct {
	created controlstate.CreateShareRequest
	share   controlstate.Share
}

func (s *shareStoreStub) CreateShare(_ context.Context, request controlstate.CreateShareRequest, now time.Time) (controlstate.Share, error) {
	s.created = request
	s.share = controlstate.Share{
		ID: "shr_example", PreviewID: request.PreviewID, TeamID: request.TeamID,
		CreatedByIdentityID: request.ActingIdentityID, PublicURLIDs: []string{request.PublicURLs[0].PublicURLID},
		CreatedAt: now, ExpiresAt: request.ExpiresAt,
	}
	return s.share, nil
}

func (s *shareStoreStub) GetShare(_ context.Context, _ string) (controlstate.Share, error) {
	return s.share, nil
}

func (s *shareStoreStub) ListShares(_ context.Context, _, _ string) (controlstate.SharePage, error) {
	return controlstate.SharePage{Shares: []controlstate.Share{s.share}}, nil
}

func (s *shareStoreStub) ListTeamShares(_ context.Context, teamID, identityID, _ string) (controlstate.SharePage, error) {
	if teamID != s.share.TeamID || identityID != s.share.CreatedByIdentityID {
		return controlstate.SharePage{}, nil
	}
	return controlstate.SharePage{Shares: []controlstate.Share{s.share}}, nil
}

func (s *shareStoreStub) RevokeShare(_ context.Context, _, _ string, now time.Time) (controlstate.Share, error) {
	s.share.RevokedAt = &now
	return s.share, nil
}

func TestShareCreateAuthorizesEachIncludedURLAndHidesSecretFingerprint(t *testing.T) {
	preview := &previewStoreStub{preview: controlstate.Preview{
		ID: "pv_preview", TeamID: "team_1", CreatedByIdentityID: "identity_1", PublicURLIDs: []string{"url_1"},
	}}
	routes := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "web.example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, MutationRevision: 3,
		LifecycleState: controlstate.PublicURLLifecycleEnabled,
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 7,
		PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "web.example.test", PublicURLScope: authorization.PublicURLScopeMember,
	}}
	shares := &shareStoreStub{}
	h := &handler{store: routes, previews: preview, shares: shares, authorizer: authorizer}
	secretSum := sha256.Sum256([]byte("preview-secret"))
	secret := hex.EncodeToString(secretSum[:])
	create := func(ids string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/previews/pv_preview/shares", strings.NewReader(fmt.Sprintf(`{"public_url_ids":%s,"expires_at":"%s","secret_fingerprint":"%s"}`, ids, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339), secret)))
		request.Header.Set("Authorization", "Bearer access-token")
		request.Header.Set("Idempotency-Key", "first-share")
		response := httptest.NewRecorder()
		h.CreateShare(response, request, "pv_preview", controlv1.CreateShareParams{})
		return response
	}
	if response := create(`["url_other"]`); response.Code != http.StatusBadRequest || len(authorizer.requests) != 0 {
		t.Fatalf("URL outside group = %d %s, authorized=%v", response.Code, response.Body.String(), authorizer.requests)
	}
	response := create(`["url_1"]`)
	if response.Code != http.StatusCreated || shares.created.PreviewID != "pv_preview" ||
		shares.created.ActingIdentityID != "identity_1" || shares.created.PublicURLs[0].ExpectedMutationRevision != 3 ||
		len(authorizer.requests) != 1 || authorizer.requests[0].Operation != authorization.OperationPublicURLUpdate ||
		strings.Contains(response.Body.String(), "fingerprint") || strings.Contains(response.Body.String(), secret) {
		t.Fatalf("share creation = %d %s, request=%+v, authorization=%v", response.Code, response.Body.String(), shares.created, authorizer.requests)
	}
	read := httptest.NewRequest(http.MethodGet, "/v1/shares/shr_example", nil)
	read.Header.Set("Authorization", "Bearer access-token")
	list := httptest.NewRecorder()
	h.ListShares(list, read, "pv_preview", controlv1.ListSharesParams{})
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"id":"shr_example"`) {
		t.Fatalf("share list = %d %s", list.Code, list.Body.String())
	}
	teamRequest := httptest.NewRequest(http.MethodGet, "/v1/shares?team_id=team_1", nil)
	teamRequest.Header.Set("Authorization", "Bearer access-token")
	teamList := httptest.NewRecorder()
	h.ListTeamShares(teamList, teamRequest, controlv1.ListTeamSharesParams{})
	if teamList.Code != http.StatusOK || !strings.Contains(teamList.Body.String(), `"id":"shr_example"`) {
		t.Fatalf("team share list = %d %s", teamList.Code, teamList.Body.String())
	}
	otherRequest := httptest.NewRequest(http.MethodGet, "/v1/shares?team_id=team_other", nil)
	otherRequest.Header.Set("Authorization", "Bearer access-token")
	otherList := httptest.NewRecorder()
	h.ListTeamShares(otherList, otherRequest, controlv1.ListTeamSharesParams{})
	if otherList.Code != http.StatusNotFound {
		t.Fatalf("other team shares were listed: %d %s", otherList.Code, otherList.Body.String())
	}
	preview.preview.CreatedByIdentityID = "different-identity"
	denied := httptest.NewRecorder()
	h.RevokeShare(denied, read, "shr_example")
	if denied.Code != http.StatusNotFound || shares.share.RevokedAt != nil {
		t.Fatalf("other identity revoked a share: %d %s", denied.Code, denied.Body.String())
	}
	preview.preview.CreatedByIdentityID = "identity_1"
	revoked := httptest.NewRecorder()
	h.RevokeShare(revoked, read, "shr_example")
	if revoked.Code != http.StatusOK || shares.share.RevokedAt == nil ||
		!strings.Contains(revoked.Body.String(), `"revoked_at"`) || strings.Contains(revoked.Body.String(), "fingerprint") {
		t.Fatalf("revoke = %d %s", revoked.Code, revoked.Body.String())
	}
}

func TestShareCreationDoesNotStorePartiallyAuthorizedSnapshot(t *testing.T) {
	preview := &previewStoreStub{preview: controlstate.Preview{
		ID: "pv_preview", TeamID: "team_1", CreatedByIdentityID: "identity_1", PublicURLIDs: []string{"url_1", "url_2"},
	}}
	authorizer := &selectiveShareAuthorizer{principal: testPublicURLReadPrincipal()}
	shares := &shareStoreStub{}
	h := &handler{store: &shareRoutesStub{}, previews: preview, shares: shares, authorizer: authorizer}
	secretSum := sha256.Sum256([]byte("preview-secret"))
	body := fmt.Sprintf(`{"public_url_ids":["url_1","url_2"],"expires_at":"%s","secret_fingerprint":"%s"}`, time.Now().UTC().Add(24*time.Hour).Format(time.RFC3339), hex.EncodeToString(secretSum[:]))
	request := httptest.NewRequest(http.MethodPost, "/v1/previews/pv_preview/shares", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Idempotency-Key", "two-services")
	response := httptest.NewRecorder()
	h.CreateShare(response, request, "pv_preview", controlv1.CreateShareParams{})
	if response.Code != http.StatusForbidden || len(authorizer.requests) != 2 ||
		authorizer.requests[0].PublicURLID != "url_1" || authorizer.requests[1].PublicURLID != "url_2" || shares.created.PreviewID != "" {
		t.Fatalf("partial authorization = %d %s, requests=%+v, stored=%+v", response.Code, response.Body.String(), authorizer.requests, shares.created)
	}
}
