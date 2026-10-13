package controlapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherRunIdentityStub struct {
	PublisherIdentityStore
	identity controlstate.PublisherIdentity
	public   ed25519.PublicKey
	plan     authorization.CertificatePlan
}

func (s publisherRunIdentityStub) AuthenticatePublisherAccess(context.Context, string, time.Time) (controlstate.PublisherIdentity, error) {
	return s.identity, nil
}

func (s publisherRunIdentityStub) PublisherMayStartRun(_ context.Context, _ controlstate.PublisherIdentity, publicURLID string) (bool, error) {
	return s.identity.Scope.PublicURLID == publicURLID, nil
}

func (s publisherRunIdentityStub) PublisherKeyForAccess(context.Context, controlstate.PublisherIdentity) (ed25519.PublicKey, error) {
	return s.public, nil
}

func (s publisherRunIdentityStub) PublisherRunPlan(context.Context, controlstate.PublisherIdentity, controlstate.PublicURL, bool) (authorization.CertificatePlan, error) {
	return s.plan, nil
}

func TestPublisherRunUsesBoundGrantProofAndCurrentRouteState(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const urlID = "public_url_1"
	const idempotency = "session-idempotency"
	proof, err := publisheridentity.SignRun(private, urlID, idempotency)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := publisheridentity.VerifyRun(public, proof, urlID, idempotency)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Date(2026, 9, 5, 12, 2, 0, 0, time.UTC)
	updatedAt := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	store := &publicURLMutationStoreStub{
		route: controlstate.PublicURL{
			ID: urlID, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "api.member.example", Target: "http://127.0.0.1:3000",
			PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
			MutationRevision: 4, AuthorizationPublishRunNumber: 7, PolicyRevision: 9,
		},
		postSessionPublicURL: &controlstate.PublicURL{
			ID: urlID, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
			CanonicalHostname: "api.member.example", Target: "http://127.0.0.1:3000",
			PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
			NextPublishRunNumber: 8, MutationRevision: 5, ExpiresAt: &expiresAt,
			OpenPublishRunID: "session_1", UpdatedAt: updatedAt,
		},
		sessionSetup: controlstate.PublishRunSetup{PublishRunID: "session_1", PublicURLID: urlID,
			TeamID: "team_1", MembershipID: "membership_1", PublishRunNumber: 7, PolicyRevision: 9,
			PublishRunToken: credentials.PublishRunToken("session-token"), State: controlstate.PublishRunStarting},
	}
	identity := publisherRunIdentityStub{identity: controlstate.PublisherIdentity{
		ID: "pub_owner", GrantID: "pgr_saved", CreatorID: "identity_1",
		Scope: controlstate.PublisherScope{Kind: "saved_url", TeamID: "team_1", PublicURLID: urlID},
	}, public: public, plan: authorization.CertificatePlan{CacheKey: "member.example", Scope: "member.example",
		Identifiers: []string{"*.member.example"}, ChallengeMethod: certificateidentity.ChallengeDNS01}}
	h := &handler{config: Config{DNSAutomation: true}, store: store, publisherIdentities: &identity}
	call := func(connections int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/"+urlID+"/publish-runs",
			strings.NewReader(fmt.Sprintf(`{"publisher_proof":%q,"traffic":{"connections":%d}}`, proof, connections)))
		request.Header.Set("Authorization", "Bearer pta_scoped")
		request.Header.Set("Idempotency-Key", idempotency)
		response := httptest.NewRecorder()
		h.CreatePublishRun(response, request, urlID, controlv1.CreatePublishRunParams{})
		return response
	}
	response := call(16)
	if response.Code != http.StatusCreated {
		t.Fatalf("run creation = %d %s", response.Code, response.Body.String())
	}
	var setup controlv1.PublishRunSetup
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.PublicUrl.OpenPublishRunId == nil || *setup.PublicUrl.OpenPublishRunId != "session_1" ||
		setup.PublicUrl.ExpiresAt == nil || !setup.PublicUrl.ExpiresAt.Equal(expiresAt) || !setup.PublicUrl.UpdatedAt.Equal(updatedAt) ||
		setup.PublicUrl.NextPublishRunNumber != 8 || store.authorizationReads != 2 ||
		store.sessionLookup != [2]string{urlID, idempotency} || store.sessionRequest.PublisherIdentityID != identity.identity.ID ||
		store.sessionRequest.PublisherGrantID != identity.identity.GrantID || !bytes.Equal(store.sessionRequest.RetrySecret, secret[:]) ||
		store.sessionRequest.ExpectedMutationRevision != 4 || store.sessionRequest.PolicyRevision != 9 {
		t.Fatalf("run setup = %+v, request = %+v", setup, store.sessionRequest)
	}
	if chosen := store.sessionRequest.Traffic; chosen == nil || chosen.Connections != 16 {
		t.Fatalf("publisher traffic limit = %+v", chosen)
	}
	firstDigest := store.sessionRequest.RequestDigest
	if response := call(17); response.Code != http.StatusCreated || firstDigest == store.sessionRequest.RequestDigest {
		t.Fatalf("changed traffic did not change run digest: %d", response.Code)
	}
	if response := call(129); response.Code != http.StatusBadRequest || store.sessions != 2 {
		t.Fatalf("above-ceiling traffic reached store: %d, writes=%d", response.Code, store.sessions)
	}
}

func TestPublisherRunRejectsOutOfGrantURLsBeforeReadingState(t *testing.T) {
	store := &publicURLMutationStoreStub{}
	identity := &publisherRunIdentityStub{identity: controlstate.PublisherIdentity{ID: "pub_owner",
		Scope: controlstate.PublisherScope{Kind: "saved_url", TeamID: "team_1", PublicURLID: "url_allowed"}}}
	h := &handler{store: store, publisherIdentities: identity}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/url_other/publish-runs", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer pta_scoped")
	response := httptest.NewRecorder()
	h.CreatePublishRun(response, request, "url_other", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusNotFound || store.authorizationReads != 0 {
		t.Fatalf("out-of-grant URL lookup = %d, reads=%d", response.Code, store.authorizationReads)
	}
}

func TestPublisherRunRejectsUnavailableDNSPlan(t *testing.T) {
	store := &publicURLMutationStoreStub{route: controlstate.PublicURL{ID: "url_allowed", TeamID: "team_1"}}
	identity := &publisherRunIdentityStub{identity: controlstate.PublisherIdentity{
		ID: "pub_owner", GrantID: "pgr_saved", CreatorID: "identity_1",
		Scope: controlstate.PublisherScope{Kind: "saved_url", TeamID: "team_1", PublicURLID: "url_allowed"},
	}, plan: authorization.CertificatePlan{ChallengeMethod: certificateidentity.ChallengeDNS01}}
	h := &handler{store: store, publisherIdentities: identity}
	request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/url_allowed/publish-runs", strings.NewReader(`{}`))
	request.Header.Set("Authorization", "Bearer pta_scoped")
	response := httptest.NewRecorder()
	h.CreatePublishRun(response, request, "url_allowed", controlv1.CreatePublishRunParams{})
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "requires DNS automation") {
		t.Fatalf("unavailable DNS plan = %d: %s", response.Code, response.Body.String())
	}
}
