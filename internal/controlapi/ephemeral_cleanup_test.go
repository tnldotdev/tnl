package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type ephemeralCleanupStoreStub struct {
	Store
	request controlstate.AuthorizedPublicURLDeleteRequest
}

func (s *ephemeralCleanupStoreStub) DeleteAuthorizedPublicURL(_ context.Context, request controlstate.AuthorizedPublicURLDeleteRequest, _ time.Time) error {
	s.request = request
	return nil
}

func TestEphemeralCleanupUsesOnlyItsNamespaceGrant(t *testing.T) {
	store := &ephemeralCleanupStoreStub{}
	h := &handler{store: store, publisherIdentities: &namespacePublisherStub{identity: controlstate.PublisherIdentity{
		ID: "pub_1", GrantID: "pgr_1", CreatorID: "identity_1",
		Scope: controlstate.PublisherScope{TeamID: "team_1", Kind: "namespace", DomainID: "domain_1", Namespace: "member.example.test"},
	}}}
	request := httptest.NewRequest(http.MethodDelete, "/v1/ephemeral-public-urls/url_1", nil)
	request.Header.Set("Authorization", "Bearer pta_scoped")
	response := httptest.NewRecorder()
	h.DeleteEphemeralPublicURL(response, request, "url_1")
	if response.Code != http.StatusNoContent || store.request.PublicURLID != "url_1" ||
		store.request.ActingIdentityID != "identity_1" || store.request.PublisherIdentityID != "pub_1" ||
		store.request.PublisherGrantID != "pgr_1" {
		t.Fatalf("ad-hoc cleanup returned status %d or lost its grant scope", response.Code)
	}
}
