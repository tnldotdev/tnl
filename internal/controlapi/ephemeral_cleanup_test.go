package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

type ephemeralCleanupStoreStub struct {
	Store
	request controlstate.AuthorizedPublicURLDeleteRequest
}

func (s *ephemeralCleanupStoreStub) DeleteAuthorizedPublicURL(_ context.Context, request controlstate.AuthorizedPublicURLDeleteRequest, _ time.Time) error {
	s.request = request
	return nil
}

func TestEphemeralCleanupForwardsOnlyTheScopedCredential(t *testing.T) {
	token, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	store := &ephemeralCleanupStoreStub{}
	h := &handler{store: store, publishCredentials: &scopedCredentialStoreStub{credential: controlstate.PublicURLPublishCredential{
		ID: "upc_ephemeral", Kind: controlstate.PublishCredentialEphemeral,
		IdentityID: "identity_1", TeamID: "team_1",
	}}}
	request := httptest.NewRequest(http.MethodDelete, "/v1/ephemeral-public-urls/url_1", nil)
	request.Header.Set("Authorization", "Bearer "+token.String())
	response := httptest.NewRecorder()
	h.DeleteEphemeralPublicURL(response, request, "url_1")
	if response.Code != http.StatusNoContent || store.request.PublicURLID != "url_1" ||
		store.request.ActingIdentityID != "identity_1" || store.request.EphemeralCredential != token ||
		strings.Contains(response.Body.String(), token.String()) {
		t.Fatalf("ad-hoc cleanup returned status %d or failed to keep its credential scoped", response.Code)
	}
}
