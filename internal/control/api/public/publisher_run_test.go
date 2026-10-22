package public

import (
	"net/http"
	"net/http/httptest"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherRunRejectsSessionAndOutOfScopeBeforeLookup(t *testing.T) {
	for _, token := range []string{"", "control-session-access", "pta_revoked"} {
		s := &publicURLMutationStoreStub{}
		r := httptest.NewRequest(http.MethodPost, "/v1/public-urls/sensitive/publish-runs", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		(&handler{store: s}).CreatePublishRun(w, r, "sensitive", controlv1.CreatePublishRunParams{})
		if w.Code != 401 || s.authorizationReads != 0 || s.sessions != 0 {
			t.Fatalf("unregistered publisher reached lookup: %d", w.Code)
		}
	}
	s := &publicURLMutationStoreStub{publicURL: controlstate.PublicURL{TeamID: "team"}, publisher: &controlstate.PublisherIdentity{Scope: controlstate.PublisherScope{TeamID: "team", Kind: "saved_public_url", PublicURLID: "authorized"}}}
	r := httptest.NewRequest(http.MethodPost, "/v1/public-urls/sensitive/publish-runs", nil)
	r.Header.Set("Authorization", "Bearer publisher-access")
	w := httptest.NewRecorder()
	(&handler{store: s}).CreatePublishRun(w, r, "sensitive", controlv1.CreatePublishRunParams{})
	if w.Code != 404 || s.authorizationReads != 0 || s.sessions != 0 {
		t.Fatal("out-of-scope publisher probed URL state")
	}
}
