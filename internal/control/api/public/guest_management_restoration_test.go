package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestGuestRestoredTrialCannotUpdateServicesOrManageFeedback(t *testing.T) {
	for _, operation := range []string{"configure", "feedback"} {
		t.Run(operation, func(t *testing.T) {
			human := &guestHumanAuthorizer{}
			h := &handler{guests: guestAPIStore(t), authorizer: human,
				dependencies: Stores{Services: &guestDeletionStore{}}}
			r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(
				`{"protocol":"http","publisher_pool":false,"expected_trust_revision":"1","configuration":{"target":"localhost:3000"}}`))
			r.Header.Set("Authorization", "Bearer guest-token")
			w := httptest.NewRecorder()
			if operation == "configure" {
				h.ConfigureService(w, r, "service")
			} else {
				h.ListFeedbackThreads(w, r, controlv1.ListFeedbackThreadsParams{})
			}
			if w.Code != http.StatusUnauthorized || human.reads != 1 {
				t.Fatal("guest trial became human service or feedback management authority", w.Code, human.reads)
			}
		})
	}
}
