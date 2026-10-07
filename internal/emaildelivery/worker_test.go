package emaildelivery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type storeStub struct {
	job    controlstate.EmailDelivery
	status int
}

func (s *storeStub) ClaimInvitationEmail(context.Context, string, time.Time) (controlstate.EmailDelivery, error) {
	return s.job, nil
}
func (s *storeStub) FinishInvitationEmail(_ context.Context, _ controlstate.EmailDelivery, status int, _ time.Time) error {
	s.status = status
	return nil
}

func TestEmailDeliveryRetriesStatusWithoutFollowingRedirects(t *testing.T) {
	redirected := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer destination.Close()
	for _, status := range []int{204, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/internal/tnl/emails" || r.Header.Get("Authorization") != "Bearer email-secret" || r.Header.Get("Idempotency-Key") != "ivt_job" {
					t.Error("incorrect delivery boundary")
				}
				var body authorityv1.EmailDeliveryRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeliveryId != "ivt_job" {
					t.Errorf("invalid typed email: %v", err)
				}
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			store := &storeStub{job: controlstate.EmailDelivery{ID: "ivt_job", Payload: authorityv1.EmailDeliveryRequest{DeliveryId: "ivt_job", Type: authorityv1.TeamInvitation, To: "sam@example.com", Data: authorityv1.TeamInvitationEmail{TeamDisplayName: "studio", Secret: "secret", ExpiresAt: time.Now().Add(time.Hour)}}}}
			worker, err := New(store, server.URL, "email-secret", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := worker.Process(t.Context()); err != nil || store.status != status {
				t.Fatalf("delivery status=%d error=%v", store.status, err)
			}
		})
	}
	if redirected != 0 {
		t.Fatal("redirect received the delivery credential")
	}
}
