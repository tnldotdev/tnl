package emaildelivery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type storeStub struct {
	job    controlstate.EmailDelivery
	status int
	err    error
}

func (s *storeStub) ClaimInvitationEmail(context.Context, string, time.Time) (controlstate.EmailDelivery, error) {
	return s.job, s.err
}

func TestEmailDeliveryFailurePreservesCauseAndRetryReason(t *testing.T) {
	cause := errors.New("database failed with invitation-secret-do-not-display")
	worker, err := New(&storeStub{err: cause}, "https://mail.example.test", "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.Process(t.Context())
	reason, definition, classified := failure.Describe(err)
	if !classified || reason != failure.ServerEmailDeliveryFailed || definition.Retry != failure.RetryLater || !errors.Is(err, cause) {
		t.Fatalf("email failure reason=%s retry=%v cause=%t", reason, definition.Retry, errors.Is(err, cause))
	}
}
func (s *storeStub) FinishInvitationEmail(_ context.Context, _ controlstate.EmailDelivery, status int, _ time.Time) error {
	s.status = status
	return nil
}

func TestEmailDeliveryRetriesStatusWithoutFollowingRedirects(t *testing.T) {
	const deliveryID = "ivt_0123456789abcdefghijkl"
	const webhookSecret = "webhook-secret-with-at-least-32-bytes"
	redirected := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer destination.Close()
	for _, status := range []int{204, 503, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/internal/tnl/emails" || r.Header.Get("Authorization") != "Bearer "+webhookSecret || r.Header.Get("Idempotency-Key") != deliveryID {
					t.Error("incorrect delivery boundary")
				}
				var body authorityv1.EmailDeliveryRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DeliveryId != deliveryID {
					t.Errorf("invalid email delivery request: %v", err)
				}
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(status)
			}))
			defer server.Close()
			store := &storeStub{job: controlstate.EmailDelivery{ID: deliveryID, Payload: authorityv1.EmailDeliveryRequest{DeliveryId: deliveryID, Type: authorityv1.TeamInvitation, To: "sam@example.com", Data: authorityv1.TeamInvitationEmail{TeamDisplayName: "studio", Secret: "invitation-secret-with-at-least-32-bytes", ExpiresAt: time.Now().Add(time.Hour)}}}}
			worker, err := New(store, server.URL, webhookSecret, server.Client())
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
