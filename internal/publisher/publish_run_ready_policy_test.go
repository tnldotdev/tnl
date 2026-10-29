package publisher

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type readyPolicyControl struct {
	PublicURLControlClient
	mark func()
}

func (c readyPolicyControl) MarkPublishRunReady(context.Context, string, uint64, credentials.PublishRunToken) error {
	c.mark()
	return nil
}

func TestPublisherReadyRequiresPolicyBeforeRequestAndNotification(t *testing.T) {
	for _, when := range []string{"current", "before request", "before notification"} {
		t.Run(when, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				policy, update, _ := httpPermissionFixture(t, true)
				route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: update.View.Hostname, PublicURLID: update.View.Scope.ID,
					Certificate: publicURLTestCertificate(t, update.View.Hostname), VisitorPolicy: policy, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})})
				if err != nil {
					t.Fatal(err)
				}
				defer route.Close()
				if when == "before request" {
					policy.Close()
				}
				requests, notifications := 0, 0
				authority := publicRunAuthority{client: readyPolicyControl{mark: func() {
					requests++
					if when == "before notification" {
						policy.Close()
					}
				}}}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				err = confirmPublishRunReady(ctx, authority, route, func() error { notifications++; return nil })
				if when == "current" {
					if err != nil || requests != 1 || notifications != 1 {
						t.Fatal("prepared publisher did not confirm once", requests, notifications, err)
					}
				} else if !errors.Is(err, context.DeadlineExceeded) || notifications != 0 || when == "before request" && requests != 0 || when == "before notification" && requests != 1 {
					t.Fatal("publisher confirmed without installed policy", requests, notifications, err)
				}
			})
		})
	}
}
