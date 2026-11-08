package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type sessionResponseTransport func(*http.Request) (*http.Response, error)

func (f sessionResponseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSessionCanceledUpdatesRetainConfirmedAuthority(t *testing.T) {
	for _, operation := range []string{"renew", "attach"} {
		t.Run(operation, func(t *testing.T) {
			original := sessionFixture(controlv1.WorkloadOIDC)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("caller canceled its pending authority update")
			transport := sessionResponseTransport(func(r *http.Request) (*http.Response, error) {
				next := cloneSession(original)
				if !strings.HasSuffix(r.URL.Path, "/exchange") {
					if operation == "renew" {
						next.RenewalSequence++
					} else {
						next.IdentityExpiresAt = next.IdentityExpiresAt.Add(time.Minute)
					}
					cancel(cause)
				}
				data, _ := json.Marshal(next)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
			})
			client, err := New("https://control.example", &http.Client{Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "initial", nil); err != nil {
				t.Fatal(err)
			}
			before, _ := client.Session()
			if operation == "renew" {
				_, err = client.Renew(ctx)
			} else {
				_, err = client.Attach(ctx, "fresh")
			}
			if !errors.Is(err, cause) {
				t.Fatal("late response replaced the caller's cancellation", err)
			}
			if saved, _ := client.Session(); !reflect.DeepEqual(saved, before) {
				t.Fatal("late canceled update changed confirmed authority")
			}
		})
	}
}
