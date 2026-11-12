package authority

import (
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestEnvironmentVisitorSessionRequestsRejectNoContent(t *testing.T) {
	client, err := New("https://authority.example", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		call func() error
	}{
		{"prepare", func() error {
			_, err := client.PrepareEnvironmentVisitor(t.Context(), "project", "environment", authorityv1.EnvironmentVisitorPrepareRequest{})
			return err
		}},
		{"attach", func() error {
			_, err := client.AttachEnvironmentVisitorAssertion(t.Context(), "session", "credential", authorityv1.EnvironmentVisitorAssertion{})
			return err
		}},
		{"renew", func() error {
			_, err := client.RenewEnvironmentVisitorSession(t.Context(), "session", "credential", authorityv1.EnvironmentVisitorRenewal{})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatalf("empty visitor response = %v", err)
			}
		})
	}
}
