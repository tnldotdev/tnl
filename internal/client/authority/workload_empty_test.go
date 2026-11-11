package authority

import (
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestWorkloadSessionRequestsRejectNoContent(t *testing.T) {
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
		{"exchange", func() error {
			_, err := client.ExchangeWorkload(t.Context(), authorityv1.WorkloadExchange{})
			return err
		}},
		{"attach", func() error {
			_, err := client.AttachWorkloadAssertion(t.Context(), "session", "credential", authorityv1.WorkloadAssertion{})
			return err
		}},
		{"renew", func() error {
			_, err := client.RenewWorkloadSession(t.Context(), "session", "credential", authorityv1.WorkloadRenewal{})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatalf("empty workload response = %v", err)
			}
		})
	}
}
