package relay

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

func TestRegionRegistrationRejectsUnqualifiedInputs(t *testing.T) {
	calls := 0
	client, err := NewDirectClient(DirectConfig{Store: &relayStoreStub{registerRelay: func(context.Context, controlstate.RelayRegistration, time.Time, time.Duration) (controlstate.RelayLease, error) {
		calls++
		return controlstate.RelayLease{}, nil
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "sjc", "us-west-1", "aws:sjc", "fly:unknown", "FLY:SJC"} {
		_, err := client.RegisterRelay(t.Context(), relayv1.RelayRegistration{Region: value})
		var problem *serverhttp.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || problem.Code != "invalid_request" || calls != 0 {
			t.Fatal("invalid region reached storage or lost classification", value, err)
		}
	}
}
