package ingress

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestRegionRegistrationRejectsUnqualifiedInputs(t *testing.T) {
	calls := 0
	client, err := NewDirectClient(DirectConfig{Store: &ingressStoreStub{registerIngress: func(context.Context, controlstate.IngressRegistration, time.Time, time.Duration) (controlstate.IngressLease, error) {
		calls++
		return controlstate.IngressLease{}, nil
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "sjc", "us-west-1", "aws:sjc", "fly:unknown", "FLY:SJC"} {
		_, err := client.RegisterIngress(t.Context(), ingressv1.IngressRegistration{Region: value})
		var problem *serviceapi.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || problem.Code != "invalid_request" || calls != 0 {
			t.Fatal("invalid region reached storage or lost classification", value, err)
		}
	}
}
