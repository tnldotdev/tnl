package relay

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayResponseErrorHandlesTypedNil(t *testing.T) {
	t.Parallel()
	var response *relayv1.RegisterRelayResponse
	err := relayResponseError("register relay", response)
	var problem *ControlProblem
	if !errors.As(err, &problem) || problem.Operation != "register relay" || problem.Status != 0 || problem.Problem != nil {
		t.Fatalf("error = %#v", err)
	}
}
