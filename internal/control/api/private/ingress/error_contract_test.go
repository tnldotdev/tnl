package ingress

import (
	"errors"
	"net/http"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestIngressStoreProblemsUseDeclaredCodes(t *testing.T) {
	for _, err := range []error{
		controlstate.ErrIngressAlreadyRunning,
		controlstate.ErrIngressLeaseStale,
		controlstate.ErrPublicURLRecoveryEpisodeStale,
		errors.New("unexpected database error"),
	} {
		status, code, detail := storeProblem(err, func(error) {})
		if status < http.StatusBadRequest || status > 599 || !ingressv1.ProblemCode(code).Valid() || detail == "" {
			t.Fatalf("%v -> status=%d code=%q detail=%q", err, status, code, detail)
		}
	}
}
