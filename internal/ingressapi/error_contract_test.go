package ingressapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestIngressStoreProblemsUseDeclaredCodes(t *testing.T) {
	for _, err := range []error{
		controlstate.ErrIngressAlreadyRunning,
		controlstate.ErrIngressLeaseStale,
		controlstate.ErrPublicURLRecoveryEpisodeStale,
		controlstate.ErrIngressUsageReportInvalid,
		controlstate.ErrIngressUsagePublicURLNotFound,
		controlstate.ErrIngressUsageReportStale,
		controlstate.ErrIngressUsageReportConflict,
		controlstate.ErrPublicURLUsageBucketFinalized,
		errors.New("unexpected database error"),
	} {
		status, code, detail := storeProblem(err, func(error) {})
		if status < http.StatusBadRequest || status > 599 || !ingressv1.ProblemCode(code).Valid() || detail == "" {
			t.Fatalf("%v -> status=%d code=%q detail=%q", err, status, code, detail)
		}
	}
}
