package relayapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayStoreProblemsUseDeclaredCodes(t *testing.T) {
	for _, err := range []error{
		controlstate.ErrRelayRegistrationConflict,
		controlstate.ErrRelayLeaseStale,
		controlstate.ErrRelayTransportCertificateLeaseStale,
		controlstate.ErrRelayTransportCertificateNotFound,
		controlstate.ErrConnectionAssignmentStale,
		controlstate.ErrPublishRunStale,
		controlstate.ErrPublisherConnectionAlreadyClaimed,
		controlstate.ErrPublisherConnectionCredential,
		credentials.ErrInvalidPublisherConnectionCredential,
		controlstate.ErrRelayDraining,
		controlstate.ErrRelayConnectionCapacity,
		controlstate.ErrPublisherConnectionRelayService,
		controlstate.ErrPublisherConnectionUnavailable,
		errors.New("unexpected database error"),
	} {
		status, code, detail := storeProblem(err, func(error) {})
		if status < http.StatusBadRequest || status > 599 || !relayv1.ProblemCode(code).Valid() || detail == "" {
			t.Fatalf("%v -> status=%d code=%q detail=%q", err, status, code, detail)
		}
	}
}
