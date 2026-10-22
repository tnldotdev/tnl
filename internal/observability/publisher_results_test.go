package observability_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublisherOwnedRejectionsKeepTheirClassificationAndCause(t *testing.T) {
	secretCause := errors.New("secret provider response and arbitrary hostname")
	for _, test := range []struct {
		name    string
		err     error
		outcome observability.Outcome
		code    string
	}{
		{"tunnel authorization", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, observability.Denied, "tunnel.unauthenticated"},
		{"tunnel capacity", &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}, observability.Rejected, "tunnel.capacity_exceeded"},
		{"tunnel stale assignment", &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}, observability.Rejected, "tunnel.stale_connection_assignment"},
		{"tunnel infrastructure", &tunnel.ProtocolError{Code: tunnelv1.Unavailable}, observability.Error, "tunnel.unavailable"},
		{"unknown tunnel code", &tunnel.ProtocolError{Code: "secret-arbitrary-value"}, observability.Error, string(failure.Unexpected)},
		{"diagnostic denial", diagnostic.Wrap(diagnostic.VisitorAccessDenied, secretCause), observability.Denied, string(diagnostic.VisitorAccessDenied)},
		{"diagnostic capacity", diagnostic.Wrap(diagnostic.RequestLimitReached, secretCause), observability.Rejected, string(diagnostic.RequestLimitReached)},
		{"diagnostic timeout", diagnostic.Wrap(diagnostic.AuthenticationTimeout, secretCause), observability.Timeout, string(diagnostic.AuthenticationTimeout)},
		{"control denial", failure.Wrap("authorize publisher", failure.ServerDenied, secretCause), observability.Denied, string(failure.ServerDenied)},
		{"control infrastructure", failure.Wrap("authorize publisher", failure.ServerUnavailable, secretCause), observability.Error, string(failure.ServerUnavailable)},
		{"provider failure", secretCause, observability.Error, string(failure.Unexpected)},
		{"cancellation", context.Canceled, observability.Canceled, string(failure.Unexpected)},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapped := fmt.Errorf("publisher boundary: %w", test.err)
			if got := observability.ErrorOutcome(wrapped); got != test.outcome {
				t.Fatal("owned rejection became an infrastructure failure", got, test.outcome)
			}
			if got := observability.FailureCode(wrapped); got != test.code {
				t.Fatal("owned code was lost or untrusted text was exported", got, test.code)
			}
			if !errors.Is(wrapped, test.err) {
				t.Fatal("classification changed the original cause")
			}
		})
	}
}
