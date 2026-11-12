package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// fixture shutdown tolerates only the intended result in every branch. cleanup
// failures remain failures even when their cause is an expected operation stop.
func workloadRuntimeAllErrors(err error, accept func(error) bool) bool {
	if _, cleanup := err.(*connectorstream.CleanupError); cleanup {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !workloadRuntimeAllErrors(child, accept) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return workloadRuntimeAllErrors(wrapped, accept)
	}
	return accept(err)
}

func workloadRuntimeOnlyCanceled(err error) bool {
	return workloadRuntimeAllErrors(err, func(err error) bool { return err == context.Canceled })
}

func workloadRuntimeOnlyGone(err error) bool {
	return workloadRuntimeAllErrors(err, func(err error) bool {
		problem, ok := err.(*clientauthority.ProblemError)
		return ok && problem != nil && problem.Status == http.StatusGone && problem.Problem.Code == authorityv1.Forbidden
	})
}

func workloadRuntimeOnlyConnectorTermination(err error, expected, expired bool) bool {
	return workloadRuntimeAllErrors(err, func(err error) bool {
		if err == context.Canceled {
			return true
		}
		if !expected {
			return false
		}
		if err == connectorstream.ErrServiceConnection || err == tunnel.ErrConnectorPermissionRejected {
			return true
		}
		if err == context.DeadlineExceeded {
			return expired
		}
		switch problem := err.(type) {
		case *clientcontrol.ProblemError:
			return problem != nil && problem.Problem.Code == controlv1.Forbidden && (problem.Status == http.StatusForbidden || expired && problem.Status == http.StatusGone)
		case *tunnel.ProtocolError:
			return problem != nil && problem.Code == tunnelv1.Unauthenticated
		default:
			return false
		}
	})
}

func TestWorkloadRuntimeCancellationPreservesIndependentErrors(t *testing.T) {
	assertWorkloadRuntimeErrorBranches(t, workloadRuntimeOnlyCanceled, context.Canceled)
	if workloadRuntimeOnlyCanceled(context.DeadlineExceeded) {
		t.Fatal("fixture treated an independent deadline as owned cancellation")
	}
}

func TestWorkloadRuntimeGonePreservesIndependentErrors(t *testing.T) {
	gone := &clientauthority.ProblemError{Status: http.StatusGone, Problem: authorityv1.Problem{Code: authorityv1.Forbidden}}
	assertWorkloadRuntimeErrorBranches(t, workloadRuntimeOnlyGone, gone)
	for _, err := range []error{
		context.Canceled,
		context.DeadlineExceeded,
		&clientauthority.ProblemError{Status: http.StatusForbidden, Problem: authorityv1.Problem{Code: authorityv1.Forbidden}},
		&clientauthority.ProblemError{Status: http.StatusGone, Problem: authorityv1.Problem{Code: authorityv1.Internal}},
	} {
		if workloadRuntimeOnlyGone(err) {
			t.Fatal("fixture accepted a non-expiry renewal failure")
		}
	}
}

func TestWorkloadRuntimeConnectorTerminationPreservesIndependentErrors(t *testing.T) {
	denied := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	gone := &clientcontrol.ProblemError{Status: http.StatusGone, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	for _, err := range []error{
		context.Canceled, connectorstream.ErrServiceConnection, tunnel.ErrConnectorPermissionRejected,
		&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, denied, gone, context.DeadlineExceeded,
		errors.Join(connectorstream.ErrServiceConnection, fmt.Errorf("authority: %w", denied), context.Canceled),
	} {
		assertWorkloadRuntimeErrorBranches(t, func(err error) bool { return workloadRuntimeOnlyConnectorTermination(err, true, true) }, err)
	}
	for _, err := range []error{connectorstream.ErrServiceConnection, denied, gone, tunnel.ErrConnectorPermissionRejected} {
		if workloadRuntimeOnlyConnectorTermination(err, false, true) {
			t.Fatal("fixture accepted an unrequested retirement")
		}
	}
	for _, err := range []error{gone, context.DeadlineExceeded} {
		if workloadRuntimeOnlyConnectorTermination(err, true, false) {
			t.Fatal("fixture accepted an unexpired deadline")
		}
	}
	for _, err := range []error{
		&tunnel.ProtocolError{Code: tunnelv1.Unavailable},
		&clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Internal}},
	} {
		if workloadRuntimeOnlyConnectorTermination(err, true, true) {
			t.Fatal("fixture accepted an unrelated connector failure")
		}
	}
}

func assertWorkloadRuntimeErrorBranches(t *testing.T, classify func(error) bool, expected error) {
	t.Helper()
	for _, err := range []error{expected, fmt.Errorf("operation: %w", expected), errors.Join(expected, fmt.Errorf("wrapped: %w", expected))} {
		if !classify(err) {
			t.Fatal("fixture did not accept only expected operation results", err)
		}
	}
	for _, independent := range []error{errors.New("independent operation failure"), io.ErrUnexpectedEOF, io.ErrClosedPipe} {
		for _, err := range []error{
			independent, errors.Join(expected, independent), fmt.Errorf("operation: %w", errors.Join(expected, independent)),
			errors.Join(expected, &connectorstream.CleanupError{Err: independent}),
		} {
			if classify(err) {
				t.Fatal("fixture discarded an independent joined failure", err)
			}
		}
	}
	for _, err := range []error{&connectorstream.CleanupError{Err: expected}, fmt.Errorf("joined cleanup: %w", &connectorstream.CleanupError{Err: expected})} {
		if classify(err) {
			t.Fatal("fixture discarded a cleanup failure with an expected operation cause")
		}
	}
}
