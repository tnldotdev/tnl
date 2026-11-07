package state

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type storageRotationDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c storageRotationDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestStorageRotationErrorPreservesQueryAndCancellation(t *testing.T) {
	query := &net.OpError{Op: "write", Net: "tcp", Err: os.ErrDeadlineExceeded}
	if got := storageRotationError(t.Context(), query); got != query {
		t.Fatal("live operation changed the query error", got)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("rotation stopped")
	cancel(cause)
	if got := storageRotationError(ctx, query); !errors.Is(got, query) || !errors.Is(got, cause) {
		t.Fatal("rotation lost the query error or cancellation cause", got)
	}
	// model the socket timeout winning the context timer's scheduling race.
	deadline := storageRotationDeadlineContext{t.Context(), time.Now().Add(-time.Second)}
	if context.Cause(deadline) != nil {
		t.Fatal("deadline fixture already canceled")
	}
	got := storageRotationError(deadline, query)
	var socket *net.OpError
	if !errors.Is(got, context.DeadlineExceeded) || !errors.As(got, &socket) || socket != query {
		t.Fatal("spent deadline lost cancellation classification or the original socket error", got)
	}
	if got := storageRotationError(ctx, nil); got != nil {
		t.Fatal("cancellation turned a completed rotation into a failure", got)
	}
}
