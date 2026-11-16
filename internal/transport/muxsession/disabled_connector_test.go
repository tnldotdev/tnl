package muxsession

import (
	"context"
	"errors"
	"testing"
)

func TestDisabledConnectorReportsNoDialAndPreservesEntryStop(t *testing.T) {
	disabled := DisabledConnector{}
	session, err := disabled.Connect(t.Context(), Endpoint{Address: "invalid endpoint"})
	if session != nil || err != ErrConnectorDisabled {
		t.Fatal("a disabled candidate tried to validate or dial an endpoint", err)
	}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("owner stopped before the disabled candidate")
	cancel(cause)
	session, err = disabled.Connect(ctx, Endpoint{})
	if session != nil || err != cause {
		t.Fatal("disabled configuration replaced its exact entry stop", err)
	}
}
