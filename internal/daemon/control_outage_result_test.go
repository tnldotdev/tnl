package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestOutageTerminalOnlyPreservesEveryJoinedCause(t *testing.T) {
	expected := []error{
		clientcontrol.ErrUnavailable, context.Canceled, context.DeadlineExceeded,
		publisherservice.ErrPrivateStream, controloutage.ErrDeadline,
		ingress.ErrIngressLeaseLost, connectorstream.ErrServiceConnection,
	}
	for _, cause := range expected {
		if !outageTerminalOnly(cause) {
			t.Fatal("existing outage terminal cause was rejected", cause)
		}
	}
	mixed := errors.Join(context.DeadlineExceeded, connectorstream.ErrServiceConnection)
	independent := errors.New("independent physical cleanup failure")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"all existing terminal causes", errors.Join(expected...), true},
		{"direct mixed expiry", mixed, true},
		{"wrapped mixed expiry", fmt.Errorf("terminal operation: %w", mixed), true},
		{"cleanup mixed expiry", &connectorstream.CleanupError{Err: mixed}, true},
		{"nested cleanup mixed expiry", errors.Join(connectorstream.ErrServiceConnection,
			&connectorstream.CleanupError{Err: errors.Join(context.DeadlineExceeded,
				fmt.Errorf("terminal operation: %w", mixed))}), true},
		{"independent cleanup", &connectorstream.CleanupError{Err: independent}, false},
		{"mixed expiry and independent cleanup", &connectorstream.CleanupError{Err: errors.Join(mixed, independent)}, false},
		{"wrapped mixed expiry and independent cleanup", fmt.Errorf("terminal result: %w",
			&connectorstream.CleanupError{Err: errors.Join(mixed, independent)}), false},
		{"joined independent cleanup", errors.Join(mixed, &connectorstream.CleanupError{Err: independent}), false},
		{"unexpected forwarding failure", &connectorstream.CleanupError{Err: errors.Join(mixed, io.ErrUnexpectedEOF)}, false},
		{"physical close cannot borrow expiry", &muxsession.QUICTransportCloseError{Err: context.DeadlineExceeded}, false},
		{"nested physical close cannot borrow expiry", &connectorstream.CleanupError{Err: errors.Join(mixed,
			&muxsession.QUICTransportCloseError{Err: context.DeadlineExceeded})}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := outageTerminalOnly(test.err); got != test.want {
				t.Fatalf("outage terminal classification = %t, want %t: %v", got, test.want, test.err)
			}
		})
	}
}
