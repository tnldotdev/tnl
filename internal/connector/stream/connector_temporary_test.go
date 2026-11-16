package stream

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorTemporaryProtocolRenewal(t *testing.T) {
	if !connectorTemporary(errors.Join(errors.New("control returned 503"), &tunnel.ProtocolError{Code: tunnelv1.Unavailable})) {
		t.Fatal("unavailable renewal must retry within the original authority deadline")
	}
	if connectorTemporary(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}) {
		t.Fatal("denied renewal must not retry")
	}
}

func TestConnectorTemporaryRetainsReasonsAndIndependentDenials(t *testing.T) {
	unavailable := &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
	denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	diagnostic := errors.New("provider diagnostic")
	for _, test := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"classified diagnostic", errors.Join(diagnostic, unavailable), true},
		{"reasoned diagnostic", failure.Wrap("renew", failure.ConnectionUnavailable, diagnostic), true},
		{"denial wraps EOF", failure.Wrap("renew", failure.ServerDenied, io.EOF), false},
		{"unavailable then denial", errors.Join(unavailable, denied), false},
		{"denial then unavailable", errors.Join(denied, unavailable), false},
		{"unavailable then reasoned denial", errors.Join(unavailable, failure.Wrap("renew", failure.ServerDenied, io.EOF)), false},
		{"unavailable then HTTP denial", errors.Join(unavailable, &clientcontrol.ProblemError{Status: http.StatusForbidden}), false},
		{"network then independent failure", errors.Join(io.EOF, diagnostic), false},
		{"unavailable then owned close", errors.Join(unavailable, &CleanupError{Err: io.EOF}), false},
		{"unavailable then transport cleanup", errors.Join(unavailable, &tunnel.SessionCleanupError{Err: io.EOF}), false},
		{"unavailable then physical cleanup", errors.Join(unavailable, &muxsession.QUICTransportCloseError{Err: io.EOF}), false},
		{"physical cleanup then unavailable", errors.Join(&muxsession.QUICTransportCloseError{Err: io.EOF}, unavailable), false},
		{"wrapped childless denial", errors.Join(unavailable, fmt.Errorf("operation: %w", connectorChildlessDenial{})), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := connectorTemporary(test.err); got != test.retry {
				t.Fatal("retry classification lost an operation reason or independent failure", got, test.err)
			}
		})
	}
}

type connectorChildlessDenial struct{}

func (connectorChildlessDenial) Error() string                 { return "childless authority denial" }
func (connectorChildlessDenial) FailureReason() failure.Reason { return failure.ServerDenied }
func (connectorChildlessDenial) Unwrap() []error               { return nil }
