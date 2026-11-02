package stream

import (
	"errors"
	"testing"

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
