package tunnel

import (
	"errors"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIsTerminalHandshakeError(t *testing.T) {
	for _, test := range []struct {
		code     tunnelv1.ErrorCode
		terminal bool
	}{
		{tunnelv1.InvalidMessage, true},
		{tunnelv1.Unauthenticated, true},
		{tunnelv1.StalePublishRunNumber, true},
		{tunnelv1.StaleConnectionAssignment, true},
		{tunnelv1.DuplicatePublisherConnection, true},
		{tunnelv1.DrainingPublisherConnection, false},
		{tunnelv1.CapacityExceeded, false},
		{tunnelv1.Unavailable, false},
		{tunnelv1.Internal, false},
	} {
		err := &ProtocolError{Code: test.code}
		for _, err := range []error{err, fmt.Errorf("wrapped: %w", err)} {
			if got := IsTerminalHandshakeError(err); got != test.terminal {
				t.Errorf("%v: terminal = %v, want %v", err, got, test.terminal)
			}
		}
	}
	for _, err := range []error{nil, errors.New("transport failed")} {
		if IsTerminalHandshakeError(err) {
			t.Errorf("non-protocol error %v is terminal", err)
		}
	}
}
