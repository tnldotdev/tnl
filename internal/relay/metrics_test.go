package relay

import (
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwardingAcceptorReportsStreamCapacity(t *testing.T) {
	secrets, err := serviceapi.NewBearerSecrets(strings.Repeat("s", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	var deltas []int
	rejections := 0
	acceptor, err := NewForwardingAcceptor(ForwardingAcceptorConfig{
		Registry: NewRegistry(), ClusterSecrets: secrets, StreamCapacity: 1,
		StreamsDelta:     func(delta int) { deltas = append(deltas, delta) },
		CapacityRejected: func() { rejections++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !acceptor.acquireStream() || acceptor.acquireStream() {
		t.Fatal("stream capacity admission did not enforce its limit")
	}
	acceptor.releaseStream()
	if len(deltas) != 2 || deltas[0] != 1 || deltas[1] != -1 || rejections != 1 {
		t.Fatalf("stream metrics: deltas=%v rejections=%d", deltas, rejections)
	}
}

func TestPublisherAcceptorReportsConnectionCapacity(t *testing.T) {
	rejections := 0
	acceptor := &PublisherAcceptor{capacity: func() { rejections++ }}
	code := acceptor.controlErrorCode(&ControlProblemError{Problem: &relayv1.Problem{
		Type: "https://tnl.dev/problems/relay_connection_capacity_exhausted",
	}})
	if code != tunnelv1.CapacityExceeded || rejections != 1 {
		t.Fatalf("capacity error: code=%s rejections=%d", code, rejections)
	}
	code = acceptor.controlErrorCode(&ControlProblemError{Problem: &relayv1.Problem{
		Type: "https://tnl.dev/problems/stale_connection_assignment",
	}})
	if code != tunnelv1.StaleConnectionAssignment || rejections != 1 {
		t.Fatalf("non-capacity error: code=%s rejections=%d", code, rejections)
	}
}
