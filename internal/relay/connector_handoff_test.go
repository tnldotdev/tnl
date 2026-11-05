package relay

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestHandoffRecordsAdvanceAndExactRetryBeforeInstallation(t *testing.T) {
	at := time.Now()
	initial := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{1})
	s := initialHandoff(initial, at)
	op, err := tunnelv1.NewConnectorHandoff(initial.SelectedHandoff(), tunnelv1.ConnectorHandoffID{2})
	if err != nil {
		t.Fatal(err)
	}
	selection := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{3}).Replacing(op)
	if got := s.record(selection, at.Add(time.Microsecond)); got != handoffAdvanced {
		t.Fatal("first operation did not advance", got)
	}
	if got := s.record(selection, at.Add(time.Microsecond)); got != handoffRejected {
		t.Fatal("same hello timestamp was replayed", got)
	}
	fresh := tunnelv1.InitialConnectorActivation(tunnelv1.ConnectorHelloNonce{4}).Replacing(op)
	if got := s.record(fresh, at.Add(2*time.Microsecond)); got != handoffRetried || len(s.used) != 2 {
		t.Fatal("exact operation retry consumed history", got)
	}
	if got := s.record(initial, at.Add(3*time.Microsecond)); got != handoffRejected {
		t.Fatal("initial activation reset history", got)
	}
}
