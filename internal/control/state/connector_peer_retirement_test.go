package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestConnectorPeerRetirementDoesNotTreatIndependentFailureAsDenial(t *testing.T) {
	database := errors.New("independent database failure")
	for _, err := range []error{database, context.Canceled, context.DeadlineExceeded,
		errors.Join(ErrServiceAccess, database), errors.Join(ErrVisitorPermission, context.Canceled)} {
		if connectorPeerAuthorityDenied(err) {
			t.Fatal("failure became negative-only authorization", err)
		}
		if got := connectorPeerPairWrite(0, err); got != err {
			t.Fatal("fenced write discarded or reclassified a failure", got)
		}
	}
	if connectorPeerPairWrite(0, nil) != ErrServiceAccess || connectorPeerPairWrite(1, nil) != nil {
		t.Fatal("fenced mutation did not require one exact row")
	}
	at := time.Now()
	pair := controlstatedb.ControlConnectorPeerPair{OwnerRevision: 1, ExpiresAt: timestamptz(at), ReplayFenceUntil: timestamptz(at.Add(time.Minute))}
	if !connectorPeerPairUnretired(pair) || !connectorPeerPairRetainedUntil(pair).Equal(at.Add(time.Minute)) {
		t.Fatal("retention did not keep the original later fence")
	}
	pair.OwnerRevision, pair.RetiredAt = 2, timestamptz(at)
	if connectorPeerPairUnretired(pair) {
		t.Fatal("terminal revision became positive authority")
	}
}
