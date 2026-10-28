package stream

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativePeerHandoffConsumerKeepsSourceDeadlineAndOneShotSelection(t *testing.T) {
	for _, outcome := range []string{"accepted", "changed source", "expired", "rejected", "ambiguous"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, prepared, owner := preparedPeerFixture(t)
				binding := *prepared.peer
				previous := peerLegPredecessor{nonce: [32]byte{1}, source: "127.0.0.1", until: time.Now().Add(3 * time.Second)}
				if outcome == "expired" {
					previous.until = time.Now()
				}
				session := peerHelloSession(t, binding, owner.signer, func(r *tunnelv1.NativePairLegAccepted) {
					if outcome == "changed source" {
						r.SourceIP = "127.0.0.2"
					}
				}, nil, true)
				session.selection = func(selection tunnelv1.NativeLegBinding) {
					if !bytes.Equal(selection.PreviousNonce, previous.nonce[:]) {
						t.Error("handoff lost the exact predecessor")
					}
				}
				session.activate = func() error {
					switch outcome {
					case "rejected":
						return ErrServiceConnection
					case "ambiguous":
						time.Sleep(4 * time.Second)
					}
					return nil
				}
				connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return session, nil })
				next, err := racePeerRelayCandidates(t.Context(), t.Context(), [2]muxsession.Connector{connector, connector}, binding, owner.signer, 0, &previous)
				if (err == nil) != (outcome == "accepted") {
					t.Fatal("unexpected handoff result", err)
				}
				if next != nil {
					defer next.Close()
					next.mu.Lock()
					until := next.until
					next.mu.Unlock()
					if !until.Equal(previous.until) {
						t.Fatal("handoff extended the predecessor deadline")
					}
				}
				consumed := outcome == "rejected" || outcome == "ambiguous"
				if errors.Is(err, errPeerHandoffConsumed) != consumed {
					t.Fatal("handoff lost its retry boundary", err)
				}
				if (session.activations.Load() == 0) != (outcome == "changed source" || outcome == "expired") {
					t.Fatal("handoff selected before checking source and authority")
				}
			})
		})
	}
}
