package stream

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type renewalDenialTransport struct {
	*legRetrySession
	acknowledge func() error
}

func (s renewalDenialTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.legRetrySession.OpenStream(ctx)
	return renewalDenialAcknowledgment{Stream: stream, acknowledge: s.acknowledge}, err
}

type renewalDenialAcknowledgment struct {
	muxsession.Stream
	acknowledge func() error
}

func (s renewalDenialAcknowledgment) CloseWrite() error { return s.acknowledge() }

func TestConnectorRenewalDenialKeepsAcknowledgmentFailureAfterCarrierClosure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
		defer finish()
		p, _ := pendingRetryOwner(t, budget)
		p.rebind, p.recoveryState = nil, connectorBindingReady
		p.endpoint = &peer.Endpoint{}
		p.paths[0].probeAfter = time.Now().Add(time.Minute)
		p.paths[0].carrier = peer.NewCarrierSlot()
		defer p.paths[0].carrier.Close()
		local, remote := net.Pipe()
		raw := &legRetrySession{ctx: budget, local: local, peer: remote, done: make(chan struct{})}
		defer raw.Close()
		physical := errors.New("independent acknowledgment close failure")
		transport := renewalDenialTransport{legRetrySession: raw, acknowledge: func() error {
			// the received denial and physical failure precede the next guard.
			// carrier loss and expiry cannot replace that entered result.
			p.run.ValidUntil = time.Now()
			return errors.Join(raw.Close(), physical)
		}}
		served := make(chan error, 1)
		go func() {
			hello, err := tunnelv1.ReadControl(remote)
			if err == nil {
				err = tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version,
					ConnectorPairLegAccepted: &tunnelv1.ConnectorPairLegAccepted{PairID: p.pair.PairId, DeliveryID: p.pair.DeliveryId,
						DeliveryGeneration: p.pair.DeliveryGeneration, BindingState: tunnelv1.ConnectorPeerLegBindingPrepared,
						ConnectionSlot: hello.ConnectorPairLegProof.ConnectionSlot, SourceIP: "192.0.2.1",
						ObservedAt: time.Now(), ExpiresAt: p.pair.ExpiresAt}})
			}
			if err == nil {
				var request tunnelv1.Message
				request, err = tunnelv1.ReadControl(remote)
				if err == nil {
					err = tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.Error,
						ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, Code: tunnelv1.Unauthenticated})
				}
			}
			served <- err
		}()
		defer func() { _ = raw.Close(); <-served }()
		leg, err := dialConnectorLeg(budget, budget, Config{
			RelayQUIC:      muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) { return transport, nil }),
			RelayWebSocket: muxsession.DisabledConnector{},
		}, p.signer, p.pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
		if err != nil {
			t.Fatal(err)
		}
		defer leg.Close()
		changed := make(chan struct{})
		close(changed)
		disposition, err := p.maintainConnectorLeg(budget, 0, leg, changed)
		var cleanup *tunnel.SessionCleanupError
		if disposition != terminateConnection || !errors.Is(err, physical) || !errors.As(err, &cleanup) ||
			!leg.session.ConnectorLegRenewalDenied(err) || p.terminalDenied == nil {
			t.Fatal("carrier loss replaced the entered denial or physical acknowledgment failure", disposition, err)
		}
		p.cancel(context.Canceled)
		p.recordLegRecoveryFailure(err, context.Cause(p.ctx))
		if !errors.Is(p.useErr, physical) || !errors.As(p.useErr, &cleanup) || p.servingErr != nil {
			t.Fatal("mixed denial acquired serving-only provenance after join", p.servingErr, p.useErr)
		}
	})
}
