package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCanceledLegDialRetainsIndependentFailures(t *testing.T) {
	for _, withFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned cancellation", true: "independent failure"}[withFailure], func(t *testing.T) {
			signer, _, pair, _, _ := rebindFixture(t)
			independent := errors.New("independent candidate cleanup failure")
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			entered := make(chan struct{}, 2)
			gate := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
				entered <- struct{}{}
				<-ctx.Done()
				if withFailure {
					return nil, errors.Join(context.Cause(ctx), independent)
				}
				return nil, context.Cause(ctx)
			})
			done := make(chan error, 1)
			joined := false
			go func() {
				_, err := dialConnectorLeg(ctx, t.Context(), Config{RelayQUIC: gate, RelayWebSocket: gate}, signer, pair, [32]byte{1}, 0, nil, tunnelv1.ConnectorHandoffID{1})
				done <- err
			}()
			defer func() {
				cancel()
				if !joined {
					<-done
				}
			}()
			for range 2 {
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("both raced candidates did not enter")
				}
			}
			cancel()
			err := <-done
			joined = true
			if !withFailure && err != context.Canceled {
				t.Fatal("owned canceled dial acquired a synthetic unavailable cause", err)
			}
			if withFailure && (!errors.Is(err, independent) || !errors.Is(err, context.Canceled)) {
				t.Fatal("canceled dial discarded an independent candidate failure", err)
			}
		})
	}
}

func TestConnectorPairDenialKeepsEnteredLegRenewalsUntilReply(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			var gates [2]*fixtureTLSGate
			for slot := range gates {
				gates[slot] = &fixtureTLSGate{entered: make(chan struct{}), release: make(chan struct{})}
			}
			release := sync.OnceFunc(func() {
				for _, gate := range gates {
					close(gate.release)
				}
			})
			defer release()
			denied := failure.Wrap("renew connector pair", failure.ServerDenied, errors.New("original authority denial"))
			cleanup := errors.New("independent control cleanup failure")
			deniedEntered := make(chan struct{})
			var pairID string
			f := newConfiguredConnectorFixture(t, transport, "", func(f *connectorFixture, config *Config) {
				control, err := NewControlWithConfig(ControlConfig{
					Signer: f.ConnectorSigner, Resolve: f.ResolveService,
					Pair: func(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
						pair, err := f.PrepareConnectorPeerPair(ctx, service, body)
						if err == nil {
							f.mu.Lock()
							pairID = pair.PairId
							f.peers[pairID].renewalGate = gates
							f.mu.Unlock()
						}
						return pair, err
					},
					RenewPair: func(ctx context.Context, _ string, _ controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPairRenewal, error) {
						for _, gate := range gates {
							select {
							case <-gate.entered:
							case <-ctx.Done():
								return controlv1.ConnectorPeerPairRenewal{}, context.Cause(ctx)
							}
						}
						close(deniedEntered)
						return controlv1.ConnectorPeerPairRenewal{}, denied
					},
					RebindPair: f.RebindConnectorPeerPair, RetirePair: f.RetireConnectorPeerPair,
					Permission: f.VisitorPermission, Close: func(context.Context) error { return cleanup },
				})
				if err != nil {
					t.Fatal(err)
				}
				config.Control = control
			})
			local := f.local(t)
			if _, err := io.WriteString(local, "admitted"); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(local, make([]byte, len("admitted"))); err != nil {
				t.Fatal(err)
			}
			f.denied.Store(true)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			select {
			case <-deniedEntered:
			case <-ctx.Done():
				t.Fatal("authority denial did not overlap both real entered leg renewals")
			}
			until, _ := ctx.Deadline()
			if err := local.SetReadDeadline(until); err != nil {
				t.Fatal(err)
			}
			if _, err := local.Read(make([]byte, 1)); err == nil {
				t.Fatal("authority denial retained the local application")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("local application waited for the held leg replies", err)
			}
			f.mu.Lock()
			var carrierErr error
			for _, sessions := range f.sessions {
				for _, session := range sessions {
					carrierErr = errors.Join(carrierErr, session.Err())
				}
			}
			f.mu.Unlock()
			if carrierErr != nil {
				t.Fatal("serving cancellation destroyed an entered renewal's packet carrier", carrierErr)
			}
			select {
			case <-f.finished:
				t.Fatal("owner returned before its entered leg renewals actually joined")
			default:
			}
			release()
			select {
			case <-f.finished:
			case <-ctx.Done():
				t.Fatal("released leg replies did not permit real Abort and retirement to join")
			}
			if !errors.Is(f.serveErr, denied) || !errors.Is(f.serveErr, cleanup) {
				t.Fatal("joined shutdown lost its original denial or independent cleanup failure", f.serveErr)
			}
			f.mu.Lock()
			retired := f.peers[pairID].retired
			f.mu.Unlock()
			if !retired {
				t.Fatal("joined terminal work did not leave budget for authenticated retirement")
			}
		})
	}
}
