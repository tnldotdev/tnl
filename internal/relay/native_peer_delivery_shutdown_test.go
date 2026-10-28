package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// hold the denial write until the serving loop has selected session shutdown.
// returning EOF then proves that both the joined cause and the denial survive.
type nativeDenialWriteGate struct {
	muxsession.Stream
	armed   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (s *nativeDenialWriteGate) Write(data []byte) (int, error) {
	if s.armed.Load() {
		close(s.started)
		<-s.release
		return 0, io.EOF
	}
	return s.Stream.Write(data)
}

func TestNativeDeliveryRetainsDenialAcrossControlWriteFailure(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "control result"
		if shutdown {
			name = "session shutdown"
		}
		t.Run(name, func(t *testing.T) {
			claimClient := nativeClaimFunc(func(_ context.Context, _ relayv1.RelayLease, source netip.Addr, proof tunnelv1.NativePairLegProof, _ []byte) (relayv1.NativePeerPairLegClaim, error) {
				return nativeTestClaim(source, proof), nil
			})
			_, owner, hello := nativeAdmissionFixture(t, 2, claimClient)
			proof := *hello.NativePairLegProof
			claim, err := owner.claim(t.Context(), socketIdentityOnly{}, proof)
			if err != nil {
				t.Fatal(err)
			}
			server, client := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			gate := &nativeDenialWriteGate{Stream: &forwardingTestStream{Conn: server}, started: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(gate.release) })
			transport := newForwardingTestSession(gate)
			ctx, cancel := context.WithCancel(t.Context())
			// a second activation is rejected before any publisher installation.
			delivery := &nativePairDelivery{ctx: ctx, cancel: cancel, activated: true,
				stopPublisher: func() bool { return true }, publisher: &nativePacketSession{},
				deadline: time.Now().Add(time.Minute), changed: make(chan struct{}),
				done: make(chan struct{}), authorityDone: make(chan struct{})}
			close(delivery.authorityDone)
			ready := make(chan struct{})
			result := relayWorker(t, func() { release(); cancel(); _ = transport.Close() }, func() error {
				session, _, err := tunnel.AcceptWithResult(ctx, transport, func(context.Context, tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error) {
					return &claim.receipt, nil
				})
				if err != nil {
					return err
				}
				defer session.Close()
				close(ready)
				return delivery.serve(owner, session, proof, claim)
			})
			if err := tunnelv1.WriteControl(client, hello); err != nil {
				t.Fatal(err)
			}
			if message, err := tunnelv1.ReadControl(client); err != nil || message.Type != tunnelv1.HelloAccepted {
				t.Fatal("native handshake failed", err)
			}
			relayAwait(t, ready)
			gate.armed.Store(true)
			if err := tunnelv1.WriteControl(client, tunnelv1.Message{Type: tunnelv1.NativeLegActivate, ProtocolVersion: tunnelv1.Version,
				RequestID: "repeated", Role: tunnelv1.NativeConnector, NativeLegBinding: &tunnelv1.NativeLegBinding{Nonce: proof.Nonce}}); err != nil {
				t.Fatal(err)
			}
			relayAwait(t, gate.started)
			if shutdown {
				_ = transport.Close()
				// only delivery.Close cancels this context. wait until the outer
				// loop is joining the still-blocked control worker before releasing it.
				relayAwait(t, ctx.Done())
			}
			release()
			err = relayAwait(t, result)
			var denied *tunnel.ProtocolError
			if !errors.As(err, &denied) || denied == nil || denied.Code != tunnelv1.Unauthenticated || !errors.Is(err, io.EOF) {
				t.Fatal("control denial or failed write was lost", err)
			}
			relayAwait(t, delivery.done)
		})
	}
}
