package service

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type staleCloseQUIC struct {
	privateSlotQUICTransport
	failure error
	cancel  context.CancelFunc
	closes  atomic.Int32
}

func (s *staleCloseQUIC) Close() error {
	s.closes.Add(1)
	err := s.privateSlotQUICTransport.Close()
	if s.cancel != nil {
		s.cancel()
	}
	return errors.Join(err, s.failure)
}

func TestPrivateConnectSlotStaleCleanupRetainsCauseAndClassification(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal-close", true: "failed-close-during-owner-cancellation"}[failed], func(t *testing.T) {
			_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			relay := newPrivateSlotRelay(t, bound, true, func(context.Context, tunnel.Transport, muxsession.Session) error {
				bound.Invalidate()
				return nil
			}, nil)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sentinel := errors.New("stale accepted session close failed")
			options := relay.options(t, relay.roots)
			quic := options.QUIC
			var physical *staleCloseQUIC
			options.QUIC = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				outer, err := quic.Connect(ctx, endpoint)
				if err != nil {
					return nil, err
				}
				physical = &staleCloseQUIC{privateSlotQUICTransport: outer.(privateSlotQUICTransport)}
				if failed {
					physical.failure, physical.cancel = sentinel, cancel
				}
				return physical, nil
			})
			options.WebSocket = muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
				return nil, net.ErrClosed
			})
			connected := make(chan error, 1)
			slots, err := tunnel.NewSlots(ctx, tunnel.SlotsConfig{SingleUse: true,
				Connect: func(ctx context.Context, slot uint8, _ bool) (tunnel.SlotSession, error) {
					claimed, err := bound.ConnectSlot(ctx, slot, options)
					connected <- err
					if claimed != nil {
						_ = claimed.Close()
						t.Error("stale accepted claim reached slot installation")
					}
					// keep this one completed attempt at the owner-cancellation
					// boundary rather than starting a second fixture connection.
					<-ctx.Done()
					return nil, err
				}})
			if err != nil {
				t.Fatal(err)
			}
			defer slots.Close()
			if err := slots.Set(0, "original-assignment"); err != nil {
				t.Fatal(err)
			}
			err = claimedAwait(t, connected)
			var cleanup *tunnel.SessionCleanupError
			if !errors.Is(err, ErrPrivateStream) || errors.Is(err, sentinel) != failed || errors.As(err, &cleanup) != failed {
				t.Fatal("stale cleanup lost its fence, cause, or cleanup classification", err)
			}
			for range 2 {
				err := slots.Close()
				if errors.Is(err, sentinel) != failed || failed && !errors.Is(err, ErrPrivateStream) {
					t.Fatal("slot owner lost stale cleanup during cancellation", err)
				}
			}
			if physical.closes.Load() != 1 || bound.packetSlots[0] != nil {
				t.Fatal("stale session closed more than once or installed a packet slot", physical.closes.Load())
			}
			awaitPrivateSlot(t, relay.closed[0])
		})
	}
}
