package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type claimedSlotCleanupTransport struct {
	claimedTerminalTransport
	closing chan struct{}
	release chan struct{}
}

func (s *claimedSlotCleanupTransport) Close() error {
	close(s.closing)
	<-s.release
	return s.claimedTerminalTransport.Close()
}

func TestClaimedSlotsSeparateAcceptOperationFromOwnedCleanup(t *testing.T) {
	independent := errors.New("independent physical cleanup failed")
	for _, operation := range []struct {
		name string
		err  error
	}{
		{"idle", &quic.IdleTimeoutError{}},
		{"eof", io.EOF},
		{"abnormal", &quic.ApplicationError{ErrorCode: 17, Remote: true}},
	} {
		for _, cleanup := range []struct {
			name string
			err  error
		}{
			{"clean", nil},
			{"independent", independent},
			{"joined-cancellation", errors.Join(context.Canceled, independent)},
			{"physical-closed", &muxsession.QUICTransportCloseError{Err: net.ErrClosed}},
			{"physical-idle", fmt.Errorf("physical cleanup: %w", &quic.IdleTimeoutError{})},
		} {
			t.Run(operation.name+"/"+cleanup.name, func(t *testing.T) {
				_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
				// the wrapper gives this operation a unique identity even though
				// zero-sized QUIC idle timeout values need not have unique pointers.
				lost := fmt.Errorf("accept operation: %w", operation.err)
				var wire *claimedSlotCleanupTransport
				claimed, _ := newClaimedTestPair(t, bound, 0, func(outer muxsession.Session) muxsession.Session {
					wire = &claimedSlotCleanupTransport{claimedTerminalTransport: claimedTerminalTransport{
						Session: outer, entered: make(chan struct{}), result: make(chan error, 1), cleanup: cleanup.err},
						closing: make(chan struct{}), release: make(chan struct{})}
					return wire
				})
				release := sync.OnceFunc(func() { close(wire.release) })
				defer release()
				observed, ended := make(chan error, 1), make(chan error, 1)
				claimed.endObservation = func(err error, expected bool) {
					if !expected {
						observed <- err
					}
				}
				slots, err := tunnel.NewSlots(t.Context(), tunnel.SlotsConfig{SingleUse: true,
					Connect:      func(context.Context, uint8, bool) (tunnel.SlotSession, error) { return claimed, nil },
					SessionEnded: func(_ uint8, _ tunnel.SlotSession, err error) { ended <- err }})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { release(); _ = slots.Close() })
				if err := slots.Set(0, bound.assignmentKey(0)); err != nil {
					t.Fatal(err)
				}
				waitDispatcherQUICCleanupSlot(t, slots, claimed)
				claimedAwait(t, wire.entered)
				wire.result <- lost
				claimedAwait(t, wire.closing)
				select {
				case err := <-ended:
					t.Fatal("slot retired before its physical cleanup joined", err)
				default:
				}
				release()
				serveErr := claimedAwait(t, ended)
				observation := claimedAwait(t, observed)
				for name, result := range map[string]error{"serve": serveErr, "observation": observation, "dispatcher result": claimed.dispatcher.Close()} {
					if !errors.Is(result, lost) || !errors.Is(result, operation.err) {
						t.Error(name, "lost the exact transport-loss operation", result)
					}
				}
				waitDispatcherQUICCleanupSlot(t, slots, nil)
				claimErr, slotsErr := claimed.Close(), slots.Close()
				for name, result := range map[string]error{"claimed cleanup": claimErr, "retired slots cleanup": slotsErr} {
					if errors.Is(result, lost) {
						t.Error(name, "cached the accept operation as owned cleanup", result)
					}
					if cleanup.err == nil {
						if result != nil {
							t.Error(name, "manufactured cleanup failure after transport loss", result)
						}
					} else if !errors.Is(result, cleanup.err) {
						t.Error(name, "discarded the exact physical cleanup result", result)
					}
				}
				if cleanup.err != nil && (!errors.Is(serveErr, cleanup.err) || !errors.Is(observation, cleanup.err)) {
					t.Error("serving or observation discarded the independent cleanup result", serveErr, observation)
				}
				if wire.closes.Load() != 1 || claimed.Close() != claimErr || slots.Close() != slotsErr {
					t.Error("retired cleanup was not joined once and cached unchanged", wire.closes.Load())
				}
			})
		}
	}
}
