package stream

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

type directFixtureSessionState struct {
	muxsession.Session
	done chan struct{}
	err  error
}

func (s directFixtureSessionState) Done() <-chan struct{} { return s.done }
func (s directFixtureSessionState) Err() error            { return s.err }

type directFixtureReadFailure struct {
	muxsession.Stream
	err error
}

func (s directFixtureReadFailure) Read([]byte) (int, error) { return 0, s.err }

func TestConnectorDirectFixturePacketLifetimeSurvivesTestCancellation(t *testing.T) {
	budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
	defer finish()
	until, _ := budget.Deadline()
	life, closeLife := directShutdownLifetime(budget, until)
	defer closeLife()
	finish()
	if life.Err() != nil {
		t.Error("test cancellation destroyed packet ownership before session cleanup")
	}
	if got, ok := life.Deadline(); !ok || got != until {
		t.Error("fixture packet lifetime changed the original five-second bound")
	}
	closeLife()
	if life.Err() != context.Canceled {
		t.Error("the fixture lost its explicit packet stop")
	}
}

func TestConnectorDirectControlRetiresOnlyItsOwnedNormalSessionEnd(t *testing.T) {
	for _, kind := range []string{"owned normal close", "not closing", "live session", "different session", "closed sentinel only", "transport close", "independent read failure", "typed cleanup", "stream reset"} {
		t.Run(kind, func(t *testing.T) {
			application := &quic.ApplicationError{Remote: true}
			normal := errors.Join(muxsession.ErrClosed, application)
			state := directFixtureSessionState{done: make(chan struct{}), err: normal}
			var closing atomic.Bool
			closing.Store(kind != "not closing")
			var operation error = normal
			switch kind {
			case "different session":
				state.err = errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
			case "closed sentinel only":
				operation = muxsession.ErrClosed
			case "transport close":
				operation = quic.ErrTransportClosed
			case "independent read failure":
				operation = errors.Join(normal, errors.New("independent control read failure"))
			case "typed cleanup":
				operation = errors.Join(normal, &tunnel.SessionCleanupError{Err: context.Canceled})
			case "stream reset":
				operation = &quic.StreamError{Remote: true}
			}
			if kind != "live session" {
				close(state.done)
			}
			retired := false
			control := &directShutdownControlStream{Stream: directFixtureReadFailure{err: operation},
				session: state, closing: &closing, retire: func() { retired = true }}
			_, err := control.Read(make([]byte, 1))
			if err != operation || retired != (kind == "owned normal close") {
				t.Error("fixture changed a physical error or borrowed another session's stop provenance", err, retired)
			}
		})
	}
}
