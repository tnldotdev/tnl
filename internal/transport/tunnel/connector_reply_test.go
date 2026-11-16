package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type connectorReplySession struct {
	muxsession.Session
	done chan struct{}
	err  error
}

func (s connectorReplySession) Done() <-chan struct{} { return s.done }
func (s connectorReplySession) Err() error            { return s.err }

func TestConnectorReplyEndRequiresPreCleanupSessionEvidence(t *testing.T) {
	normal := errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
	independent := errors.New("independent operation")
	for _, test := range []struct {
		name      string
		ended     bool
		session   error
		operation error
		want      bool
	}{
		{"ended normally", true, normal, normal, true},
		{"still live", false, normal, normal, false},
		{"no session cause", true, nil, normal, false},
		{"abnormal session", true, &quic.ApplicationError{ErrorCode: 1}, normal, false},
		{"independent session cause", true, errors.Join(normal, independent), normal, false},
		{"independent read cause", true, normal, errors.Join(normal, independent), false},
		{"stream reset", true, normal, &quic.StreamError{}, false},
		{"EOF", true, normal, io.EOF, false},
		{"cancellation", true, normal, errors.Join(normal, context.Canceled), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := connectorReplySession{done: make(chan struct{}), err: test.session}
			if test.ended {
				close(s.done)
			}
			if got := connectorReplySessionEnded(s, test.operation); got != test.want {
				t.Fatalf("pre-cleanup evidence=%t, want %t", got, test.want)
			}
			if !test.ended {
				// later owned cleanup cannot change the captured observation.
				before := connectorReplySessionEnded(s, test.operation)
				close(s.done)
				if before {
					t.Fatal("local close manufactured earlier session-end evidence")
				}
			}
		})
	}
}

func TestConnectorReplyEndEvidenceBelongsToExactResult(t *testing.T) {
	cause := errors.Join(muxsession.ErrClosed, &quic.ApplicationError{Remote: true})
	observed := connectorReplyResult(cause, true)
	if !ConnectorReplyEndedNormally(observed) || !errors.Is(observed, cause) {
		t.Fatal("exact reply result lost its evidence or cause", observed)
	}
	for _, err := range []error{
		nil, cause, connectorReplyResult(cause, false),
		fmt.Errorf("unowned operation: %w", observed),
		errors.Join(observed), errors.Join(observed, errors.New("independent failure")),
		&SessionCleanupError{Err: observed},
	} {
		if ConnectorReplyEndedNormally(err) {
			t.Fatal("reply evidence escaped into an unrelated or failed-cleanup result", err)
		}
	}
}
