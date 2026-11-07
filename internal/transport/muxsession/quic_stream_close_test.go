package muxsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	quic "github.com/quic-go/quic-go"
)

func TestQUICClosureNormalizationPreservesFailures(t *testing.T) {
	for _, cause := range []error{
		&quic.ApplicationError{ErrorCode: 7, Remote: true},
		&quic.TransportError{ErrorCode: 1, Remote: true},
		&quic.IdleTimeoutError{}, &quic.HandshakeTimeoutError{}, &quic.StatelessResetError{},
		&quic.StreamError{ErrorCode: 0, Remote: true}, &quic.StreamError{ErrorCode: 17, Remote: true},
		context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF,
	} {
		t.Run(fmt.Sprintf("%T/%v", cause, cause), func(t *testing.T) {
			wrapped := fmt.Errorf("stream operation: %w", cause)
			if got := normalizeQUICError(wrapped); got != wrapped || errors.Is(got, ErrClosed) {
				t.Fatal("normal closure classification hid a transport failure", got)
			}
		})
	}
}

func TestQUICStreamSessionClosureKeepsClassificationAndCause(t *testing.T) {
	for _, code := range []quic.ApplicationErrorCode{0, 7} {
		for _, write := range []bool{false, true} {
			t.Run(map[bool]string{true: "normal", false: "failure"}[code == 0]+"/"+map[bool]string{true: "write", false: "read"}[write], func(t *testing.T) {
				client, server := newQUICPair(t)
				outbound, err := client.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := outbound.Write([]byte("ready")); err != nil {
					t.Fatal(err)
				}
				inbound, err := server.AcceptStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				var ready [5]byte
				if _, err := io.ReadFull(inbound, ready[:]); err != nil {
					t.Fatal(err)
				}
				if err := server.(*quicSession).connection.CloseWithError(code, "fixture"); err != nil {
					t.Fatal(err)
				}
				muxAwait(t, client.Done())
				if write {
					_, err = outbound.Write([]byte("late"))
				} else {
					_, err = outbound.Read(ready[:])
				}
				var application *quic.ApplicationError
				if !errors.As(err, &application) || !application.Remote || application.ErrorCode != code {
					t.Fatal("stream lost its typed session close cause", err)
				}
				if errors.Is(err, ErrClosed) != (code == 0) {
					t.Fatal("stream closure classification differs from session closure", err)
				}
			})
		}
	}
}
