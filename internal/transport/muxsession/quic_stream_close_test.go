package muxsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/synctest"

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
				if write {
					muxAwait(t, client.Done())
					_, err = outbound.Write([]byte("late"))
				} else {
					_, err = outbound.Read(ready[:])
				}
				if code == 0 {
					select {
					case <-client.Done():
					default:
						t.Fatal("normal stream error preceded the session's terminal observation")
					}
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

func TestQUICStreamNormalErrorJoinsAlreadyDecidedSessionEnd(t *testing.T) {
	for _, cause := range []error{
		&quic.ApplicationError{Remote: true}, &quic.ApplicationError{Remote: true, ErrorCode: 7},
		&quic.StreamError{Remote: true}, context.Canceled, io.ErrUnexpectedEOF,
	} {
		t.Run(fmt.Sprintf("%T/%v", cause, cause), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				done, result := make(chan struct{}), make(chan error, 1)
				go func() { result <- normalizeQUICStreamError(done, cause) }()
				synctest.Wait()
				application, normal := cause.(*quic.ApplicationError)
				normal = normal && application.ErrorCode == 0
				if normal {
					select {
					case <-result:
						t.Fatal("normal stream error escaped before the session end joined")
					default:
					}
					close(done)
				}
				err := <-result
				if !errors.Is(err, cause) || errors.Is(err, ErrClosed) != normal {
					t.Fatal("session-end join changed the operation cause or classification", err)
				}
				if !normal {
					close(done)
				}
			})
		})
	}
}

func TestQUICStreamCloseAfterResetRetainsOnlyAbnormalPeerFailure(t *testing.T) {
	for _, remote := range []bool{false, true} {
		for _, code := range []uint32{0, 17} {
			t.Run(fmt.Sprintf("remote=%t/code=%d", remote, code), func(t *testing.T) {
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
				if remote {
					inbound.(*quicStream).Stream.CancelRead(quic.StreamErrorCode(code))
				} else if err := outbound.Reset(code); err != nil {
					t.Fatal(err)
				}
				muxAwait(t, outbound.(*quicStream).Stream.Context().Done())
				err = outbound.Close()
				if remote && code != 0 {
					var reset *quic.StreamError
					if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != quic.StreamErrorCode(code) {
						t.Fatal("close lost abnormal peer reset", err)
					}
				} else if err != nil {
					t.Fatal("close invented a cleanup failure after reset", err)
				}
			})
		}
	}
}
