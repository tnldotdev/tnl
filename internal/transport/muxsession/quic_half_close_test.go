package muxsession

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	quic "github.com/quic-go/quic-go"
)

// each operation gets a fresh native stream. a failed quic-go send close marks
// finishedWriting, so a later close is not an independent comparison.
func TestQUICStreamFullAndHalfCloseAfterSendStop(t *testing.T) {
	for _, remote := range []bool{true, false} {
		for _, code := range []quic.StreamErrorCode{0, 17} {
			for _, half := range []bool{false, true} {
				t.Run(fmt.Sprintf("remote=%t/code=%d/half=%t", remote, code, half), func(t *testing.T) {
					outbound, inbound := halfCloseQUICStreams(t)
					if remote {
						inbound.Stream.CancelRead(code)
					} else {
						outbound.Stream.CancelWrite(code)
					}
					send := outbound.Stream.Context()
					muxAwait(t, send.Done())
					var stopped *quic.StreamError
					if !errors.As(context.Cause(send), &stopped) || stopped.Remote != remote ||
						stopped.ErrorCode != code || stopped.StreamID != outbound.Stream.StreamID() {
						t.Fatal("send stop did not belong to this exact native stream")
					}
					var result error
					if half {
						result = outbound.CloseWrite()
					} else {
						result = outbound.Close()
					}
					// full close keeps its existing local-reset policy. half-close
					// succeeds only for the peer's normal stop, not a local abort.
					normal := remote && code == 0 || !half && !remote
					if normal {
						if result != nil {
							t.Fatalf("observed normal stop introduced a close failure: error_type=%T", result)
						}
						return
					}
					var reset *quic.StreamError
					if !errors.As(result, &reset) || reset.Remote != remote || reset.ErrorCode != code ||
						reset.StreamID != outbound.Stream.StreamID() || !errors.Is(result, stopped) {
						t.Fatalf("send close lost its exact abnormal or local stop: error_type=%T", result)
					}
				})
			}
		}
	}
}

func TestQUICStreamHalfCloseRequiresANativeFailureBeforeUsingSendCause(t *testing.T) {
	outbound, inbound := halfCloseQUICStreams(t)
	inbound.Stream.CancelRead(17)
	send := outbound.Stream.Context()
	muxAwait(t, send.Done())
	var stopped *quic.StreamError
	if !errors.As(context.Cause(send), &stopped) || !stopped.Remote || stopped.ErrorCode != 17 {
		t.Fatal("native send did not observe the abnormal peer stop")
	}
	// consume that native failure directly. quic-go has now marked this send
	// finished, so the next native close succeeds despite the stored cause.
	if err := outbound.Stream.Close(); err == nil {
		t.Fatal("first native close did not observe the canceled send")
	}
	if err := outbound.CloseWrite(); err != nil {
		t.Fatal("stored context cause replaced an actually successful native close", err)
	}
}

func TestQUICStreamHalfCloseWithoutSendStopKeepsCleanEOF(t *testing.T) {
	outbound, inbound := halfCloseQUICStreams(t)
	if cause := context.Cause(outbound.Stream.Context()); cause != nil {
		t.Fatal("fresh sender already stopped")
	}
	if err := outbound.CloseWrite(); err != nil {
		t.Fatal("clean send half-close failed", err)
	}
	if extra, err := io.ReadAll(inbound); err != nil || len(extra) != 0 {
		t.Fatal("clean half-close changed EOF or application bytes", len(extra), err)
	}
}

func halfCloseQUICStreams(t *testing.T) (*quicStream, *quicStream) {
	t.Helper()
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
	return outbound.(*quicStream), inbound.(*quicStream)
}
