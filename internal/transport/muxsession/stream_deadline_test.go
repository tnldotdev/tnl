package muxsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
)

type streamDeadlineMatchingHook struct{}

func (streamDeadlineMatchingHook) Error() string        { return "unknown timeout" }
func (streamDeadlineMatchingHook) Is(target error) bool { return target == os.ErrDeadlineExceeded }
func (streamDeadlineMatchingHook) Timeout() bool        { return true }
func (streamDeadlineMatchingHook) Temporary() bool      { return true }

func TestStreamDeadlineOnlyPreservesIndependentFailures(t *testing.T) {
	for _, err := range []error{
		os.ErrDeadlineExceeded, yamux.ErrTimeout, fmt.Errorf("read: %w", yamux.ErrTimeout),
		errors.Join(os.ErrDeadlineExceeded, yamux.ErrTimeout),
	} {
		if !StreamDeadlineOnly(err) {
			t.Error("a known native stream deadline lost its identity", err)
		}
	}
	for _, err := range []error{
		nil, context.Canceled, context.DeadlineExceeded, net.ErrClosed, streamDeadlineMatchingHook{},
		&quic.IdleTimeoutError{}, &quic.StreamError{}, &quic.ApplicationError{},
		&QUICTransportCloseError{Err: os.ErrDeadlineExceeded},
		errors.Join(yamux.ErrTimeout, errors.New("independent read failure")),
	} {
		if StreamDeadlineOnly(err) {
			t.Error("an unknown timeout, cancellation, or cleanup gained native deadline classification", err)
		}
	}
}

func TestYamuxStreamDeadlineRetainsNativeErrorWithoutClosingSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, right := net.Pipe()
	client, err := newYamuxSession(left, true, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := newYamuxSession(right, false, 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.AcceptStream(ctx); err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, readErr := stream.Read(make([]byte, 1))
	_, writeErr := stream.Write([]byte("expired"))
	for _, err := range []error{readErr, writeErr} {
		if err != yamux.ErrTimeout || !StreamDeadlineOnly(err) || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("native yamux i/o did not retain its distinct exact deadline error", err)
		}
	}
	if client.Err() != nil || server.Err() != nil {
		t.Fatal("a stream deadline ended its shared session", client.Err(), server.Err())
	}
}
