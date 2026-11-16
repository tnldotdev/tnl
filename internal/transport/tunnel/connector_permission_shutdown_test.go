package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this characterizes the current owner behavior, not a proposed graceful EOF
// implementation: ordered completion dispatch is followed by failure and reset.
func TestConnectorPermissionShutdownRequestEOFFailsAfterOrderedCompletions(t *testing.T) {
	client, server := realTunnelPair(t, "quic")
	writer, control := permissionControlPair(t, client.transport, server.transport)
	ctx := tunnelContext(t)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	completed := make(chan tunnelv1.ConnectorVisitorCompletion, 2)
	failed := make(chan struct{}, 1)
	reset := make(chan struct{}, 1)
	observed := permissionShutdownStream{Stream: control, reset: reset}
	var suspension ConnectorPermissionGate
	done := tunnelWorker(t, func() { unblock(); _ = control.Reset(0) }, func() error {
		handlers := &permissionTestHandlers{ctx: ctx, rawOnly: true,
			update: func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) {
				t.Error("shutdown renewed permission")
			},
			completed: func(receipt tunnelv1.ConnectorVisitorCompletion) {
				completed <- receipt
				if receipt.VisitorConnectionID == "vc_aaaaaaaaaaaaaaaaaaaaaa" {
					// hold the actual dispatch callback to prove that neither the
					// next completion nor request EOF can overtake its return.
					select {
					case <-release:
					case <-ctx.Done():
					}
				}
			}, failed: func() { failed <- struct{}{} }}
		return ServeConnectorPermissionControl(ctx, observed, permissionControlScope(), handlers, &suspension)
	})
	first := tunnelv1.ConnectorVisitorCompletion{Kind: tunnelv1.ConnectorVisitorCompleted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, TerminalNumber: 1}
	second := first
	second.VisitorConnectionID = "vc_bbbbbbbbbbbbbbbbbbbbbb"
	second.TerminalNumber = 2
	for _, receipt := range []tunnelv1.ConnectorVisitorCompletion{first, second} {
		// this causal control tests dispatch versus EOF, not matched completion.
		if err := tunnelv1.WriteConnectorVisitorCompletion(writer.stream, receipt); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := permissionShutdownAwait(t, ctx, completed); got != first {
		t.Fatal("first completion changed identity", got)
	}
	permissionShutdownPending(t, completed, "second dispatch overtook the first callback")
	permissionShutdownPending(t, failed, "EOF overtook completion dispatch")
	permissionShutdownPending(t, reset, "EOF reset control before dispatch returned")
	unblock()
	if got := permissionShutdownAwait(t, ctx, completed); got != second {
		t.Fatal("second completion changed identity", got)
	}
	permissionShutdownAwait(t, ctx, failed)
	if err := permissionShutdownAwait(t, ctx, done); err != io.EOF {
		t.Fatal("clean frame-boundary EOF did not reach the current failure path", err)
	}
	permissionShutdownAwait(t, ctx, reset)
	permissionShutdownAwait(t, ctx, writer.Done())
	var remoteReset *quic.StreamError
	if !errors.As(writer.Err(), &remoteReset) || !remoteReset.Remote || remoteReset.ErrorCode != 0 {
		t.Fatal("current response worker did not end from remote stream reset", writer.Err())
	}
	if ctx.Err() != nil {
		t.Fatal("request EOF was confused with local owner cancellation", context.Cause(ctx))
	}
}

// exact EOF is a frame-boundary event. a complete length header with no payload
// is truncation, just like a partial header or payload.
func TestConnectorPermissionShutdownTruncatedFrameIsNotCleanEOF(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 8)
	for _, direction := range []string{"request", "response"} {
		for _, test := range []struct {
			name string
			wire []byte
			want error
		}{
			{name: "between-frames", want: io.EOF},
			{name: "partial-header", wire: []byte{0, 0}, want: io.ErrUnexpectedEOF},
			{name: "complete-header-no-payload", wire: header[:], want: io.ErrUnexpectedEOF},
			{name: "partial-payload", wire: append(append([]byte(nil), header[:]...), '{'), want: io.ErrUnexpectedEOF},
		} {
			t.Run(direction+"/"+test.name, func(t *testing.T) {
				ctx := tunnelContext(t)
				sender, receiver := permissionShutdownQUICStream(t, ctx)
				if len(test.wire) != 0 {
					if n, err := sender.Write(test.wire); err != nil || n != len(test.wire) {
						t.Fatal("truncation setup write", n, err)
					}
				}
				if err := sender.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				var err error
				if direction == "request" {
					_, err = tunnelv1.ReadConnectorControlMessage(receiver)
				} else {
					_, err = tunnelv1.ReadConnectorPermissionResult(receiver)
				}
				if err != test.want {
					t.Fatalf("%s decode after %d frame bytes: got %v, want %v; exact EOF must mean no next header was consumed", direction, len(test.wire), err, test.want)
				}
			})
		}
	}
}

func TestConnectorPermissionShutdownKeepsIndependentEOFReadFailure(t *testing.T) {
	client, server := realTunnelPair(t, "quic")
	writer, control := permissionControlPair(t, client.transport, server.transport)
	ctx := tunnelContext(t)
	independent := errors.New("independent permission control read failure")
	failed := make(chan struct{}, 1)
	observed := permissionShutdownStream{Stream: control, eofFailure: independent}
	var suspension ConnectorPermissionGate
	done := tunnelWorker(t, func() { _ = control.Reset(0) }, func() error {
		return servePermissionTestControl(ctx, observed,
			func(tunnelv1.ConnectorPermissionUpdate, *ConnectorPermissionResponder) {
				t.Error("EOF dispatched renewal")
			},
			func(tunnelv1.ConnectorVisitorCompletion) { t.Error("EOF fabricated completion") },
			func() { failed <- struct{}{} }, &suspension)
	})
	if err := writer.stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	err := permissionShutdownAwait(t, ctx, done)
	if !errors.Is(err, io.EOF) || !errors.Is(err, context.Canceled) || !errors.Is(err, independent) {
		t.Fatal("EOF or cancellation erased an independent reader failure", err)
	}
	permissionShutdownAwait(t, ctx, failed)
	if ctx.Err() != nil {
		t.Fatal("fixture deadline caused the reader failure", context.Cause(ctx))
	}
}

type permissionShutdownStream struct {
	muxsession.Stream
	reset      chan struct{}
	eofFailure error
}

func (s permissionShutdownStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	if err == io.EOF && s.eofFailure != nil {
		err = errors.Join(err, context.Canceled, s.eofFailure)
	}
	return n, err
}

func (s permissionShutdownStream) Reset(code uint32) error {
	err := s.Stream.Reset(code)
	if s.reset != nil {
		select {
		case s.reset <- struct{}{}:
		default:
		}
	}
	return err
}

func permissionShutdownQUICStream(t *testing.T, ctx context.Context) (muxsession.Stream, muxsession.Stream) {
	t.Helper()
	client, server := realTunnelPair(t, "quic")
	sender, err := client.transport.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Reset(0) })
	// make the real stream visible before the empty-frame EOF control. this
	// preface is consumed here and is never part of the framing decoder input.
	if _, err := sender.Write([]byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	receiver, err := server.transport.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receiver.Reset(0) })
	until, _ := ctx.Deadline()
	if err := errors.Join(sender.SetDeadline(until), receiver.SetDeadline(until)); err != nil {
		t.Fatal(err)
	}
	var preface [1]byte
	if _, err := io.ReadFull(receiver, preface[:]); err != nil || preface != [1]byte{0x7f} {
		t.Fatal("stream visibility preface", preface, err)
	}
	return sender, receiver
}

func permissionShutdownAwait[T any](t *testing.T, ctx context.Context, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-ctx.Done():
		t.Fatal("permission shutdown exceeded its original deadline", context.Cause(ctx))
		var zero T
		return zero
	}
}

func permissionShutdownPending[T any](t *testing.T, result <-chan T, message string) {
	t.Helper()
	select {
	case value := <-result:
		t.Fatal(message, value)
	default:
	}
}
