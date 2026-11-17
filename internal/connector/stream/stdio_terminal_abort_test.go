package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func TestStdioTerminalAbortOwnsPublisherStopBeforeReset(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			observed := make(chan error, 4)
			joined := make(chan struct{})
			release := sync.OnceFunc(func() { close(joined) })
			defer release()
			f := newConfiguredConnectorFixture(t, transport, "", func(f *connectorFixture, _ *Config) {
				f.visitorReadResult = func(ctx context.Context, _ error) {
					observed <- context.Cause(ctx)
					<-joined
				}
			})
			local, input := net.Pipe()
			defer input.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Stream(ctx, &ownedStdioPipe{Conn: local}, f.config) }()
			_ = input.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(input, "active stdio"); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(input, make([]byte, len("active stdio"))); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case cause := <-observed:
				if cause != context.Canceled {
					t.Error("stream reset preceded the exact authenticated publisher abort", cause)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("publisher read did not join")
			}
			select {
			case err := <-done:
				t.Fatal("stdio returned before publisher work and terminal confirmation joined", err)
			default:
			}
			release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("confirmed stdio abort did not join cleanly", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stdio did not join its terminal exchange")
			}
		})
	}
}

func TestStdioRemoteResetRequiresJoinedTerminalAbort(t *testing.T) {
	for _, reset := range []error{&quic.StreamError{Remote: true}, &yamux.StreamError{Remote: true}} {
		t.Run(fmt.Sprintf("%T", reset), func(t *testing.T) {
			o := &stdioOperation{stopping: true, expected: true, resetStarted: true, resetOK: true}
			selected := &stdioStream{owner: o}
			o.selected = selected
			if err := selected.result(reset); err != reset {
				t.Fatal("unrequested remote reset acquired local abort provenance", err)
			}
			o.terminalStarted = true
			tagged := selected.result(reset)
			closeErr := fmt.Errorf("TLS close: %w", tagged)
			if o.abortOnly(tagged) || selected.tlsCloseResult(closeErr) != closeErr {
				t.Fatal("unacknowledged terminal abort hid a remote reset", tagged)
			}
			o.terminalOK = true
			if !o.abortOnly(tagged) || selected.tlsCloseResult(closeErr) != nil {
				t.Fatal("exact joined terminal abort lost its remote reset provenance", tagged)
			}
			independent := errors.New("independent cleanup failure")
			joined := errors.Join(closeErr, independent)
			if o.abortOnly(joined) || selected.tlsCloseResult(joined) != joined {
				t.Fatal("joined terminal abort hid an independent cleanup failure", joined)
			}
			o.terminalOK = false
			if o.abortOnly(tagged) || selected.tlsCloseResult(closeErr) != closeErr {
				t.Fatal("failed terminal result became success after reset tagging", tagged)
			}
		})
	}
}

type stdioTerminalReset struct {
	muxsession.Stream
	resets atomic.Int32
}

func (s *stdioTerminalReset) Reset(uint32) error             { s.resets.Add(1); return nil }
func (*stdioTerminalReset) SetReadDeadline(time.Time) error  { return nil }
func (*stdioTerminalReset) SetWriteDeadline(time.Time) error { return nil }

func TestStdioTerminalAbortJoinsOneFailedExchange(t *testing.T) {
	local, input := net.Pipe()
	defer input.Close()
	ctx, cancel := context.WithCancel(t.Context())
	o := newStdioOperation(ctx, local)
	entered, held := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(held) })
	t.Cleanup(func() { release(); cancel(); o.complete(); _ = o.finish(nil) })
	raw := &stdioTerminalReset{}
	selected, err := o.bind(raw)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("exact terminal abort acknowledgment failed")
	var exchanges atomic.Int32
	if err := o.activateWithAbort(selected, func() error {
		exchanges.Add(1)
		close(entered)
		<-held
		return fault
	}); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-o.abortDone
	first := make(chan error, 1)
	go func() {
		first <- o.terminalUse(context.Canceled, func(error) error {
			t.Error("selected abort did not retain its terminal exchange")
			return nil
		})
	}()
	<-entered
	if raw.resets.Load() != 0 {
		t.Fatal("physical reset preceded the authenticated abort result")
	}
	started, done := make(chan struct{}), make(chan error, 1)
	go func() {
		close(started)
		done <- o.terminalUse(context.Canceled, func(error) error {
			exchanges.Add(1)
			return errors.New("duplicate terminal exchange")
		})
	}()
	<-started
	select {
	case err := <-done:
		t.Fatal("terminal result returned before the entered abort joined", err)
	default:
	}
	release()
	result := errors.Join(<-first, <-done)
	o.complete()
	if err := o.finish(result); !errors.Is(err, fault) || exchanges.Load() != 1 || raw.resets.Load() != 1 {
		t.Fatal("terminal acknowledgment failure was hidden, duplicated, or not joined", err, exchanges.Load(), raw.resets.Load())
	}
}
