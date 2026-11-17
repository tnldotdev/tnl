package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublisherRejectionPreservesEveryFailedBoundary(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, boundary := range []string{"cleanup", "write", "half close", "read end", "trailing byte", "deadline setup", "canceled read", "terminal reset", "terminal independent", "terminal normal with independent"} {
			t.Run(map[bool]string{false: "client", true: "server"}[server]+"/"+boundary, func(t *testing.T) {
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				step, cleanup, auth := errors.New("independent exchange failure"), errors.New("independent cleanup failure"), errors.New("authorization rejected")
				message := tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: tunnelv1.StaleConnectionAssignment}
				if server {
					message = publisherHello()
				}
				control := newPublisherRejectionFaultStream(t, message)
				session := newPublisherRejectionFaultSession(control)
				session.closeErr = errors.Join(context.Canceled, cleanup)
				wantStep, wantReset := false, false
				switch boundary {
				case "write":
					control.writeErr = errors.Join(context.Canceled, step)
					wantStep = true
				case "half close":
					control.halfCloseErr = errors.Join(context.Canceled, step)
					wantStep = true
				case "read end":
					control.end = func([]byte) (int, error) { return 0, errors.Join(io.EOF, step) }
					wantStep = true
				case "trailing byte":
					control.end = func(p []byte) (int, error) { p[0] = 1; return 1, step }
					wantStep = true
				case "deadline setup":
					control.deadlineErr = step
					wantStep = true
				case "canceled read":
					control.end = func([]byte) (int, error) {
						cancel(context.Canceled)
						return 0, errors.Join(context.Canceled, step)
					}
					wantStep = true
				case "terminal reset":
					reset := fmt.Errorf("%w: connection closed: %w", yamux.ErrStreamReset, io.EOF)
					if server {
						control.end = func([]byte) (int, error) { return 0, reset }
					} else {
						session.endErr = reset
					}
					wantReset = true
				case "terminal independent":
					end := errors.Join(io.EOF, step)
					if server {
						control.end = func([]byte) (int, error) { return 0, end }
					} else {
						session.endErr = end
					}
					wantStep = true
				case "terminal normal with independent":
					end := errors.Join(&quic.ApplicationError{Remote: true}, step)
					if server {
						control.end = func([]byte) (int, error) { return 0, end }
					} else {
						session.endErr = end
					}
					wantStep = true
				}
				var err error
				if server {
					_, _, err = Accept(ctx, session, func(context.Context, tunnelv1.Message) error {
						return errors.Join(auth, &ProtocolError{Code: tunnelv1.StaleConnectionAssignment})
					})
				} else {
					var accepted *Session
					accepted, err = Dial(ctx, session, publisherHello())
					if accepted != nil {
						t.Fatal("rejection exposed an accepted session")
					}
				}
				if !errors.Is(err, cleanup) || !errors.Is(err, context.Canceled) || session.closes.Load() != 1 ||
					errors.Is(err, step) != wantStep || errors.Is(err, yamux.ErrStreamReset) != wantReset {
					t.Fatalf("lost an exchange/cleanup cause or its single owner: err=%v closes=%d", err, session.closes.Load())
				}
				var protocol *ProtocolError
				if (server || boundary != "write") && (!errors.As(err, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment) {
					t.Fatal("exchange or cleanup failure replaced the exact rejection", err)
				}
				if server && !errors.Is(err, auth) {
					t.Fatal("delivery failure replaced the authorization cause", err)
				}
			})
		}
	}
}

func TestPublisherPreFrameFailureCannotAcquireRejectionCompletion(t *testing.T) {
	for _, end := range []error{io.EOF, errors.Join(io.EOF, yamux.ErrStreamReset), errors.Join(io.EOF, context.Canceled)} {
		for _, prefix := range [][]byte{nil, {0}, {0, 0, 0, 1}} {
			control := &publisherRejectionFaultStream{reader: bytes.NewReader(prefix)}
			control.end = func([]byte) (int, error) { return 0, end }
			session := newPublisherRejectionFaultSession(control)
			_, err := Dial(t.Context(), session, publisherHello())
			want := io.EOF
			if len(prefix) == 4 || len(prefix) != 0 && end == io.EOF {
				want = io.ErrUnexpectedEOF
			}
			if !errors.Is(err, want) || end != io.EOF && !errors.Is(err, end) ||
				session.endChecks.Load() != 0 || control.halfCloses.Load() != 0 || session.closes.Load() != 1 {
				t.Fatal("incomplete rejection acquired decoded-exchange provenance", err)
			}
		}
	}
}

func TestPublisherRejectionAcknowledgementJoinsBothEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := newPublisherRejectionFaultStream(t, tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: tunnelv1.StaleConnectionAssignment})
		session := newPublisherRejectionFaultSession(control)
		fin, acknowledgement := make(chan struct{}), make(chan struct{})
		release := sync.OnceFunc(func() { close(fin) })
		control.end = func([]byte) (int, error) { <-fin; return 0, io.EOF }
		control.finished = func() { close(acknowledgement) }
		done := tunnelWorker(t, func() { release(); session.end() }, func() error {
			_, err := Dial(t.Context(), session, publisherHello())
			return err
		})
		synctest.Wait()
		if control.halfCloses.Load() != 0 || session.closes.Load() != 0 {
			t.Fatal("decoded rejection acknowledged before the server's FIN was received")
		}
		release()
		<-acknowledgement
		synctest.Wait()
		if session.closes.Load() != 0 {
			t.Fatal("queued acknowledgement FIN was treated as physical delivery")
		}
		select {
		case err := <-done:
			t.Fatal("publisher returned without joining the responder's session end", err)
		default:
		}
		session.end()
		err := await(t, done)
		var protocol *ProtocolError
		if !errors.As(err, &protocol) || protocol.Code != tunnelv1.StaleConnectionAssignment || !failure.Only(err, protocol) || session.closes.Load() != 1 {
			t.Fatal("completed rejection gained an independent failure or lost its cleanup owner", err)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		control := newPublisherRejectionFaultStream(t, publisherHello())
		session := newPublisherRejectionFaultSession(control)
		fin := make(chan struct{})
		release := sync.OnceFunc(func() { close(fin) })
		control.end = func([]byte) (int, error) { <-fin; return 0, io.EOF }
		control.finished = nil
		cause := errors.New("authorization rejected")
		rejection := errors.Join(cause, &ProtocolError{Code: tunnelv1.StaleConnectionAssignment})
		done := tunnelWorker(t, release, func() error {
			_, _, err := Accept(t.Context(), session, func(context.Context, tunnelv1.Message) error { return rejection })
			return err
		})
		synctest.Wait()
		if control.halfCloses.Load() != 1 || session.closes.Load() != 0 {
			t.Fatal("responder treated its queued rejection FIN as the publisher's acknowledgement")
		}
		release()
		if err := await(t, done); !failure.Only(err, rejection) || session.closes.Load() != 1 {
			t.Fatal("acknowledged rejection lost its authorization cause or joined cleanup", err)
		}
	})
}

func TestPublisherRejectionUsesTheOriginalHandshakeContext(t *testing.T) {
	for _, server := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx := t.Context()
			until := time.Now().Add(handshakeTimeout)
			message := tunnelv1.Message{Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: tunnelv1.StaleConnectionAssignment}
			if server {
				message = publisherHello()
			}
			control := newPublisherRejectionFaultStream(t, message)
			control.observed = make(chan time.Time, 8)
			session := newPublisherRejectionFaultSession(control)
			const spent = handshakeTimeout - 100*time.Millisecond
			if server {
				_, _, err := Accept(ctx, session, func(auth context.Context, _ tunnelv1.Message) error {
					if deadline, _ := auth.Deadline(); !deadline.Equal(until) {
						t.Error("authorization lost the original handshake deadline")
					}
					time.Sleep(spent)
					return &ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
				})
				if err == nil {
					t.Fatal("authorization rejection was accepted")
				}
			} else {
				opened := make(chan time.Time, 1)
				_, err := Dial(ctx, publisherDelayedOpen{publisherRejectionFaultSession: session, spent: spent, opened: opened}, publisherHello())
				if err == nil {
					t.Fatal("publisher accepted a rejection")
				}
				if at := <-opened; !at.Equal(until) {
					t.Fatal("opening the control stream did not spend the original handshake budget", at, until)
				}
			}
			for range 2 {
				if at := <-control.observed; !at.Equal(until) {
					t.Fatal("rejection restarted the handshake budget after earlier work", at, until)
				}
			}
		})
	}
}

func TestPublisherRejectionKeepsOriginalDeadlineAndShortDrainCap(t *testing.T) {
	for _, server := range []bool{false, true} {
		for _, boundary := range []string{"short cap", "short caller", "spent setup"} {
			t.Run(map[bool]string{false: "client", true: "server"}[server]+"/"+boundary, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					budget, spent := time.Hour, time.Duration(0)
					switch boundary {
					case "short caller":
						budget = 20 * time.Millisecond
					case "spent setup":
						budget, spent = handshakeTimeout, handshakeTimeout-100*time.Millisecond
					}
					ctx, cancel := context.WithTimeout(t.Context(), budget)
					defer cancel()
					started := time.Now()
					time.Sleep(spent)
					until := time.Now().Add(rejectionDrainTimeout)
					if original, _ := ctx.Deadline(); original.Before(until) {
						until = original
					}
					client, peer := newMemoryPair(t)
					control, err := client.OpenStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					remote, err := peer.AcceptStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					closeTransport := sync.OnceValue(client.Close)
					done := tunnelWorker(t, func() { _ = closeTransport() }, func() error {
						if server {
							return rejectPublisherHello(ctx, control, tunnelv1.StaleConnectionAssignment, closeTransport)
						}
						return acknowledgePublisherRejection(ctx, client, control, closeTransport)
					})
					if server {
						message, err := tunnelv1.ReadControl(remote)
						if err != nil || message.Code != tunnelv1.StaleConnectionAssignment {
							t.Fatal("uncooperative publisher did not receive its rejection", err)
						}
					} else if err := remote.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					select {
					case err := <-done:
						t.Fatal("uncooperative peer ended before its original bound", err)
					default:
					}
					time.Sleep(time.Until(until))
					err = await(t, done)
					if !errors.Is(err, context.DeadlineExceeded) || !time.Now().Equal(until) || time.Since(started) > budget {
						t.Fatal("rejection restarted or exceeded its original budget", err, time.Since(started), until)
					}
				})
			})
		}
	}
}

func TestPublisherRejectionInterruptJoinsDeadlineAndCloseFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		control := &publisherRejectionFaultStream{reader: bytes.NewReader(nil)}
		deadline, cleanup, operation := errors.New("interrupt deadline failed"), errors.New("interrupt cleanup failed"), errors.New("interrupted operation failed")
		control.interruptErr = deadline
		closed := make(chan struct{})
		closeTransport := sync.OnceValue(func() error { close(closed); return cleanup })
		done := tunnelWorker(t, func() { _ = closeTransport() }, func() error {
			return publisherRejectionExchange(ctx, control, closeTransport, func(context.Context) error {
				<-closed
				return errors.Join(context.Canceled, operation)
			})
		})
		synctest.Wait()
		cancel()
		err := await(t, done)
		for _, cause := range []error{context.Canceled, operation, deadline, cleanup} {
			if !errors.Is(err, cause) {
				t.Fatal("interrupted exchange hid an independent failure", cause, err)
			}
		}
	})
}

func TestPublisherRejectionBoundsHalfCloseThatIgnoresStreamDeadline(t *testing.T) {
	for _, server := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "server"}[server], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
				defer cancel()
				until, _ := ctx.Deadline()
				control := &publisherRejectionFaultStream{reader: bytes.NewReader(nil)}
				cleanup, halfClose := errors.New("physical close failed"), errors.New("queued FIN interrupted")
				closed := make(chan struct{})
				control.halfClose = func() error { <-closed; return halfClose }
				closeTransport := sync.OnceValue(func() error { close(closed); return cleanup })
				session := newPublisherRejectionFaultSession(control)
				done := tunnelWorker(t, func() { _ = closeTransport() }, func() error {
					if server {
						return rejectPublisherHello(ctx, control, tunnelv1.StaleConnectionAssignment, closeTransport)
					}
					return acknowledgePublisherRejection(ctx, session, control, closeTransport)
				})
				synctest.Wait()
				time.Sleep(time.Until(until))
				err := await(t, done)
				for _, cause := range []error{context.DeadlineExceeded, halfClose, cleanup} {
					if !errors.Is(err, cause) {
						t.Fatal("blocked FIN lost its original fence or joined cleanup", cause, err)
					}
				}
				if !time.Now().Equal(until) {
					t.Fatal("FIN queueing outlived the original caller deadline")
				}
			})
		})
	}
}

type publisherRejectionFaultSession struct {
	muxsession.Session
	control   *publisherRejectionFaultStream
	done      chan struct{}
	end       func()
	endErr    error
	closeErr  error
	closes    atomic.Int32
	endChecks atomic.Int32
}

type publisherDelayedOpen struct {
	*publisherRejectionFaultSession
	spent  time.Duration
	opened chan time.Time
}

func (s publisherDelayedOpen) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	deadline, _ := ctx.Deadline()
	s.opened <- deadline
	time.Sleep(s.spent)
	return s.publisherRejectionFaultSession.OpenStream(ctx)
}

func newPublisherRejectionFaultSession(control *publisherRejectionFaultStream) *publisherRejectionFaultSession {
	s := &publisherRejectionFaultSession{control: control, done: make(chan struct{}), endErr: io.EOF}
	s.end = sync.OnceFunc(func() { close(s.done) })
	control.finished = s.end
	return s
}

func (s *publisherRejectionFaultSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return s.control, nil
}
func (s *publisherRejectionFaultSession) AcceptStream(context.Context) (muxsession.Stream, error) {
	return s.control, nil
}
func (s *publisherRejectionFaultSession) Close() error {
	s.closes.Add(1)
	s.end()
	return s.closeErr
}
func (s *publisherRejectionFaultSession) Done() <-chan struct{} { return s.done }
func (s *publisherRejectionFaultSession) Err() error {
	s.endChecks.Add(1)
	return s.endErr
}

type publisherRejectionFaultStream struct {
	muxsession.Stream
	reader       *bytes.Reader
	end          func([]byte) (int, error)
	writeErr     error
	halfCloseErr error
	deadlineErr  error
	interruptErr error
	halfClose    func() error
	finished     func()
	deadlines    atomic.Int32
	halfCloses   atomic.Int32
	observed     chan time.Time
}

func newPublisherRejectionFaultStream(t *testing.T, message tunnelv1.Message) *publisherRejectionFaultStream {
	t.Helper()
	var wire bytes.Buffer
	if err := tunnelv1.WriteControl(&wire, message); err != nil {
		t.Fatal(err)
	}
	return &publisherRejectionFaultStream{reader: bytes.NewReader(wire.Bytes())}
}

func (s *publisherRejectionFaultStream) Read(p []byte) (int, error) {
	if s.reader.Len() != 0 {
		return s.reader.Read(p)
	}
	if s.end != nil {
		return s.end(p)
	}
	return 0, io.EOF
}
func (s *publisherRejectionFaultStream) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	return len(p), nil
}
func (s *publisherRejectionFaultStream) CloseWrite() error {
	s.halfCloses.Add(1)
	if s.halfClose != nil {
		return s.halfClose()
	}
	if s.halfCloseErr != nil {
		return s.halfCloseErr
	}
	if s.finished != nil {
		s.finished()
	}
	return nil
}
func (s *publisherRejectionFaultStream) SetDeadline(at time.Time) error {
	if s.observed != nil {
		s.observed <- at
	}
	call := s.deadlines.Add(1)
	if !at.After(time.Now()) && s.interruptErr != nil {
		return s.interruptErr
	}
	if call == 2 {
		return s.deadlineErr
	}
	return nil
}

func TestPublisherMemoryHalfCloseKeepsReverseDirection(t *testing.T) {
	client, server := newMemoryPair(t)
	local, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := server.AcceptStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := local.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var p [1]byte
	if n, err := peer.Read(p[:]); n != 0 || err != io.EOF {
		t.Fatal("half-close did not end only the sending direction", n, err)
	}
	write := tunnelWorker(t, func() { _ = server.Close() }, func() error { _, err := peer.Write([]byte{1}); return err })
	if n, err := local.Read(p[:]); n != 1 || err != nil || p[0] != 1 {
		t.Fatal("half-close also closed the reverse direction", n, err)
	}
	if err := await(t, write); err != nil {
		t.Fatal(err)
	}
}

// keep independent native deadline errors distinct from the exchange's context
// deadline in fault assertions; neither is an allowed post-rejection close.
func TestPublisherRejectionEndDoesNotSuppressJoinedEOF(t *testing.T) {
	for _, cause := range []error{os.ErrDeadlineExceeded, context.Canceled, yamux.ErrStreamReset, errors.New("independent read failed")} {
		control := &publisherRejectionFaultStream{reader: bytes.NewReader(nil), end: func([]byte) (int, error) { return 0, errors.Join(io.EOF, cause) }}
		err := publisherRejectionEnd(control, "test")
		if err == nil || !errors.Is(err, cause) || !errors.Is(err, io.EOF) || failure.Only(err, io.EOF) {
			t.Fatal("joined EOF acquired normal rejection-end provenance", err)
		}
	}
}
