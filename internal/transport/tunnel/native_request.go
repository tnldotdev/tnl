package tunnel

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativeRequestWriter serializes visitor data and independent permission updates
// on the outer native request stream. return bytes remain owned by its caller.
type NativeRequestWriter struct {
	net.Conn
	mu      chan struct{}
	renewMu chan struct{}
	ended   bool
	err     error
	opening func([]byte) error
}

var _ net.Conn = (*NativeRequestWriter)(nil)

func NewNativeRequestWriter(conn net.Conn) *NativeRequestWriter {
	return &NativeRequestWriter{Conn: conn, mu: make(chan struct{}, 1), renewMu: make(chan struct{}, 1)}
}

// NewNativeOpeningWriter sends one signed opening with the first bounded data
// block. it never waits for return bytes before forwarding the request. callers
// with server-first protocols send an empty opening before constructing a writer.
func NewNativeOpeningWriter(conn net.Conn, opening func([]byte) error) *NativeRequestWriter {
	writer := NewNativeRequestWriter(conn)
	writer.opening = opening
	return writer
}

func (s *NativeRequestWriter) startLocked(initial []byte) error {
	if s.opening != nil && s.err == nil {
		opening := s.opening
		s.opening = nil
		s.err = opening(initial)
	}
	return s.err
}

func (s *NativeRequestWriter) Write(p []byte) (int, error) {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	if s.ended {
		return 0, io.ErrClosedPipe
	}
	if s.err != nil {
		return 0, s.err
	}
	written := 0
	if s.opening != nil && len(p) > 0 {
		n := min(len(p), tunnelv1.MaxInitialBytes)
		if err := s.startLocked(p[:n]); err != nil {
			return 0, err
		}
		written, p = n, p[n:]
	}
	for len(p) > 0 {
		n := min(len(p), tunnelv1.MaxInitialBytes)
		s.err = tunnelv1.WriteNativeRequestFrame(s.Conn, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestData, Data: p[:n]})
		if s.err != nil {
			return written, s.err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (s *NativeRequestWriter) Renew(permission tunnelv1.NativeVisitorPermission) error {
	return s.renew(permission, time.Time{})
}

// RenewUntil bounds the entire renewal write and restores the outer deadline
// under the same gates as application writes and TLS half-close. the deadline
// belongs to this refresh, not a new budget for each active stream.
func (s *NativeRequestWriter) RenewUntil(permission tunnelv1.NativeVisitorPermission, until time.Time) error {
	if until.IsZero() || !until.After(time.Now()) {
		return os.ErrDeadlineExceeded
	}
	return s.renew(permission, until)
}

func (s *NativeRequestWriter) renew(permission tunnelv1.NativeVisitorPermission, until time.Time) (result error) {
	// both gates share the refresh deadline. a stalled application write or TLS
	// half-close cannot make permission refresh wait beyond its original budget.
	for _, gate := range []chan struct{}{s.renewMu, s.mu} {
		if until.IsZero() {
			gate <- struct{}{}
		} else {
			if !until.After(time.Now()) {
				return os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(time.Until(until))
			select {
			case gate <- struct{}{}:
				timer.Stop()
			case <-timer.C:
				return os.ErrDeadlineExceeded
			}
		}
		defer func() { <-gate }()
	}
	if !until.IsZero() {
		if !until.After(time.Now()) {
			return os.ErrDeadlineExceeded
		}
		if err := s.Conn.SetWriteDeadline(until); err != nil {
			return err
		}
		defer func() { result = errors.Join(result, s.Conn.SetWriteDeadline(time.Time{})) }()
	}
	if err := s.startLocked(nil); err != nil {
		return err
	}
	s.err = tunnelv1.WriteNativeRequestFrame(s.Conn, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestPermission, Permission: permission})
	return s.err
}

// CloseTLSWrite keeps the outer native stream writable after TLS close_notify.
// crypto/tls sets the underlying write deadline to now when it sends the alert;
// serialize that transition with renewals and restore the outer stream deadline.
func (s *NativeRequestWriter) CloseTLSWrite(secured interface{ CloseWrite() error }) error {
	s.renewMu <- struct{}{}
	defer func() { <-s.renewMu }()
	err := secured.CloseWrite()
	return errors.Join(err, s.Conn.SetWriteDeadline(time.Time{}))
}

func (s *NativeRequestWriter) CloseWrite() error {
	s.mu <- struct{}{}
	defer func() { <-s.mu }()
	if s.ended {
		return s.err
	}
	s.ended = true
	_ = s.startLocked(nil)
	if s.err == nil {
		s.err = tunnelv1.WriteNativeRequestFrame(s.Conn, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestEnded})
	}
	// end application bytes, but keep the request stream's write direction
	// available for permission renewal while the response is still in flight.
	return s.err
}
