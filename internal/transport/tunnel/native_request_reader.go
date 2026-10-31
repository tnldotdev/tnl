package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativeRequestRead struct {
	data []byte
	err  error
}

// NativeRequestReader has one bounded frame reader independent of application
// reads. a response-only HTTP handler must still consume permission renewals.
// one queued data frame and one being decoded bound read-ahead; application
// backpressure cannot turn into an unbounded TLS or request buffer.
type NativeRequestReader struct {
	net.Conn
	mu                          sync.Mutex
	remaining                   *bytes.Reader
	terminal                    error
	renew                       func(tunnelv1.NativeVisitorPermission) error
	lifeMu                      sync.Mutex
	started, finished, tlsEnded bool
	readUntil                   time.Time
	changed                     chan struct{}
	reads                       chan nativeRequestRead
	done, stopped               chan struct{}
	workerErr                   error
	rawErr                      error
	closeOnce                   sync.Once
	closeErr                    error
	header                      [5]byte
	headerRead                  int
	payload                     []byte
	payloadRead                 int
}

func NewNativeRequestReader(conn net.Conn, initial []byte, renew func(tunnelv1.NativeVisitorPermission) error) *NativeRequestReader {
	return &NativeRequestReader{Conn: conn, remaining: bytes.NewReader(initial), renew: renew, changed: make(chan struct{}), reads: make(chan nativeRequestRead, 1), done: make(chan struct{}), stopped: make(chan struct{})}
}

func (s *NativeRequestReader) startLocked() {
	if !s.started && !s.finished {
		s.started = true
		go s.pump()
	}
}

func (s *NativeRequestReader) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		s.lifeMu.Lock()
		s.startLocked()
		finished, until, changed := s.finished, s.readUntil, s.changed
		s.lifeMu.Unlock()
		if finished {
			return 0, net.ErrClosed
		}
		if len(p) == 0 {
			return 0, nil
		}
		if !until.IsZero() && !until.After(time.Now()) {
			return 0, os.ErrDeadlineExceeded
		}
		if s.remaining.Len() > 0 {
			return s.remaining.Read(p)
		}
		if s.terminal != nil {
			return 0, s.terminal
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !until.IsZero() {
			timer = time.NewTimer(time.Until(until))
			timeout = timer.C
		}
		var next nativeRequestRead
		select {
		case next = <-s.reads:
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		case <-s.stopped:
			if timer != nil {
				timer.Stop()
			}
			// physical close interrupts the sole raw read. retain its actual
			// result rather than inventing a close cause before that read joins.
			<-s.done
			s.lifeMu.Lock()
			err := errors.Join(s.workerErr, s.rawErr)
			s.lifeMu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, err
		}
		if timer != nil {
			timer.Stop()
		}
		if next.err != nil {
			var timeout net.Error
			if errors.As(next.err, &timeout) && timeout.Timeout() {
				return 0, next.err
			}
			s.terminal = next.err
		} else {
			s.remaining = bytes.NewReader(next.data)
		}
	}
}

func (s *NativeRequestReader) send(next nativeRequestRead) bool {
	select {
	case s.reads <- next:
		return true
	case <-s.stopped:
		return false
	}
}

func (s *NativeRequestReader) pump() {
	defer close(s.done)
	ended := false
	for {
		frame, err := s.readFrame()
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				if !s.send(nativeRequestRead{err: err}) {
					return
				}
				continue
			}
			s.lifeMu.Lock()
			s.rawErr = err
			s.lifeMu.Unlock()
			s.send(nativeRequestRead{err: err})
			return
		}
		s.lifeMu.Lock()
		tlsEnded := s.tlsEnded
		s.lifeMu.Unlock()
		switch frame.Kind {
		case tunnelv1.NativeRequestData:
			if ended || tlsEnded {
				err = tunnelv1.ErrNativeRequest
			} else if !s.send(nativeRequestRead{data: frame.Data}) {
				return
			}
		case tunnelv1.NativeRequestPermission:
			if s.renew == nil {
				err = tunnelv1.ErrNativeRequest
			} else {
				err = s.renew(frame.Permission)
			}
		case tunnelv1.NativeRequestEnded:
			if ended {
				err = tunnelv1.ErrNativeRequest
			} else {
				ended = true
				if !s.send(nativeRequestRead{err: io.EOF}) {
					return
				}
			}
		}
		if err != nil {
			s.lifeMu.Lock()
			s.workerErr = err
			s.lifeMu.Unlock()
			_ = s.Close()
			return
		}
	}
}

// after TLS reports close_notify, no later data frame may enter its parser.
// the same frame owner continues checking permission during the response.
func (s *NativeRequestReader) ContinueAfterTLSCloseNotify() {
	s.lifeMu.Lock()
	s.tlsEnded = true
	s.startLocked()
	s.lifeMu.Unlock()
}

func (s *NativeRequestReader) SetReadDeadline(at time.Time) error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	s.readUntil = at
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

func (s *NativeRequestReader) SetDeadline(at time.Time) error {
	return errors.Join(s.SetReadDeadline(at), s.Conn.SetWriteDeadline(at))
}

func (s *NativeRequestReader) Close() error {
	s.closeOnce.Do(func() { close(s.stopped); s.closeErr = s.Conn.Close() })
	return s.closeErr
}

// Finish interrupts and joins the sole raw reader before the owner releases its
// stream charge. the reader can close itself, but it never joins itself.
func (s *NativeRequestReader) Finish() error {
	s.lifeMu.Lock()
	s.finished = true
	started := s.started
	s.lifeMu.Unlock()
	err := s.Close()
	if started {
		<-s.done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return errors.Join(err, s.workerErr)
}

func (s *NativeRequestReader) readFrame() (tunnelv1.NativeRequestFrame, error) {
	if s.headerRead < len(s.header) {
		n, err := io.ReadFull(s.Conn, s.header[s.headerRead:])
		s.headerRead += n
		if err != nil {
			return tunnelv1.NativeRequestFrame{}, err
		}
	}
	header, err := tunnelv1.ParseNativeRequestHeader(s.header[:])
	if err != nil {
		return tunnelv1.NativeRequestFrame{}, err
	}
	if s.payload == nil {
		s.payload = make([]byte, header.Length)
	}
	if s.payloadRead < len(s.payload) {
		n, err := io.ReadFull(s.Conn, s.payload[s.payloadRead:])
		s.payloadRead += n
		if err != nil {
			return tunnelv1.NativeRequestFrame{}, err
		}
	}
	var frame tunnelv1.NativeRequestFrame
	if header.Kind == tunnelv1.NativeRequestData {
		frame = tunnelv1.NativeRequestFrame{Kind: header.Kind, Data: s.payload}
	} else {
		frame, err = tunnelv1.ReadNativeRequestFrame(io.MultiReader(bytes.NewReader(s.header[:]), bytes.NewReader(s.payload)))
	}
	s.headerRead, s.payloadRead, s.payload = 0, 0, nil
	return frame, err
}

func (s *NativeRequestReader) CloseWrite() error {
	if closer, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
