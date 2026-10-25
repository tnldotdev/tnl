package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativeRequestWriter serializes visitor data and independent permission updates
// on the outer native request stream. return bytes remain owned by its caller.
type NativeRequestWriter struct {
	net.Conn
	mu      sync.Mutex
	ended   bool
	err     error
	opening func([]byte) error
}

func NewNativeRequestWriter(conn net.Conn) *NativeRequestWriter {
	return &NativeRequestWriter{Conn: conn}
}

// NewNativeOpeningWriter sends one signed opening with the first bounded data
// block. it never waits for return bytes before forwarding the request. callers
// with server-first protocols send an empty opening before constructing a writer.
func NewNativeOpeningWriter(conn net.Conn, opening func([]byte) error) *NativeRequestWriter {
	return &NativeRequestWriter{Conn: conn, opening: opening}
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
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.startLocked(nil); err != nil {
		return err
	}
	s.err = tunnelv1.WriteNativeRequestFrame(s.Conn, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestPermission, Permission: permission})
	return s.err
}

func (s *NativeRequestWriter) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

// NativeRequestReader removes outer request frames before TLS or application
// parsers see bytes. a rejected renewal terminates this stream, never a sibling.
type NativeRequestReader struct {
	net.Conn
	renew       func(tunnelv1.NativeVisitorPermission) error
	initial     *bytes.Reader
	remaining   *bytes.Reader
	terminal    error
	header      [5]byte
	headerRead  int
	payload     []byte
	payloadRead int
}

func NewNativeRequestReader(conn net.Conn, initial []byte, renew func(tunnelv1.NativeVisitorPermission) error) *NativeRequestReader {
	return &NativeRequestReader{Conn: conn, initial: bytes.NewReader(initial), renew: renew}
}

func (s *NativeRequestReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if s.initial.Len() > 0 {
		return s.initial.Read(p)
	}
	for s.terminal == nil {
		if s.remaining != nil && s.remaining.Len() > 0 {
			return s.remaining.Read(p)
		}
		f, err := s.readFrame()
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return 0, err
			}
			s.terminal = err
			break
		}
		switch f.Kind {
		case tunnelv1.NativeRequestData:
			s.remaining = bytes.NewReader(f.Data)
		case tunnelv1.NativeRequestPermission:
			if s.renew == nil {
				s.terminal = tunnelv1.ErrNativeRequest
			} else {
				s.terminal = s.renew(f.Permission)
			}
		case tunnelv1.NativeRequestEnded:
			s.terminal = io.EOF
			go s.renewAfterEnd()
		}
	}
	return 0, s.terminal
}

// after the local application sees EOF, only signed permission frames may
// arrive. a failed renewal closes this visitor stream, not its mux session.
func (s *NativeRequestReader) renewAfterEnd() {
	for {
		frame, err := s.readFrame()
		if err != nil || frame.Kind != tunnelv1.NativeRequestPermission || s.renew == nil || s.renew(frame.Permission) != nil {
			_ = s.Conn.Close()
			return
		}
	}
}

// net/http interrupts idle reads with deadlines when hijacking an upgraded
// connection. retain partial frame state so clearing that deadline resumes the
// same frame rather than poisoning TLS or interpreting payload as a new header.
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
