package service

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	quic "github.com/quic-go/quic-go"
)

type stdioAbortWriteConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	writes  atomic.Int32
	fault   error
}

func (c *stdioAbortWriteConn) Write([]byte) (int, error) {
	c.writes.Add(1)
	close(c.entered)
	<-c.release
	return 0, c.fault
}

func TestConnectorStdioAbortFencesOnlyUnenteredTLSWrites(t *testing.T) {
	for _, cause := range []error{errConnectorAdmissionAbort, context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			raw := &stdioAbortWriteConn{entered: make(chan struct{}), release: make(chan struct{}), fault: io.EOF}
			close(raw.release)
			owned := &connectorOwnedConn{Conn: raw, admission: &connectorAdmission{ctx: ctx}}
			cancel(cause)
			_, err := owned.Write([]byte("TLS close alert"))
			if cause == errConnectorAdmissionAbort {
				if err != errConnectorAdmissionAbort || raw.writes.Load() != 0 {
					t.Fatal("authenticated abort started a TLS write on its closed raw stream", err, raw.writes.Load())
				}
			} else if err != io.EOF || raw.writes.Load() != 1 {
				t.Fatal("ordinary cancellation hid an independent TLS write result", err, raw.writes.Load())
			}
		})
	}
	for _, fault := range []error{io.EOF, net.ErrClosed, errors.New("independent entered TLS write failure"), &quic.StreamError{ErrorCode: 7}} {
		t.Run(fault.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			raw := &stdioAbortWriteConn{entered: make(chan struct{}), release: make(chan struct{}), fault: fault}
			owned := &connectorOwnedConn{Conn: raw, admission: &connectorAdmission{ctx: ctx}}
			done := make(chan error, 1)
			go func() { _, err := owned.Write([]byte("entered TLS write")); done <- err }()
			<-raw.entered
			cancel(errConnectorAdmissionAbort)
			close(raw.release)
			if err := <-done; err != fault {
				t.Fatal("authenticated abort hid an entered TLS write failure", fault, err)
			}
		})
	}
}
