package relay

import (
	"errors"
	"io"
	"net"
	"reflect"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// ForwardingError retains one validated forwarding header's scope and the
// separate copy and final-close results. it grants no visitor permission.
type ForwardingError struct {
	service, run, visitor      string
	number                     uint64
	phase                      string
	operation, copyResult      error
	cleanup, result            error
	copyMethodsObserved        bool
	relay, relayRun, publisher string
	step                       string
	elapsed                    time.Duration
	span                       trace.SpanContext
	ingressRun                 string
	slot                       uint8
	assignmentRevision         uint64
	sent, returned             int64
	acknowledged               time.Duration
	closeTrigger               string
}

func (e *ForwardingError) SpanContext() trace.SpanContext { return e.span }

func (e *ForwardingError) RelayScope() (string, string, string) {
	return e.relay, e.relayRun, e.publisher
}
func (e *ForwardingError) ForwardingStep() (string, time.Duration) { return e.step, e.elapsed }
func (e *ForwardingError) IngressRunID() string                    { return e.ingressRun }
func (e *ForwardingError) Assignment() (uint8, uint64)             { return e.slot, e.assignmentRevision }
func (e *ForwardingError) AcceptedAt() time.Duration               { return e.acknowledged }
func (e *ForwardingError) Forwarded() (int64, int64)               { return e.sent, e.returned }

func (e *ForwardingError) CloseProgress() (string, string) {
	if e.acknowledged == 0 {
		return "", ""
	}
	progress := "relay_ack"
	if e.sent > 0 {
		// ingress-to-publisher wire bytes on this hop include PROXY metadata.
		progress = "ingress_bytes_forwarded"
	}
	if e.returned > 0 {
		progress = "publisher_bytes_forwarded"
	}
	return progress, e.closeTrigger
}

func (*ForwardingError) Error() string      { return "relay: visitor forwarding failed" }
func (e *ForwardingError) GoString() string { return e.Error() }
func (e *ForwardingError) Unwrap() error    { return e.result }

func (e *ForwardingError) ForwardingScope() (service, run, visitor string, number uint64) {
	return e.service, e.run, e.visitor, e.number
}

func (e *ForwardingError) ForwardingPhase() string             { return e.phase }
func (e *ForwardingError) ForwardingOperation() error          { return e.operation }
func (e *ForwardingError) ForwardingCopyResult() error         { return e.copyResult }
func (e *ForwardingError) ForwardingCleanup() error            { return e.cleanup }
func (e *ForwardingError) ForwardingCopyMethodsObserved() bool { return e.copyMethodsObserved }

func (e *ForwardingError) finish(operation error) error {
	if operation == nil && e.cleanup == nil {
		return nil
	}
	e.operation = operation
	e.result = errors.Join(operation, e.cleanup)
	return e
}

type copyEndpoint uint8

const (
	copyIngress copyEndpoint = iota + 1
	copyPublisher
)

type copyOperation uint8

const (
	copyRead copyOperation = iota + 1
	copyWrite
	copyHalfClose
	copyAbortClose
)

// copyOperationError identifies the returning copy-interface call, not an
// inferred native syscall. the original cause and its classification are intact.
type copyOperationError struct {
	operation copyOperation
	endpoint  copyEndpoint
	cause     error
}

func (*copyOperationError) Error() string      { return "relay: stream copy operation failed" }
func (e *copyOperationError) GoString() string { return e.Error() }
func (e *copyOperationError) Unwrap() error    { return e.cause }

func (e *copyOperationError) ForwardingCopyOperation() (operation, endpoint, direction string) {
	switch e.operation {
	case copyRead:
		operation = "read"
	case copyWrite:
		operation = "write"
	case copyHalfClose:
		operation = "half_close"
	case copyAbortClose:
		operation = "copy_abort_close"
	}
	if e.endpoint == copyIngress {
		endpoint = "ingress"
	} else if e.endpoint == copyPublisher {
		endpoint = "publisher"
	}
	if operation == "" || endpoint == "" {
		return "unknown", "", ""
	}
	if e.operation == copyAbortClose {
		return operation, endpoint, "not_applicable"
	}
	toPublisher := e.operation == copyRead && e.endpoint == copyIngress ||
		e.operation != copyRead && e.endpoint == copyPublisher
	if toPublisher {
		direction = "visitor_to_publisher"
	} else {
		direction = "publisher_to_visitor"
	}
	return
}

type copyHalfCloser interface{ CloseWrite() error }
type copyReadCloser interface{ CloseRead() error }
type copyResetter interface{ Reset(uint32) error }

type copyDiagnosticConn struct {
	net.Conn
	endpoint copyEndpoint
}

func (c *copyDiagnosticConn) mark(operation copyOperation, err error) error {
	if err == nil {
		return nil
	}
	return &copyOperationError{operation: operation, endpoint: c.endpoint, cause: err}
}

func (c *copyDiagnosticConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	// io.Copy consumes only this exact read sentinel. wrapped/joined EOF is
	// still a failure, as is EOF returned by Write rather than Read.
	if err == io.EOF {
		return n, err
	}
	return n, c.mark(copyRead, err)
}

func (c *copyDiagnosticConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, c.mark(copyWrite, err)
}

func (c *copyDiagnosticConn) Close() error {
	return c.mark(copyAbortClose, c.Conn.Close())
}

type copyDiagnosticHalfConn struct {
	*copyDiagnosticConn
	half copyHalfCloser
}

func (c *copyDiagnosticHalfConn) CloseWrite() error {
	err := c.half.CloseWrite()
	// preserve the exact capability result tested by streamcopy.Copy.
	if err == errors.ErrUnsupported {
		return err
	}
	return c.mark(copyHalfClose, err)
}

type copyDiagnosticReadHalfConn struct {
	*copyDiagnosticHalfConn
	read copyReadCloser
}

func (c *copyDiagnosticReadHalfConn) CloseRead() error { return c.read.CloseRead() }

type copyDiagnosticResetHalfConn struct {
	*copyDiagnosticHalfConn
	reset copyResetter
}

func (c *copyDiagnosticResetHalfConn) Reset(code uint32) error { return c.reset.Reset(code) }

// only the references passed to Copy are adapted. its abort closes are therefore
// distinct from the owner's deferred closes of the original objects. unknown
// method sets, including future ReaderFrom/WriterTo paths, keep both originals.
func copyDiagnosticArguments(left, right net.Conn) (net.Conn, net.Conn, bool) {
	observedLeft, leftOK := copyDiagnosticArgument(left, copyIngress)
	observedRight, rightOK := copyDiagnosticArgument(right, copyPublisher)
	if !leftOK || !rightOK {
		return left, right, false
	}
	return observedLeft, observedRight, true
}

func copyDiagnosticArgument(connection net.Conn, endpoint copyEndpoint) (net.Conn, bool) {
	if connection == nil {
		return connection, false
	}
	half, hasHalf := connection.(copyHalfCloser)
	read, hasRead := connection.(copyReadCloser)
	reset, hasReset := connection.(copyResetter)
	methods := reflect.TypeOf(connection)
	for i := range methods.NumMethod() {
		switch methods.Method(i).Name {
		case "Read", "Write", "Close", "LocalAddr", "RemoteAddr", "SetDeadline", "SetReadDeadline", "SetWriteDeadline":
		case "CloseWrite":
			if !hasHalf {
				return connection, false
			}
		case "CloseRead":
			if !hasRead {
				return connection, false
			}
		case "Reset":
			if !hasReset {
				return connection, false
			}
		default:
			return connection, false
		}
	}
	if !hasHalf && (hasRead || hasReset) || hasRead && hasReset {
		return connection, false
	}
	base := &copyDiagnosticConn{Conn: connection, endpoint: endpoint}
	if !hasHalf {
		return base, true
	}
	closed := &copyDiagnosticHalfConn{copyDiagnosticConn: base, half: half}
	if hasRead {
		return &copyDiagnosticReadHalfConn{copyDiagnosticHalfConn: closed, read: read}, true
	}
	if hasReset {
		return &copyDiagnosticResetHalfConn{copyDiagnosticHalfConn: closed, reset: reset}, true
	}
	return closed, true
}
