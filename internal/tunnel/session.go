package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const handshakeTimeout = 10 * time.Second

// ProtocolError is a stable tunnelv1 rejection.
type ProtocolError struct {
	Code tunnelv1.ErrorCode
}

func (e *ProtocolError) Error() string { return "tunnel: " + string(e.Code) }

// AuthenticateFunc authorizes one publisher or ingress hello.
type AuthenticateFunc func(context.Context, tunnelv1.Message) error

// Session is an authenticated tunnelv1 session over an arbitrary transport.
type Session struct {
	transport muxsession.Session
	control   muxsession.Stream

	closeOnce sync.Once
	closeErr  error
}

// Dial performs the client side of the shared tunnelv1 handshake.
func Dial(ctx context.Context, transport muxsession.Session, hello tunnelv1.Message) (result *Session, err error) {
	if transport == nil {
		return nil, errors.New("tunnel: transport session is required")
	}
	if hello.Type != tunnelv1.Hello {
		return nil, errors.New("tunnel: hello message is required")
	}
	defer func() {
		if err != nil {
			err = errors.Join(controlContextError(ctx, err), transport.Close())
		}
	}()
	control, err := transport.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: open control stream: %w", err)
	}
	finish, err := setupDeadline(ctx, control)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
		}
	}()
	if err := tunnelv1.WriteControl(control, hello); err != nil {
		return nil, fmt.Errorf("tunnel: write hello: %w", err)
	}
	response, err := tunnelv1.ReadControl(control)
	if err != nil {
		return nil, fmt.Errorf("tunnel: read hello response: %w", err)
	}
	if response.Type == tunnelv1.Error {
		return nil, &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.HelloAccepted {
		return nil, errors.New("tunnel: unexpected hello response")
	}
	return &Session{transport: transport, control: control}, nil
}

// Accept performs the server side of the shared tunnelv1 handshake.
func Accept(ctx context.Context, transport muxsession.Session, authenticate AuthenticateFunc) (result *Session, message tunnelv1.Message, err error) {
	if transport == nil || authenticate == nil {
		return nil, tunnelv1.Message{}, errors.New("tunnel: transport session and authenticator are required")
	}
	setupCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	defer func() {
		if err != nil {
			err = errors.Join(controlContextError(ctx, err), transport.Close())
		}
	}()
	control, err := transport.AcceptStream(setupCtx)
	if err != nil {
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: accept control stream: %w", err)
	}
	finish, err := setupDeadline(setupCtx, control)
	if err != nil {
		return nil, tunnelv1.Message{}, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
		}
	}()
	hello, err := tunnelv1.ReadControl(control)
	if err != nil || hello.Type != tunnelv1.Hello {
		_ = writeProtocolError(control, tunnelv1.InvalidMessage)
		if err != nil {
			return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: read hello: %w", err)
		}
		return nil, tunnelv1.Message{}, errors.New("tunnel: first control message is not hello")
	}
	if err := authenticate(setupCtx, hello); err != nil {
		code := tunnelv1.Internal
		var protocolError *ProtocolError
		if errors.As(err, &protocolError) && validAuthenticationError(protocolError.Code) {
			code = protocolError.Code
		}
		_ = writeProtocolError(control, code)
		return nil, tunnelv1.Message{}, err
	}
	if err := tunnelv1.WriteControl(control, tunnelv1.Message{
		Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version,
	}); err != nil {
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: write hello response: %w", err)
	}
	return &Session{transport: transport, control: control}, hello, nil
}

// OpenVisitorStream opens a visitor stream and waits for the publisher to
// accept it. It returns before sending PROXY v2 metadata or visitor bytes.
func (s *Session) OpenVisitorStream(ctx context.Context, header tunnelv1.VisitorStreamHeader) (muxsession.Stream, error) {
	return s.openAcknowledgedStream(ctx, "visitor", func(stream muxsession.Stream) error {
		return tunnelv1.WriteVisitorStreamHeader(stream, header)
	})
}

// OpenInternalForwardingStream opens one visitor stream from ingress to a relay
// and waits for acceptance before returning it. No visitor bytes are sent here.
func (s *Session) OpenInternalForwardingStream(
	ctx context.Context,
	header tunnelv1.InternalForwardingHeader,
) (muxsession.Stream, error) {
	return s.openAcknowledgedStream(ctx, "internal forwarding", func(stream muxsession.Stream) error {
		return tunnelv1.WriteInternalForwardingHeader(stream, header)
	})
}

// RequestPublisherDrain asks a relay to stop admitting visitor streams and
// waits until all streams already admitted by that relay have closed.
func (s *Session) RequestPublisherDrain(ctx context.Context, requestID string) error {
	clearDeadline, err := setContextDeadline(ctx, s.control)
	if err != nil {
		return err
	}
	defer clearDeadline()
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{
		Type: tunnelv1.Drain, ProtocolVersion: tunnelv1.Version, RequestID: requestID,
	}); err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: write drain request: %w", err))
	}
	draining, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: read draining response: %w", err))
	}
	if draining.Type == tunnelv1.Error && draining.RequestID == requestID {
		return &ProtocolError{Code: draining.Code}
	}
	if draining.Type != tunnelv1.Draining || draining.RequestID != requestID {
		return errors.New("tunnel: unexpected draining response")
	}
	drained, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: read drained response: %w", err))
	}
	if drained.Type == tunnelv1.Error && drained.RequestID == requestID {
		return &ProtocolError{Code: drained.Code}
	}
	if drained.Type != tunnelv1.Drained || drained.RequestID != requestID {
		return errors.New("tunnel: unexpected drained response")
	}
	return nil
}

// HandlePublisherDrain handles one relay-side publisher drain request.
func (s *Session) HandlePublisherDrain(ctx context.Context, drain func(context.Context) error) error {
	if drain == nil {
		return errors.New("tunnel: publisher drain callback is required")
	}
	clearDeadline, err := setContextDeadline(ctx, s.control)
	if err != nil {
		return err
	}
	defer clearDeadline()
	request, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: read drain request: %w", err))
	}
	if request.Type != tunnelv1.Drain || request.RequestID == "" {
		return errors.New("tunnel: unexpected drain request")
	}
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{
		Type: tunnelv1.Draining, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID,
	}); err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: write draining response: %w", err))
	}
	if err := drain(ctx); err != nil {
		return err
	}
	if err := tunnelv1.WriteControl(s.control, tunnelv1.Message{
		Type: tunnelv1.Drained, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID,
	}); err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: write drained response: %w", err))
	}
	return nil
}

func (s *Session) openAcknowledgedStream(
	ctx context.Context,
	kind string,
	writeHeader func(muxsession.Stream) error,
) (result muxsession.Stream, err error) {
	stream, err := s.transport.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: open %s stream: %w", kind, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(controlContextError(ctx, err), stream.Close())
		}
	}()
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
		}
	}()
	if err := writeHeader(stream); err != nil {
		return nil, fmt.Errorf("tunnel: write %s stream header: %w", kind, err)
	}
	response, err := tunnelv1.ReadStreamResponse(stream)
	if err != nil {
		return nil, fmt.Errorf("tunnel: read %s stream response: %w", kind, err)
	}
	if response.Type == tunnelv1.StreamRejected {
		return nil, &ProtocolError{Code: response.Code}
	}
	return stream, nil
}

// IncomingVisitorStream is a visitor stream awaiting an accept or reject response.
type IncomingVisitorStream struct {
	Stream muxsession.Stream
	Header tunnelv1.VisitorStreamHeader

	response incomingStreamResponse
}

// AcceptVisitorStream reads the next stream header without accepting its assignment identity.
func (s *Session) AcceptVisitorStream(ctx context.Context) (*IncomingVisitorStream, error) {
	stream, err := s.acceptStream(ctx, "visitor")
	if err != nil {
		return nil, err
	}
	header, err := tunnelv1.ReadVisitorStreamHeader(stream)
	if err != nil {
		_ = tunnelv1.WriteStreamResponse(stream, tunnelv1.StreamResponse{
			Type: tunnelv1.StreamRejected, Code: tunnelv1.InvalidMessage,
		})
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: read visitor stream header: %w", err)
	}
	return &IncomingVisitorStream{
		Stream: stream, Header: header, response: incomingStreamResponse{stream: stream},
	}, nil
}

// Accept acknowledges the visitor stream and clears its setup deadline.
func (r *IncomingVisitorStream) Accept() error {
	return r.response.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

// Reject rejects the visitor stream with a stable protocol code.
func (r *IncomingVisitorStream) Reject(code tunnelv1.ErrorCode) error {
	return r.response.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: code})
}

// IncomingInternalForwardingStream is an ingress stream awaiting acceptance by a relay.
type IncomingInternalForwardingStream struct {
	Stream muxsession.Stream
	Header tunnelv1.InternalForwardingHeader

	response incomingStreamResponse
}

func (s *Session) AcceptInternalForwardingStream(ctx context.Context) (*IncomingInternalForwardingStream, error) {
	stream, err := s.acceptStream(ctx, "internal forwarding")
	if err != nil {
		return nil, err
	}
	header, err := tunnelv1.ReadInternalForwardingHeader(stream)
	if err != nil {
		_ = tunnelv1.WriteStreamResponse(stream, tunnelv1.StreamResponse{
			Type: tunnelv1.StreamRejected, Code: tunnelv1.InvalidMessage,
		})
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: read internal forwarding stream header: %w", err)
	}
	return &IncomingInternalForwardingStream{
		Stream: stream, Header: header, response: incomingStreamResponse{stream: stream},
	}, nil
}

func (r *IncomingInternalForwardingStream) Accept() error {
	return r.response.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

func (r *IncomingInternalForwardingStream) Reject(code tunnelv1.ErrorCode) error {
	return r.response.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: code})
}

func (s *Session) acceptStream(ctx context.Context, kind string) (muxsession.Stream, error) {
	stream, err := s.transport.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: accept %s stream: %w", kind, err)
	}
	if err := setHandshakeDeadline(ctx, stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return stream, nil
}

type incomingStreamResponse struct {
	stream      muxsession.Stream
	respondOnce sync.Once
	respondErr  error
}

func (r *incomingStreamResponse) respond(response tunnelv1.StreamResponse) error {
	r.respondOnce.Do(func() {
		if err := tunnelv1.WriteStreamResponse(r.stream, response); err != nil {
			r.respondErr = err
			_ = r.stream.Close()
			return
		}
		if response.Type == tunnelv1.StreamRejected {
			r.respondErr = r.stream.Close()
			return
		}
		if err := r.stream.SetDeadline(time.Time{}); err != nil {
			r.respondErr = err
			_ = r.stream.Close()
		}
	})
	return r.respondErr
}

func (s *Session) Done() <-chan struct{} { return s.transport.Done() }

func (s *Session) Err() error { return s.transport.Err() }

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		// The transport owns all streams. Closing a control stream first can
		// block enqueueing its FIN behind a failed transport writer.
		s.closeErr = s.transport.Close()
	})
	return s.closeErr
}

func setHandshakeDeadline(ctx context.Context, connection net.Conn) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(handshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("tunnel: set handshake deadline: %w", err)
	}
	return nil
}

func setupDeadline(ctx context.Context, connection net.Conn) (func(bool) error, error) {
	setupCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	if err := context.Cause(setupCtx); err != nil {
		cancel()
		return nil, err
	}
	deadline, _ := setupCtx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		cancel()
		return nil, fmt.Errorf("tunnel: set control deadline: %w", err)
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(setupCtx, func() {
		_ = connection.SetDeadline(time.Now())
		close(interrupted)
	})
	return func(success bool) error {
		if !stop() {
			<-interrupted
		}
		cause := context.Cause(setupCtx)
		cancel()
		if !success {
			return cause
		}
		return errors.Join(cause, connection.SetDeadline(time.Time{}))
	}, nil
}

func setContextDeadline(ctx context.Context, connection net.Conn) (func() error, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("tunnel: set control deadline: %w", err)
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(interrupted)
	})
	return func() error {
		if !stop() {
			<-interrupted
		}
		return errors.Join(context.Cause(ctx), connection.SetDeadline(time.Time{}))
	}, nil
}

func controlContextError(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil {
		return errors.Join(cause, err)
	}
	return err
}

func writeProtocolError(control muxsession.Stream, code tunnelv1.ErrorCode) error {
	return tunnelv1.WriteControl(control, tunnelv1.Message{
		Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: code,
	})
}

func validAuthenticationError(code tunnelv1.ErrorCode) bool {
	switch code {
	case tunnelv1.Unauthenticated, tunnelv1.StalePublishRunNumber, tunnelv1.StaleConnectionAssignment,
		tunnelv1.DuplicatePublisherConnection, tunnelv1.DrainingPublisherConnection, tunnelv1.CapacityExceeded,
		tunnelv1.Unavailable:
		return true
	default:
		return false
	}
}
