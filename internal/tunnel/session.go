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
func Dial(ctx context.Context, transport muxsession.Session, hello tunnelv1.Message) (*Session, error) {
	if transport == nil {
		return nil, errors.New("tunnel: transport session is required")
	}
	if hello.Type != tunnelv1.Hello {
		return nil, errors.New("tunnel: hello message is required")
	}
	control, err := transport.OpenStream(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("tunnel: open control stream: %w", err)
	}
	if err := setHandshakeDeadline(ctx, control); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, err
	}
	if err := tunnelv1.WriteControl(control, hello); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("tunnel: write hello: %w", err)
	}
	response, err := tunnelv1.ReadControl(control)
	if err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("tunnel: read hello response: %w", err)
	}
	if response.Type == tunnelv1.Error {
		_ = control.Close()
		_ = transport.Close()
		return nil, &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.HelloAccepted {
		_ = control.Close()
		_ = transport.Close()
		return nil, errors.New("tunnel: unexpected hello response")
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, fmt.Errorf("tunnel: clear control deadline: %w", err)
	}
	return &Session{transport: transport, control: control}, nil
}

// Accept performs the server side of the shared tunnelv1 handshake.
func Accept(ctx context.Context, transport muxsession.Session, authenticate AuthenticateFunc) (*Session, tunnelv1.Message, error) {
	if transport == nil || authenticate == nil {
		return nil, tunnelv1.Message{}, errors.New("tunnel: transport session and authenticator are required")
	}
	control, err := transport.AcceptStream(ctx)
	if err != nil {
		_ = transport.Close()
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: accept control stream: %w", err)
	}
	if err := setHandshakeDeadline(ctx, control); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, tunnelv1.Message{}, err
	}
	hello, err := tunnelv1.ReadControl(control)
	if err != nil || hello.Type != tunnelv1.Hello {
		_ = writeProtocolError(control, tunnelv1.InvalidMessage)
		_ = control.Close()
		_ = transport.Close()
		if err != nil {
			return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: read hello: %w", err)
		}
		return nil, tunnelv1.Message{}, errors.New("tunnel: first control message is not hello")
	}
	if err := authenticate(ctx, hello); err != nil {
		code := tunnelv1.Internal
		var protocolError *ProtocolError
		if errors.As(err, &protocolError) && validAuthenticationError(protocolError.Code) {
			code = protocolError.Code
		}
		_ = writeProtocolError(control, code)
		_ = control.Close()
		_ = transport.Close()
		return nil, tunnelv1.Message{}, err
	}
	if err := tunnelv1.WriteControl(control, tunnelv1.Message{
		Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version,
	}); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: write hello response: %w", err)
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		_ = control.Close()
		_ = transport.Close()
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: clear control deadline: %w", err)
	}
	return &Session{transport: transport, control: control}, hello, nil
}

// OpenPublisherStream opens one visitor stream to a publisher and waits for setup acknowledgement before
// returning it to the caller. No PROXY v2 or visitor bytes have been sent yet.
func (s *Session) OpenPublisherStream(ctx context.Context, header tunnelv1.PublisherStreamHeader) (muxsession.Stream, error) {
	return s.openAcknowledgedStream(ctx, "publisher", func(stream muxsession.Stream) error {
		return tunnelv1.WritePublisherStreamHeader(stream, header)
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

func (s *Session) openAcknowledgedStream(
	ctx context.Context,
	kind string,
	writeHeader func(muxsession.Stream) error,
) (muxsession.Stream, error) {
	stream, err := s.transport.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("tunnel: open %s stream: %w", kind, err)
	}
	if err := setHandshakeDeadline(ctx, stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if err := writeHeader(stream); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: write %s stream header: %w", kind, err)
	}
	response, err := tunnelv1.ReadStreamResponse(stream)
	if err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: read %s stream response: %w", kind, err)
	}
	if response.Type == tunnelv1.StreamRejected {
		_ = stream.Close()
		return nil, &ProtocolError{Code: response.Code}
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: clear %s stream deadline: %w", kind, err)
	}
	return stream, nil
}

// IncomingPublisherStream is a visitor stream awaiting an accept or reject response.
type IncomingPublisherStream struct {
	Stream muxsession.Stream
	Header tunnelv1.PublisherStreamHeader

	response incomingStreamResponse
}

// AcceptPublisherStream reads the next stream header without accepting its assignment identity.
func (s *Session) AcceptPublisherStream(ctx context.Context) (*IncomingPublisherStream, error) {
	stream, err := s.acceptStream(ctx, "publisher")
	if err != nil {
		return nil, err
	}
	header, err := tunnelv1.ReadPublisherStreamHeader(stream)
	if err != nil {
		_ = tunnelv1.WriteStreamResponse(stream, tunnelv1.StreamResponse{
			Type: tunnelv1.StreamRejected, Code: tunnelv1.InvalidMessage,
		})
		_ = stream.Close()
		return nil, fmt.Errorf("tunnel: read publisher stream header: %w", err)
	}
	return &IncomingPublisherStream{
		Stream: stream, Header: header, response: incomingStreamResponse{stream: stream},
	}, nil
}

// Accept acknowledges the publisher stream and clears its setup deadline.
func (r *IncomingPublisherStream) Accept() error {
	return r.response.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

// Reject rejects the route stream with a stable semantic code.
func (r *IncomingPublisherStream) Reject(code tunnelv1.ErrorCode) error {
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
		s.closeErr = errors.Join(s.control.Close(), s.transport.Close())
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

func writeProtocolError(control muxsession.Stream, code tunnelv1.ErrorCode) error {
	return tunnelv1.WriteControl(control, tunnelv1.Message{
		Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, Code: code,
	})
}

func validAuthenticationError(code tunnelv1.ErrorCode) bool {
	switch code {
	case tunnelv1.Unauthenticated, tunnelv1.StaleRouteVersion, tunnelv1.StaleConnectionAssignment,
		tunnelv1.DuplicatePublisherConnection, tunnelv1.DrainingPublisherConnection, tunnelv1.CapacityExceeded,
		tunnelv1.Unavailable:
		return true
	default:
		return false
	}
}
