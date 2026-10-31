package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const handshakeTimeout = 10 * time.Second

// ProtocolError is a stable tunnelv1 rejection.
type ProtocolError struct {
	Code tunnelv1.ErrorCode
}

func (e *ProtocolError) Error() string { return "tunnel: " + string(e.Code) }

// TunnelCode exposes the owned wire classification without parsing Error text.
func (e *ProtocolError) TunnelCode() tunnelv1.ErrorCode { return e.Code }

// StreamHeaderError belongs to one rejected stream, not its authenticated
// publisher connection. the acceptor may keep serving other streams.
type StreamHeaderError struct {
	Kind string
	Err  error
}

func (e *StreamHeaderError) Error() string {
	return fmt.Sprintf("tunnel: read %s stream header: %v", e.Kind, e.Err)
}

func (e *StreamHeaderError) Unwrap() error { return e.Err }

// AuthenticateFunc authorizes one publisher or ingress hello.
type AuthenticateFunc func(context.Context, tunnelv1.Message) error

// AuthenticateWithResultFunc may return a native receipt after authorizing a
// hello. the handshake owns writing either the receipt or a protocol error.
type AuthenticateWithResultFunc func(context.Context, tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error)

// Session is an authenticated tunnelv1 session over an arbitrary transport.
type Session struct {
	transport           muxsession.Session
	control             muxsession.Stream
	role                tunnelv1.PeerRole
	publisherConnection *tunnelv1.PublisherConnectionRef
	serviceConnection   *tunnelv1.ServicePublisherConnectionRef
	nativeLeg           *tunnelv1.NativePairLegProof
	nativeControl       sync.Mutex
	nativeActivated     bool

	closeOnce sync.Once
	closeErr  error
}

// BorrowServicePublisherTransport gives the service run owner the authenticated
// outer transport for shared packet registration. it does not transfer ownership
// or authorize any pair. the owner must use a single stream acceptor (the service
// dispatcher for mixed streams) and join packet readers before closing Session.
func (s *Session) BorrowServicePublisherTransport() (muxsession.Session, error) {
	if s == nil || s.transport == nil || s.role != tunnelv1.Publisher || s.serviceConnection == nil {
		return nil, &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	return s.transport, nil
}

// Dial performs the client side of the shared tunnelv1 handshake.
func Dial(ctx context.Context, transport muxsession.Session, hello tunnelv1.Message) (result *Session, err error) {
	if hello.Role == tunnelv1.NativeConnector {
		return nil, errors.New("tunnel: native connector requires an expected delivery ID")
	}
	result, _, err = dial(ctx, transport, hello, "", false)
	return result, err
}

// DialNative requires the delivery ID from the prepared pair, independently
// of the signed leg proof and of the untrusted hello response.
func DialNative(ctx context.Context, transport muxsession.Session, hello tunnelv1.Message, expectedDeliveryID string) (*Session, tunnelv1.NativePairLegAccepted, error) {
	if hello.Role != tunnelv1.NativeConnector || hello.NativePairLegProof == nil {
		return nil, tunnelv1.NativePairLegAccepted{}, errors.New("tunnel: native connector hello is required")
	}
	return dial(ctx, transport, hello, expectedDeliveryID, true)
}

func dial(ctx context.Context, transport muxsession.Session, hello tunnelv1.Message, expectedDeliveryID string, native bool) (result *Session, receipt tunnelv1.NativePairLegAccepted, err error) {
	if transport == nil {
		return nil, receipt, errors.New("tunnel: transport session is required")
	}
	if hello.Type != tunnelv1.Hello {
		return nil, receipt, errors.New("tunnel: hello message is required")
	}
	defer func() {
		if err != nil {
			err = errors.Join(controlContextError(ctx, err), transport.Close())
		}
	}()
	if native {
		if _, err := tunnelv1.ParsePeerDeliveryIdentifier(expectedDeliveryID); err != nil || hello.NativePairLegProof.Validate() != nil {
			return nil, receipt, errors.New("tunnel: valid native leg and expected delivery ID are required")
		}
	}
	started := time.Now()
	control, err := transport.OpenStream(ctx)
	if err != nil {
		return nil, receipt, fmt.Errorf("tunnel: open control stream: %w", err)
	}
	finish, err := setupDeadline(ctx, control)
	if err != nil {
		return nil, receipt, err
	}
	defer func() {
		err = errors.Join(err, finish(err == nil))
		if err != nil {
			result = nil
			receipt = tunnelv1.NativePairLegAccepted{}
		}
	}()
	if err := tunnelv1.WriteControl(control, hello); err != nil {
		return nil, receipt, fmt.Errorf("tunnel: write hello: %w", err)
	}
	response, err := tunnelv1.ReadControl(control)
	if err != nil {
		return nil, receipt, fmt.Errorf("tunnel: read hello response: %w", err)
	}
	if response.Type == tunnelv1.Error {
		return nil, receipt, &ProtocolError{Code: response.Code}
	}
	if response.Type != tunnelv1.HelloAccepted {
		return nil, receipt, errors.New("tunnel: unexpected hello response")
	}
	if native {
		if response.NativePairLegAccepted == nil || response.NativePairLegAccepted.Match(*hello.NativePairLegProof, expectedDeliveryID, started, time.Now()) != nil {
			return nil, receipt, errors.New("tunnel: native hello receipt does not match prepared pair")
		}
		receipt = *response.NativePairLegAccepted
	} else if response.NativePairLegAccepted != nil {
		return nil, receipt, errors.New("tunnel: unexpected native hello receipt")
	}
	return authenticatedSession(transport, control, hello), receipt, nil
}

// Accept performs the server side of the shared tunnelv1 handshake.
func Accept(ctx context.Context, transport muxsession.Session, authenticate AuthenticateFunc) (result *Session, message tunnelv1.Message, err error) {
	if authenticate == nil {
		return nil, tunnelv1.Message{}, errors.New("tunnel: transport session and authenticator are required")
	}
	return AcceptWithResult(ctx, transport, func(ctx context.Context, hello tunnelv1.Message) (*tunnelv1.NativePairLegAccepted, error) {
		return nil, authenticate(ctx, hello)
	})
}

// AcceptWithResult shares the same handshake as Accept, adding a checked
// native receipt to hello_accepted only after authentication succeeds.
func AcceptWithResult(ctx context.Context, transport muxsession.Session, authenticate AuthenticateWithResultFunc) (result *Session, message tunnelv1.Message, err error) {
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
	receipt, authErr := authenticate(setupCtx, hello)
	if authErr == nil && (receipt != nil && (hello.Role != tunnelv1.NativeConnector || receipt.Validate() != nil ||
		receipt.PairID != hello.NativePairLegProof.PairID || receipt.DeliveryGeneration != hello.NativePairLegProof.DeliveryGeneration ||
		receipt.ConnectionSlot != hello.NativePairLegProof.ConnectionSlot || !receipt.ExpiresAt.After(time.Now())) ||
		hello.Role == tunnelv1.NativeConnector && receipt == nil) {
		authErr = errors.New("tunnel: invalid native hello receipt")
	}
	if authErr != nil {
		code := tunnelv1.Internal
		var protocolError *ProtocolError
		if errors.As(authErr, &protocolError) && validAuthenticationError(protocolError.Code) {
			code = protocolError.Code
		}
		_ = writeProtocolError(control, code)
		return nil, tunnelv1.Message{}, authErr
	}
	if err := tunnelv1.WriteControl(control, tunnelv1.Message{
		Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version, NativePairLegAccepted: receipt,
	}); err != nil {
		return nil, tunnelv1.Message{}, fmt.Errorf("tunnel: write hello response: %w", err)
	}
	return authenticatedSession(transport, control, hello), hello, nil
}

func authenticatedSession(transport muxsession.Session, control muxsession.Stream, hello tunnelv1.Message) *Session {
	s := &Session{transport: transport, control: control, role: hello.Role}
	if hello.PublisherConnection != nil {
		ref := *hello.PublisherConnection
		s.publisherConnection = &ref
	}
	if hello.ServiceConnection != nil {
		ref := *hello.ServiceConnection
		s.serviceConnection = &ref
	}
	if hello.NativePairLegProof != nil {
		proof := *hello.NativePairLegProof
		proof.Nonce, proof.Signature = bytes.Clone(proof.Nonce), bytes.Clone(proof.Signature)
		s.nativeLeg = &proof
	}
	return s
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
	if err := s.readDrainResponse(ctx, requestID, tunnelv1.Draining); err != nil {
		return err
	}
	return s.readDrainResponse(ctx, requestID, tunnelv1.Drained)
}

func (s *Session) readDrainResponse(ctx context.Context, requestID string, expected tunnelv1.MessageType) error {
	response, err := tunnelv1.ReadControl(s.control)
	if err != nil {
		return controlContextError(ctx, fmt.Errorf("tunnel: read %s response: %w", expected, err))
	}
	if response.Type == tunnelv1.Error && response.RequestID == requestID {
		return &ProtocolError{Code: response.Code}
	}
	if response.Type != expected || response.RequestID != requestID {
		return fmt.Errorf("tunnel: unexpected %s response", expected)
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

// IncomingVisitorStream is a visitor stream awaiting an accept or reject response.
type IncomingVisitorStream struct {
	owner  context.Context
	Stream muxsession.Stream
	Header tunnelv1.VisitorStreamHeader

	response *replyStream
}

// AcceptVisitorStream reads the next stream header without accepting its assignment identity.
func (s *Session) AcceptVisitorStream(ctx context.Context) (*IncomingVisitorStream, error) {
	stream, err := s.acceptStream(ctx, "visitor")
	if err != nil {
		return nil, err
	}
	header, initial, err := tunnelv1.ReadVisitorOpening(stream)
	if err != nil {
		_ = (&replyStream{Stream: stream}).forwardRejection(ctx, tunnelv1.InvalidMessage)
		_ = stream.Close()
		return nil, &StreamHeaderError{Kind: "visitor", Err: err}
	}
	reply := newReplyStream(stream, initial, header.ConfirmBeforeBytes)
	if ref := s.publisherConnection; ref != nil && header.AccessPending {
		reply.promotion = tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherPromotion,
			VisitorConnectionID: header.VisitorConnectionID, PublicURLID: header.PublicURLID, PublishRunID: header.PublishRunID,
			PublishRunNumber: header.PublishRunNumber, PublisherConnectionID: header.PublisherConnectionID,
			ConnectionAssignmentRevision: header.ConnectionAssignmentRevision, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID}
	}
	return &IncomingVisitorStream{
		owner:  ctx,
		Stream: reply, Header: header, response: reply,
	}, nil
}

// Accept acknowledges the visitor stream and clears its setup deadline.
func (r *IncomingVisitorStream) Accept() error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

// Reject rejects the visitor stream with a stable protocol code.
func (r *IncomingVisitorStream) Reject(code tunnelv1.ErrorCode) error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: code})
}

// Promote carries the publisher's current authorization decision on this exact
// stream. the bound responder survives connection wrappers used by the publisher.
func (r *IncomingVisitorStream) Promote(ctx context.Context) error {
	return r.response.promote(ctx, r.response.promotion)
}

// CloseWrite ends the return frames before a TLS owner closes its connection.
// cancellation remains stream-local and includes contended writer acquisition.
func (r *IncomingVisitorStream) CloseWrite(ctx context.Context) error {
	return r.response.end(ctx)
}

func (s *Session) AcceptInternalForwardingStream(ctx context.Context) (InternalForwardingRequest, error) {
	stream, err := s.acceptStream(ctx, "internal forwarding")
	if err != nil {
		return nil, err
	}
	header, service, initial, err := tunnelv1.ReadForwardingOpening(stream)
	if err != nil {
		_ = (&replyStream{Stream: stream}).forwardRejection(ctx, tunnelv1.InvalidMessage)
		_ = stream.Close()
		return nil, &StreamHeaderError{Kind: "internal forwarding", Err: err}
	}
	reply := newReplyStream(stream, initial, service != nil || header.ConfirmBeforeBytes)
	response := reply
	if service != nil {
		return &IncomingServiceForwardingStream{owner: ctx, stream: reply, Header: *service, response: response}, nil
	}
	return &IncomingPublicForwardingStream{owner: ctx, stream: reply, Header: header, response: response}, nil
}

// InternalForwardingRequest narrows the decoded wire union before forwarding.
// each concrete request shares its pointer-owned responder with the decoded
// stream, so copies and projections cannot acknowledge a stream twice.
type InternalForwardingRequest interface {
	internalForwardingRequest()
	Context() context.Context
	Stream() muxsession.Stream
	Accept() error
	Reject(tunnelv1.ErrorCode) error
}

type IncomingPublicForwardingStream struct {
	owner    context.Context
	stream   muxsession.Stream
	Header   tunnelv1.InternalForwardingHeader
	response *replyStream
}

func (*IncomingPublicForwardingStream) internalForwardingRequest()  {}
func (*IncomingServiceForwardingStream) internalForwardingRequest() {}

func (r *IncomingPublicForwardingStream) Stream() muxsession.Stream { return r.stream }

func (r *IncomingPublicForwardingStream) TakeInitial() []byte { return r.response.takeInitial() }

func (r *IncomingPublicForwardingStream) Context() context.Context {
	return incomingContext(r.owner, r.Header.TraceContext)
}

func (r *IncomingPublicForwardingStream) Accept() error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

func (r *IncomingPublicForwardingStream) Reject(code tunnelv1.ErrorCode) error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: code})
}

func (r *IncomingPublicForwardingStream) ForwardRejection(code tunnelv1.ErrorCode) error {
	return r.response.forwardRejection(r.Context(), code)
}

func (r *IncomingPublicForwardingStream) Promote(h tunnelv1.AdmissionHeader) error {
	if !r.Header.AccessPending || h != r.Header.Admission() {
		return tunnelv1.ErrReturnFrame
	}
	return r.response.promote(r.Context(), h)
}

// IncomingServiceForwardingStream carries one decoded service request.
// publisher acceptance also binds it to the claimed connection. callers check
// the relay lease and PROXY source before permitting application bytes.
type IncomingServiceForwardingStream struct {
	owner    context.Context
	stream   muxsession.Stream
	Header   tunnelv1.ServiceForwardingHeader
	response *replyStream
}

func (s *Session) AcceptServiceForwardingStream(ctx context.Context) (*IncomingServiceForwardingStream, error) {
	if s == nil || s.role != tunnelv1.Publisher || s.serviceConnection == nil {
		return nil, errors.New("tunnel: claimed service publisher connection is required")
	}
	stream, err := s.acceptStream(ctx, "service forwarding")
	if err != nil {
		return nil, err
	}
	return s.readServiceForwardingStream(ctx, stream)
}

// AcceptDispatchedServiceForwardingStream consumes the sole outer stream owner.
func (s *Session) AcceptDispatchedServiceForwardingStream(ctx context.Context, d *ServiceStreamDispatcher) (*IncomingServiceForwardingStream, error) {
	if s == nil || s.role != tunnelv1.Publisher || s.serviceConnection == nil || d == nil || d.owner != s {
		return nil, errors.New("tunnel: claimed service publisher connection and matching dispatcher are required")
	}
	stream, err := d.AcceptForwardingStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := setHandshakeDeadline(ctx, stream); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return s.readServiceForwardingStream(ctx, stream)
}

func (s *Session) readServiceForwardingStream(ctx context.Context, stream muxsession.Stream) (*IncomingServiceForwardingStream, error) {
	header, err := tunnelv1.ReadServiceForwardingHeader(stream)
	if err != nil {
		_ = (&replyStream{Stream: stream}).forwardRejection(ctx, tunnelv1.InvalidMessage)
		_ = stream.Close()
		return nil, &StreamHeaderError{Kind: "service forwarding", Err: err}
	}
	if ServiceForwardingRef(header) != *s.serviceConnection {
		_ = (&replyStream{Stream: stream}).forwardRejection(ctx, tunnelv1.StaleConnectionAssignment)
		_ = stream.Close()
		return nil, &StreamHeaderError{Kind: "service forwarding", Err: errors.New("claimed assignment changed")}
	}
	initial, err := tunnelv1.ReadInitialBytes(stream)
	if err != nil {
		_ = stream.Close()
		return nil, &StreamHeaderError{Kind: "service forwarding", Err: err}
	}
	reply := newReplyStream(stream, initial, true)
	return &IncomingServiceForwardingStream{owner: ctx, stream: reply, Header: header, response: reply}, nil
}

// Context retains the receiver's process context and adopts only the untrusted
// telemetry parent of this visitor, independently of every other mux stream.
func (r *IncomingVisitorStream) Context() context.Context {
	return incomingContext(r.owner, r.Header.TraceContext)
}

func (r *IncomingServiceForwardingStream) Stream() muxsession.Stream { return r.stream }

func (r *IncomingServiceForwardingStream) Context() context.Context {
	return incomingContext(r.owner, r.Header.TraceContext)
}

func incomingContext(owner context.Context, tc tunnelv1.TraceContext) context.Context {
	if owner == nil {
		owner = context.Background()
	}
	return observability.ExtractWireTrace(owner, tc)
}

func (r *IncomingServiceForwardingStream) Accept() error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted})
}

func (r *IncomingServiceForwardingStream) Reject(code tunnelv1.ErrorCode) error {
	return r.response.respond(r.Context(), tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: code})
}

func (r *IncomingServiceForwardingStream) CloseWrite(ctx context.Context) error {
	return r.response.end(ctx)
}

func (s *Session) acceptStream(ctx context.Context, kind string) (muxsession.Stream, error) {
	if s.role == tunnelv1.NativeConnector {
		return nil, errors.New("tunnel: native session has no application stream owner")
	}
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

func (s *Session) Done() <-chan struct{} { return s.transport.Done() }

func (s *Session) Err() error { return s.transport.Err() }

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		// the transport owns all streams. closing a control stream first can
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
