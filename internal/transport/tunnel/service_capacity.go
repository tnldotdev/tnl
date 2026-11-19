package tunnel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// serviceCapacity lives only as long as its physical visitor stream. repeated
// requests share its one result; they never reserve capacity twice.
type serviceCapacity struct {
	header  tunnelv1.ServiceForwardingHeader
	ctx     context.Context
	reserve func(context.Context) error
	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	result  error
}

// RegisterServiceCapacity binds a capacity reservation to this authenticated
// session and exact visitor stream. unregister cancels and joins an entered call.
func (s *Session) RegisterServiceCapacity(ctx context.Context, header tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (func(), error) {
	if !s.serviceCapacityAllowed(header) || ctx == nil || reserve == nil || ctx.Err() != nil || s.Err() != nil {
		return nil, &ProtocolError{Code: tunnelv1.Unavailable}
	}
	life, cancel := context.WithCancel(ctx)
	ingress := *header.PublicService
	header.PublicService = &ingress
	entry := &serviceCapacity{header: header, ctx: life, reserve: reserve}
	s.capacityMu.Lock()
	if s.capacityRequests == nil {
		s.capacityRequests = make(map[string]*serviceCapacity)
	}
	if s.capacityRequests[header.VisitorConnectionID] != nil {
		s.capacityMu.Unlock()
		cancel()
		return nil, &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	s.capacityRequests[header.VisitorConnectionID] = entry
	s.capacityMu.Unlock()
	return sync.OnceFunc(func() {
		s.capacityMu.Lock()
		delete(s.capacityRequests, header.VisitorConnectionID)
		s.capacityMu.Unlock()
		entry.mu.Lock()
		entry.closed = true
		cancel()
		done := entry.done
		entry.mu.Unlock()
		if done != nil {
			<-done
		}
	}), nil
}

// RequestServiceCapacity uses a separate bounded stream so a pending HTTP
// handler never waits for its own request-body reader to receive the reply.
func (s *Session) RequestServiceCapacity(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (result error) {
	if ctx == nil {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	deadline, ok := ctx.Deadline()
	if !ok || !s.serviceCapacityAllowed(header) {
		return &ProtocolError{Code: tunnelv1.InvalidMessage}
	}
	deadline = minTime(deadline, minTime(header.ExpiresAt, minTime(header.ServingUntil, time.Now().Add(handshakeTimeout))))
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := context.Cause(call); err != nil {
		return err
	}
	stream, err := s.transport.OpenStream(call)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, stream.Close()) }()
	finish, err := setupDeadline(call, stream)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, finish(false)) }()
	request := tunnelv1.ServiceCapacityRequest{Kind: tunnelv1.ServiceCapacityStream, Stream: header, Deadline: deadline}
	if err := tunnelv1.WriteServiceCapacityRequest(stream, request); err != nil {
		return err
	}
	frame, err := tunnelv1.ReadReturnFrame(stream)
	if err != nil {
		return err
	}
	switch frame.Kind {
	case tunnelv1.ReturnAccepted:
		return nil
	case tunnelv1.ReturnRejected:
		return &ProtocolError{Code: frame.Code}
	default:
		return tunnelv1.ErrReturnFrame
	}
}

// ServeServiceCapacity is the sole reader for incoming capacity requests on
// this side of the session. the caller cancels and joins it with the session.
func (s *Session) ServeServiceCapacity(ctx context.Context) (result error) {
	if s == nil || s.transport == nil || s.role != tunnelv1.Ingress && s.role != tunnelv1.Publisher {
		return &ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	const readers = 8
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	slots := make(chan struct{}, readers)
	var work sync.WaitGroup
	var cleanupMu sync.Mutex
	var cleanupErr error
	recordCleanup := func(err error) {
		if err != nil {
			cleanupMu.Lock()
			cleanupErr = errors.Join(cleanupErr, &SessionCleanupError{Err: err})
			cleanupMu.Unlock()
			cancel()
		}
	}
	defer func() {
		cancel()
		work.Wait()
		result = errors.Join(result, cleanupErr)
	}()
	for {
		stream, err := s.transport.AcceptStream(ctx)
		if err != nil {
			if muxsession.NormalSessionCloseOnly(err) ||
				ctx.Err() != nil && (failure.Only(err, context.Cause(ctx)) || failure.Only(err, ctx.Err())) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			work.Go(func() {
				defer func() { <-slots }()
				recordCleanup(s.answerServiceCapacity(ctx, stream))
			})
		default:
			recordCleanup(stream.Reset(0))
		}
	}
}

func (s *Session) serviceCapacityAllowed(header tunnelv1.ServiceForwardingHeader) bool {
	if s == nil || s.transport == nil || header.PublicService == nil || header.Validate() != nil {
		return false
	}
	switch s.role {
	case tunnelv1.Ingress:
		return s.serviceConnection == nil
	case tunnelv1.Publisher:
		return s.serviceConnection != nil && *s.serviceConnection == ServiceForwardingRef(header)
	default:
		return false
	}
}

func (s *Session) answerServiceCapacity(ctx context.Context, stream muxsession.Stream) (cleanupErr error) {
	defer func() { cleanupErr = stream.Close() }()
	finish, err := setupDeadline(ctx, stream)
	if err != nil {
		return
	}
	defer finish(false)
	request, err := tunnelv1.ReadServiceCapacityRequest(stream)
	if err != nil {
		_ = tunnelv1.WriteReturnFrame(stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: tunnelv1.InvalidMessage})
		return
	}
	s.capacityMu.Lock()
	entry := s.capacityRequests[request.Stream.VisitorConnectionID]
	s.capacityMu.Unlock()
	if entry == nil {
		_ = tunnelv1.WriteReturnFrame(stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: tunnelv1.Unavailable})
		return
	}
	if !tunnelv1.SameServiceStream(entry.header, request.Stream) {
		_ = tunnelv1.WriteReturnFrame(stream, tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnRejected, Code: tunnelv1.StaleConnectionAssignment})
		return
	}
	until := minTime(request.Deadline, time.Now().Add(handshakeTimeout))
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	stopped := make(chan struct{})
	stop := context.AfterFunc(entry.ctx, func() { defer close(stopped); cancel() })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	err = entry.reserveOnce(call)
	code := tunnelv1.Unavailable
	var rejection *ProtocolError
	if errors.As(err, &rejection) {
		code = rejection.Code
	}
	frame := tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnAccepted}
	if err != nil || call.Err() != nil || !time.Now().Before(until) {
		frame.Kind, frame.Code = tunnelv1.ReturnRejected, code
	}
	_ = tunnelv1.WriteReturnFrame(stream, frame)
	return
}

func (e *serviceCapacity) reserveOnce(ctx context.Context) error {
	e.mu.Lock()
	if e.closed || e.ctx.Err() != nil || ctx.Err() != nil {
		e.mu.Unlock()
		return &ProtocolError{Code: tunnelv1.Unavailable}
	}
	first := e.done == nil
	if first {
		e.done = make(chan struct{})
	}
	done := e.done
	e.mu.Unlock()
	if first {
		e.result = errors.Join(e.reserve(ctx), context.Cause(ctx), context.Cause(e.ctx))
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			e.result = errors.Join(e.result, context.DeadlineExceeded)
		}
		close(done)
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-done:
		return errors.Join(e.result, context.Cause(e.ctx))
	}
}
