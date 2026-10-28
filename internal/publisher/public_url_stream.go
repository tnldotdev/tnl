package publisher

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ServePublisherConnection accepts visitor streams for one exact publisher
// connection. on exit it closes the session to stop pending header reads;
// callers may also close it to interrupt active streams.
func (r *PublicURLServer) ServePublisherConnection(
	ctx context.Context,
	session *tunnel.Session,
	ref tunnelv1.PublisherConnectionRef,
) error {
	if session == nil {
		return errors.New("publisher: tunnel session is required")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	live, err := r.registerPublisherSession(ctx, session, ref)
	if err != nil {
		return err
	}
	defer r.unregisterPublisherSession(live)
	ctx = live.ctx
	// bound header parsing while letting a slow or invalid stream coexist with
	// healthy streams on the same publisher connection.
	const headerReaders = 4
	acceptCtx, cancel := context.WithCancel(ctx)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		_ = session.Close()
		readers.Wait()
	}()
	results := make(chan error, headerReaders)
	for range headerReaders {
		readers.Go(func() {
			for {
				incoming, err := session.AcceptVisitorStream(acceptCtx)
				if err != nil {
					var headerErr *tunnel.StreamHeaderError
					if errors.As(err, &headerErr) {
						continue
					}
					results <- err
					return
				}
				if acceptCtx.Err() != nil {
					_ = incoming.Stream.Close()
					return
				}
				if err := r.acceptVisitorContext(acceptCtx, incoming, ref); err != nil {
					results <- err
					return
				}
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-results:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func (r *PublicURLServer) acceptVisitorContext(ctx context.Context, incoming *tunnel.IncomingVisitorStream, ref tunnelv1.PublisherConnectionRef) error {
	var prepared *preparedVisitorProxy
	if incoming.Header.ConfirmBeforeBytes {
		// confirmed openings contain only ingress-owned metadata. reject a bad
		// source before the relay permits ingress to send any visitor bytes.
		header, reader, err := proxyproto.Decode(bytes.NewReader(incoming.TakeInitial()))
		if err != nil {
			_ = incoming.Reject(tunnelv1.InvalidMessage)
			return nil
		}
		prepared = &preparedVisitorProxy{header: header, reader: io.MultiReader(reader, incoming.Stream)}
	}
	code := r.validateIncomingPublicURL(incoming.Header, ref)
	r.mu.Lock()
	if r.closed || r.draining {
		code = tunnelv1.Unavailable
	}
	if code == "" && len(r.streams) >= r.streamCapacity {
		code = tunnelv1.CapacityExceeded
	}
	var reservation *visitorlease.ReservationGuard
	if code == "" {
		var err error
		reservation, err = r.policy.BindReservation(incoming.Header.Reservation, func() { _ = incoming.Stream.Close() })
		if err != nil {
			code = tunnelv1.Unauthenticated
		} else if prepared != nil && reservation.BindSource(prepared.header.Source.Addr()) != nil {
			reservation.Close()
			code = tunnelv1.Unauthenticated
		}
	}
	if code != "" {
		r.mu.Unlock()
		_ = incoming.Reject(code)
		return nil
	}
	r.streams[incoming.Stream] = struct{}{}
	r.handlers.Add(1)
	r.mu.Unlock()
	if err := incoming.Accept(); err != nil {
		_ = incoming.Stream.Close()
		reservation.Close()
		r.mu.Lock()
		delete(r.streams, incoming.Stream)
		r.mu.Unlock()
		r.handlers.Done()
		// a confirmation write may fail after the peer closes this stream. keep
		// the publisher connection and its unrelated visitors alive.
		return nil
	}
	go func() {
		defer reservation.Close()
		defer r.handlers.Done()
		defer func() {
			r.mu.Lock()
			delete(r.streams, incoming.Stream)
			r.mu.Unlock()
		}()
		r.handleVisitorPreparedContext(incoming.Context(), incoming.Stream, incoming.Header.AccessPending, incoming.Header, reservation, prepared)
	}()
	return nil
}

func (r *PublicURLServer) validateIncomingPublicURL(
	header tunnelv1.VisitorStreamHeader,
	ref tunnelv1.PublisherConnectionRef,
) tunnelv1.ErrorCode {
	if header.PublicURLID != ref.PublicURLID || header.PublishRunID != ref.PublishRunID ||
		header.PublishRunNumber != ref.PublishRunNumber {
		return tunnelv1.StalePublishRunNumber
	}
	if header.PublisherConnectionID != ref.PublisherConnectionID ||
		header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision {
		return tunnelv1.StaleConnectionAssignment
	}
	reservation := header.Reservation
	if reservation.ResourceKind != "public_url" || reservation.ResourceID != header.PublicURLID || reservation.RunID != header.PublishRunID || reservation.RunNumber != header.PublishRunNumber || reservation.VisitorConnectionID != header.VisitorConnectionID {
		return tunnelv1.InvalidMessage
	}
	if r.policy == nil || r.policy.ValidateReservation(reservation) != nil {
		return tunnelv1.Unauthenticated
	}
	return ""
}

func (r *PublicURLServer) handle(connection net.Conn) {
	r.handleVisitor(connection, false)
}

func (r *PublicURLServer) handleVisitor(connection net.Conn, denied bool) {
	r.handleVisitorHeader(connection, denied, tunnelv1.VisitorStreamHeader{})
}

func (r *PublicURLServer) handleVisitorHeader(connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader) {
	r.handleVisitorHeaderContext(r.life, connection, denied, streamHeader, nil)
}

func (r *PublicURLServer) handleVisitorHeaderContext(parent context.Context, connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader, reservation *visitorlease.ReservationGuard) {
	r.handleVisitorPreparedContext(parent, connection, denied, streamHeader, reservation, nil)
}

type preparedVisitorProxy struct {
	header proxyproto.Header
	reader io.Reader
}

func (r *PublicURLServer) handleVisitorPreparedContext(parent context.Context, connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader, reservation *visitorlease.ReservationGuard, prepared *preparedVisitorProxy) {
	defer connection.Close()
	if parent == nil {
		parent = context.Background()
	}
	parent = observability.NarrowIdentity(parent, observability.Identity{PublicURLID: r.run.PublicURLID})
	parent = observability.WithFields(parent, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "direct", Exposure: "public"})
	parent = observability.WithVisitor(parent, streamHeader.VisitorConnectionID)
	life, cancel := context.WithCancel(parent)
	defer cancel()
	life, endVisitor := observability.Start(life, "publisher.visitor")
	var visitorErr error
	defer func() { endVisitor(visitorErr) }()
	stopClose := context.AfterFunc(life, func() { _ = connection.Close() })
	defer stopClose()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	var header proxyproto.Header
	var replay io.Reader
	if prepared != nil {
		header, replay = prepared.header, prepared.reader
	} else {
		var err error
		header, replay, err = proxyproto.Decode(connection)
		if err != nil {
			visitorErr = err
			return
		}
		if reservation != nil {
			if err := reservation.BindSource(header.Source.Addr()); err != nil {
				visitorErr = err
				return
			}
		}
	}
	promote := r.promote
	if promote == nil && streamHeader.PublisherConnectionID != "" && denied {
		promote = func(ctx context.Context, visitor Visitor) error {
			return r.promoteVisitorStream(ctx, visitor, connection)
		}
	}
	streamHeader.AccessPending = denied
	session := &visitorSession{visitor: Visitor{Run: r.run, Header: streamHeader, Source: header.Source, Destination: header.Destination}, promote: promote, guard: r.guard, life: life, cancel: cancel}
	defer session.close()
	var pendingTimer *time.Timer
	if denied {
		pendingTimer = time.AfterFunc(visitorPromotionTimeout, cancel)
		defer pendingTimer.Stop()
	}
	session.onPromoted = func() {
		if pendingTimer != nil {
			pendingTimer.Stop()
		}
		// net/http owns request-body read deadlines. clearing both deadlines
		// here would let incomplete bodies hold application slots indefinitely.
		_ = connection.SetWriteDeadline(time.Time{})
	}
	metadata := &metadataConn{Conn: &publicURLReaderConn{Conn: connection, reader: replay}, header: header, denied: denied, session: session}
	tracked := newDoneConn(metadata)
	secured := tls.Server(tracked, r.tls)
	ctx, cancelHandshake := context.WithTimeout(life, 10*time.Second)
	ctx = observability.WithVisitor(ctx, streamHeader.VisitorConnectionID)
	ctx, finish := observability.PublisherOperation(ctx, "visitor_tls")
	err := secured.HandshakeContext(ctx)
	visitorErr = err
	observability.PublisherTLS(ctx, "visitor", secured.ConnectionState(), err)
	finish(err)
	cancelHandshake()
	if err != nil {
		_ = secured.Close()
		return
	}
	if denied {
		_ = secured.SetDeadline(time.Now().Add(visitorPromotionTimeout))
	} else {
		_ = secured.SetDeadline(time.Time{})
	}
	if !r.queue.enqueue(secured) {
		_ = secured.Close()
		return
	}
	<-tracked.done
}
