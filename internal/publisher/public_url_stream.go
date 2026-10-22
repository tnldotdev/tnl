package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
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
	code := r.validateIncomingPublicURL(incoming.Header, ref)
	r.mu.Lock()
	if r.closed || r.draining {
		code = tunnelv1.Unavailable
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
		r.mu.Lock()
		delete(r.streams, incoming.Stream)
		r.mu.Unlock()
		r.handlers.Done()
		return err
	}
	go func() {
		defer r.handlers.Done()
		defer func() {
			r.mu.Lock()
			delete(r.streams, incoming.Stream)
			r.mu.Unlock()
		}()
		r.handleVisitorHeaderContext(incoming.Context(), incoming.Stream, incoming.Header.AccessPending, incoming.Header)
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
	return ""
}

func (r *PublicURLServer) handle(connection net.Conn) {
	r.handleVisitor(connection, false)
}

func (r *PublicURLServer) handleVisitor(connection net.Conn, denied bool) {
	r.handleVisitorHeader(connection, denied, tunnelv1.VisitorStreamHeader{})
}

func (r *PublicURLServer) handleVisitorHeader(connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader) {
	r.handleVisitorHeaderContext(r.life, connection, denied, streamHeader)
}

func (r *PublicURLServer) handleVisitorHeaderContext(parent context.Context, connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader) {
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
	header, replay, err := proxyproto.Decode(connection)
	if err != nil {
		visitorErr = err
		return
	}
	promote := r.promote
	if promote == nil && streamHeader.PublisherConnectionID != "" {
		promote = r.defaultPromote
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
	err = secured.HandshakeContext(ctx)
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
