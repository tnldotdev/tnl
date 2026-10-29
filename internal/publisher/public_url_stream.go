package publisher

import (
	"context"
	"crypto/tls"
	"errors"
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
		live.visitors.Wait()
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
				if err := r.acceptVisitorForSession(acceptCtx, incoming, live); err != nil {
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

func (r *PublicURLServer) acceptVisitorForSession(ctx context.Context, incoming *tunnel.IncomingVisitorStream, live *livePublisherSession) error {
	if live == nil || ctx.Err() != nil {
		_ = incoming.Reject(tunnelv1.Unavailable)
		return nil
	}
	code := r.validateIncomingPublicURL(incoming.Header, live.ref)
	if code != "" {
		_ = incoming.Reject(code)
		return nil
	}
	admission, code := r.reservePublicSetup(live, incoming.Stream)
	if code != "" {
		_ = incoming.Reject(code)
		return nil
	}
	if err := incoming.Accept(); err != nil {
		admission.retire()
		return nil
	}
	go r.handleVisitor(incoming.Context(), admission, incoming.Header)
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

func (r *PublicURLServer) handleVisitor(parent context.Context, admission *publicVisitorAdmission, streamHeader tunnelv1.VisitorStreamHeader) {
	defer admission.retire()
	connection := admission.connection
	denied := streamHeader.AccessPending
	parent = observability.NarrowIdentity(parent, observability.Identity{PublicURLID: r.run.PublicURLID})
	parent = observability.WithFields(parent, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "direct", Exposure: "public"})
	parent = observability.WithVisitor(parent, streamHeader.VisitorConnectionID)
	life, cancel := context.WithCancel(parent)
	defer cancel()
	life, endVisitor := observability.Start(life, "publisher.visitor")
	var visitorErr error
	defer func() { endVisitor(visitorErr) }()
	closeDone := make(chan struct{})
	stopClose := context.AfterFunc(life, func() { defer close(closeDone); _ = connection.Close() })
	defer func() {
		if !stopClose() {
			<-closeDone
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	header, replay, err := proxyproto.Decode(connection)
	if err != nil {
		visitorErr = err
		return
	}
	if err := r.authenticateVisitorSource(streamHeader, header); err != nil {
		visitorErr = err
		return
	}
	promote := r.promote
	if promote == nil && streamHeader.PublisherConnectionID != "" {
		promote = r.defaultPromote
	}
	session := &visitorSession{visitor: Visitor{Run: r.run, Header: streamHeader, Source: header.Source, Destination: header.Destination}, promote: promote, guard: r.guard, life: life, cancel: cancel, capacity: admission}
	defer session.close()
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
