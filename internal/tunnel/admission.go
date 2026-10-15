package tunnel

import (
	"context"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PromoteVisitor waits for the complete publisher -> relay -> ingress capacity
// acknowledgement. it never writes to the visitor or the lifecycle control stream.
func (s *Session) PromoteVisitor(ctx context.Context, h tunnelv1.AdmissionHeader) error {
	stream, err := s.openAcknowledgedStream(ctx, "admission", func(stream muxsession.Stream) error {
		if err := tunnelv1.WriteAdmissionHeader(stream, h); err != nil {
			return err
		}
		// the decision is one frame. finish the request direction before the
		// receiver writes its acknowledgement and closes its read direction;
		// QUIC otherwise cancels an unfinished publisher stream.
		return stream.CloseWrite()
	})
	if err != nil {
		return err
	}
	return stream.Close()
}

// NewVisitorPromoter adapts the publisher's typed Visitor without importing its
// engine. resolve must return the exact live publisher session identified by the
// header; a replacement session cannot authorize an old visitor.
func NewVisitorPromoter[T any](header func(T) tunnelv1.VisitorStreamHeader, resolve func(string) *Session) func(context.Context, T) error {
	return func(ctx context.Context, v T) error {
		if header == nil || resolve == nil {
			return &ProtocolError{Code: tunnelv1.Unavailable}
		}
		h := header(v)
		if err := h.Validate(); err != nil {
			return err
		}
		if !h.IPPolicyDenied {
			return nil
		}
		s := resolve(h.PublisherConnectionID)
		if s == nil || s.Err() != nil || s.role != tunnelv1.Publisher || s.publisherConnection == nil {
			return &ProtocolError{Code: tunnelv1.Unavailable}
		}
		r := *s.publisherConnection
		if h.PublicURLID != r.PublicURLID || h.PublishRunID != r.PublishRunID || h.PublishRunNumber != r.PublishRunNumber ||
			h.PublisherConnectionID != r.PublisherConnectionID || h.ConnectionAssignmentRevision != r.ConnectionAssignmentRevision {
			return &ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
		ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
		return s.PromoteVisitor(ctx, tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream,
			VisitorConnectionID: h.VisitorConnectionID, PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID, PublishRunNumber: h.PublishRunNumber,
			PublisherConnectionID: h.PublisherConnectionID, ConnectionSlot: r.ConnectionSlot,
			ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: r.RelayServiceID})
	}
}

// ServeAdmissions uses a fixed number of header/decision workers. malformed or
// slow sidebands consume neither unbounded goroutines nor lifecycle control reads.
// only the receiver of the reverse stream direction calls this method.
func (s *Session) ServeAdmissions(ctx context.Context, kind tunnelv1.StreamKind, handle func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		workers.Go(func() {
			for {
				stream, err := s.acceptStream(ctx, "admission")
				if err != nil {
					errs <- err
					return
				}
				func() {
					defer stream.Close()
					requestCtx, stop := context.WithTimeout(ctx, handshakeTimeout)
					defer stop()
					// cancellation must interrupt a partial frame even on a live session.
					interrupt := context.AfterFunc(requestCtx, func() { _ = stream.SetDeadline(time.Now()) })
					defer interrupt()
					h, err := tunnelv1.ReadAdmissionHeader(stream)
					result := tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.InvalidMessage}
					if err == nil && h.Kind == kind && handle != nil {
						result = handle(requestCtx, h)
					}
					_ = tunnelv1.WriteAdmissionResult(stream, result)
				}()
			}
		})
	}
	var result error
	select {
	case <-ctx.Done():
	case <-s.Done():
	case result = <-errs:
	}
	cancel()
	workers.Wait()
	if parent.Err() != nil || s.Err() != nil {
		return nil
	}
	return result
}
