package publisher

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the registry retains only the current session for each connection slot. an
// old visitor can never resolve a replacement through a shared relay address.
func (r *PublicURLServer) registerPublisherSession(ctx context.Context, session *tunnel.Session, ref tunnelv1.PublisherConnectionRef) (*livePublisherSession, error) {
	if r.run.PublicURLID != "" && r.run.PublicURLID != ref.PublicURLID || r.run.Number != 0 && r.run.Number != ref.PublishRunNumber ||
		r.run.PublishRunID != "" && r.run.PublishRunID != ref.PublishRunID {
		return nil, errors.New("publisher: session belongs to a different publish run")
	}
	life, cancel := context.WithCancel(r.life)
	stop := context.AfterFunc(ctx, cancel)
	live := &livePublisherSession{session: session, ref: ref, ctx: life, cancel: func() { stop(); cancel() }}
	r.mu.Lock()
	old := r.sessions[ref.ConnectionSlot]
	if r.closed || r.draining || old != nil && old.ctx.Err() == nil && ref.ConnectionAssignmentRevision <= old.ref.ConnectionAssignmentRevision {
		r.mu.Unlock()
		live.cancel()
		return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	r.sessions[ref.ConnectionSlot] = live
	r.mu.Unlock()
	if old != nil {
		old.cancel()
		_ = old.session.Close()
	}
	return live, nil
}

func (r *PublicURLServer) unregisterPublisherSession(live *livePublisherSession) {
	live.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[live.ref.ConnectionSlot] == live {
		r.sessions[live.ref.ConnectionSlot] = nil
	}
}

func (r *PublicURLServer) resolvePublisherSession(id string) *tunnel.Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	for _, live := range r.sessions {
		if live != nil && live.ref.PublisherConnectionID == id && live.ctx.Err() == nil && live.session.Err() == nil {
			return live.session
		}
	}
	return nil
}
