package ingress

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const pendingAuthorizationTimeout = 10 * time.Second

type pendingVisitorState struct {
	ticket   *classTicket
	urlID    string
	run      uint64
	hostname string
	port     uint16
	byPort   bool
	deadline time.Time
}

func (s *Server) registerPendingVisitor(id string, value *pendingVisitorState) func() {
	s.mu.Lock()
	if s.pendingVisitors == nil {
		s.pendingVisitors = make(map[string]*pendingVisitorState)
	}
	s.pendingVisitors[id] = value
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		if s.pendingVisitors[id] == value {
			delete(s.pendingVisitors, id)
		}
		s.mu.Unlock()
	}
}

// PromotePendingAdmission rechecks the live public URL before transferring a
// publisher-authorized connection to ordinary ingress capacity.
func (s *Server) PromotePendingAdmission(ctx context.Context, header tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
	reject := func(code tunnelv1.ErrorCode) tunnelv1.AdmissionResult {
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: code}
	}
	if ctx.Err() != nil || header.Kind != tunnelv1.IngressAdmissionStream {
		return reject(tunnelv1.Unavailable)
	}
	s.mu.Lock()
	value := s.pendingVisitors[header.VisitorConnectionID]
	closing := s.closing
	s.mu.Unlock()
	if value == nil || closing || header.PublicURLID != value.urlID || header.PublishRunNumber != value.run ||
		!value.deadline.After(time.Now()) {
		return reject(tunnelv1.StalePublishRunNumber)
	}
	var current PublicURL
	var reason LookupReason
	if value.byPort {
		current, reason = s.config.LookupPort(value.port)
	} else {
		current, reason = s.config.Lookup(value.hostname)
	}
	if reason != LookupCurrent || current.ID != value.urlID || current.PublishRunNumber != value.run {
		return reject(tunnelv1.StalePublishRunNumber)
	}
	limits := s.config.Traffic.Default
	if current.Traffic != nil {
		limits = *current.Traffic
	}
	return value.ticket.promote(s, trafficKey{url: value.urlID, run: value.run}, limits)
}
