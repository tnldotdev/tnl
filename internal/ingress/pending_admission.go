package ingress

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type visitorAdmission struct {
	mu                          sync.Mutex
	server                      *Server
	key                         trafficKey
	source                      netip.Addr
	runID, hostname             string
	ordinary, closed, attempted bool
	deadline                    time.Time
	upload, download            int64
	release                     func()
	public, upstream            net.Conn
	timer                       *time.Timer
}

func (s *Server) selectedTraffic(route PublicURL) (TrafficLimits, bool) {
	l := s.config.Traffic.Default
	if route.Traffic != nil {
		l = *route.Traffic
	}
	return l, l.Within(s.config.Traffic.Ceiling)
}

func (s *Server) admitVisitor(route PublicURL, source netip.Addr, denied bool) (*visitorAdmission, string) {
	stage := "ordinary"
	if denied {
		stage = "pending"
	}
	accepted := false
	defer func() {
		result := "capacity"
		if accepted {
			result = "accepted"
		}
		s.observeTraffic(stage, result)
	}()
	l, valid := s.selectedTraffic(route)
	if !valid {
		return nil, "invalid_traffic_projection"
	}
	key := trafficKey{url: route.ID, run: route.PublishRunNumber, id: route.PublishRunID}
	kind := visitorConnection
	if denied {
		kind = pendingConnection
	}
	release, reason := s.admitClass(kind, route.ID)
	if release == nil {
		return nil, reason
	}
	var budgetRelease func()
	if denied {
		budgetRelease, reason = s.traffic.acquirePending(key, source)
	} else {
		budgetRelease, reason = s.traffic.acquire(key, l)
	}
	if budgetRelease == nil {
		release()
		return nil, reason
	}
	accepted = true
	return &visitorAdmission{server: s, key: key, source: source, runID: route.PublishRunID, ordinary: !denied,
		deadline: time.Now().Add(s.config.Pending.Timeout), upload: s.config.Pending.UploadBytes, download: s.config.Pending.DownloadBytes,
		release: func() { release(); budgetRelease() }}, ""
}

func (v *visitorAdmission) close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return
	}
	v.closed = true
	if v.timer != nil {
		v.timer.Stop()
	}
	v.release()
}

func (v *visitorAdmission) beforeWrite(ctx context.Context, upload bool, size int) error {
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		return net.ErrClosed
	}
	ordinary := v.ordinary
	if !ordinary {
		remaining := &v.download
		if upload {
			remaining = &v.upload
		}
		if !v.deadline.After(time.Now()) || int64(size) > *remaining {
			v.mu.Unlock()
			return trafficError("pending_byte_or_time_budget")
		}
		*remaining -= int64(size)
	}
	v.mu.Unlock()
	err := v.server.traffic.bytes(ctx, v.key, upload, size, ordinary)
	if err != nil {
		v.server.rejectCapacity("traffic_bandwidth")
		v.server.observeTraffic("bytes", "bandwidth")
	}
	return err
}

func (s *Server) registerPendingVisitor(id string, v *visitorAdmission, public net.Conn) func() {
	v.mu.Lock()
	v.public = public
	v.timer = time.AfterFunc(time.Until(v.deadline), func() {
		v.mu.Lock()
		expired := !v.ordinary && !v.closed
		public, upstream := v.public, v.upstream
		v.mu.Unlock()
		if expired {
			s.observeTraffic("pending", "expired")
			_ = public.Close()
			if upstream != nil {
				_ = upstream.Close()
			}
		}
	})
	v.mu.Unlock()
	s.mu.Lock()
	s.pendingVisitors[id] = v
	s.mu.Unlock()
	return func() { s.mu.Lock(); delete(s.pendingVisitors, id); s.mu.Unlock() }
}

// PromotePendingAdmission is called only after Forwarder has bound the full
// identity to the same live authenticated relay session and forwarding stream.
func (s *Server) PromotePendingAdmission(ctx context.Context, h tunnelv1.AdmissionHeader) (result tunnelv1.AdmissionResult) {
	defer func() {
		outcome := "stale"
		if result.Type == tunnelv1.StreamAccepted {
			outcome = "accepted"
		} else if result.Code == tunnelv1.CapacityExceeded {
			outcome = "capacity"
		}
		s.observeTraffic("promotion", outcome)
	}()
	reject := func(code tunnelv1.ErrorCode) tunnelv1.AdmissionResult {
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: code}
	}
	if h.Validate() != nil || h.Kind != tunnelv1.IngressPromotion {
		return reject(tunnelv1.InvalidMessage)
	}
	s.mu.Lock()
	v := s.pendingVisitors[h.VisitorConnectionID]
	closing := s.closing
	s.mu.Unlock()
	if v == nil || closing || ctx.Err() != nil {
		return reject(tunnelv1.Unavailable)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.ordinary || v.attempted || !v.deadline.After(time.Now()) || h.PublicURLID != v.key.url || h.PublishRunID != v.runID || h.PublishRunNumber != v.key.run {
		return reject(tunnelv1.StalePublishRunNumber)
	}
	v.attempted = true
	var current PublicURL
	var reason LookupReason
	if s.config.LookupPool != nil {
		var candidates []PublicURL
		candidates, reason = s.config.LookupPool(v.hostname)
		if reason == LookupCurrent {
			reason = LookupNotFound
			for _, candidate := range candidates {
				if candidate.PublishRunID == v.runID {
					current, reason = candidate, LookupCurrent
					break
				}
			}
		}
	} else {
		current, reason = s.config.Lookup(v.hostname)
	}
	if reason != LookupCurrent || current.ID != v.key.url || current.PublishRunNumber != v.key.run || current.PublishRunID != v.runID {
		return reject(tunnelv1.StalePublishRunNumber)
	}
	if !current.allowsIP(v.source) {
		return reject(tunnelv1.Unauthenticated)
	}
	// a routing refresh can replace the assignment while the visitor authorizes.
	matched := false
	for _, want := range current.assignments {
		want.VisitorConnectionID = h.VisitorConnectionID
		if want == h {
			matched = true
			break
		}
	}
	if !matched {
		return reject(tunnelv1.StaleConnectionAssignment)
	}
	l, valid := s.selectedTraffic(current)
	if !valid {
		return reject(tunnelv1.InvalidMessage)
	}
	release, resource := s.admitClass(visitorConnection, current.ID)
	if release == nil {
		s.rejectCapacity(resource)
		return reject(tunnelv1.CapacityExceeded)
	}
	budgetRelease, resource := s.traffic.acquire(v.key, l)
	if budgetRelease == nil {
		release()
		s.rejectCapacity(resource)
		return reject(tunnelv1.CapacityExceeded)
	}
	v.release()
	v.release = func() { release(); budgetRelease() }
	v.ordinary = true
	if v.timer != nil {
		v.timer.Stop()
	}
	return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
}

func (s *Server) observeTraffic(stage, result string) {
	if metrics, ok := s.config.Metrics.(interface{ ObserveTrafficAdmission(string, string) }); ok {
		metrics.ObserveTrafficAdmission(stage, result)
	}
}
