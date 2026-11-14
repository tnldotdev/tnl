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
	limits                      TrafficLimits
	source                      netip.Addr
	runID, hostname             string
	ordinary, closed, attempted bool
	metered                     bool // ordinary byte accounting, not target permission.
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
	key := trafficKey{service: route.ID, run: route.PublishRunNumber, id: route.PublishRunID}
	admission, reason := s.admitTrafficVisitor(key, l, source, denied)
	accepted = admission != nil
	return admission, reason
}

func (s *Server) admitTrafficVisitor(key trafficKey, limits TrafficLimits, source netip.Addr, denied bool) (*visitorAdmission, string) {
	kind := visitorConnection
	if denied {
		kind = pendingConnection
	}
	release, reason := s.admitClass(kind, key.service)
	if release == nil {
		return nil, reason
	}
	var budgetRelease func()
	if denied {
		budgetRelease, reason = s.traffic.acquirePending(key, source)
	} else {
		budgetRelease, reason = s.traffic.acquire(key, limits)
	}
	if budgetRelease == nil {
		release()
		return nil, reason
	}
	return &visitorAdmission{server: s, key: key, limits: limits, source: source, runID: key.id, ordinary: !denied, metered: !denied,
		deadline: time.Now().Add(s.config.Pending.Timeout), upload: s.config.Pending.UploadBytes, download: s.config.Pending.DownloadBytes,
		release: func() { release(); budgetRelease() }}, ""
}

// before control selects a run, only the process pending slot is known.
// control's anonymous fact selects ordinary accounting; other runs stay pending.
func (s *Server) admitPendingService() (*visitorAdmission, string) {
	release, reason := s.admitClass(pendingConnection, "")
	if release == nil {
		return nil, reason
	}
	return &visitorAdmission{server: s, release: release,
		deadline: time.Now().Add(s.config.Pending.Timeout), upload: s.config.Pending.UploadBytes, download: s.config.Pending.DownloadBytes}, ""
}

func (v *visitorAdmission) selectRun(key trafficKey, limits TrafficLimits, source netip.Addr, anonymous bool) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed || v.ordinary || v.key.service != "" {
		return "service_already_selected"
	}
	if !limits.Within(v.server.config.Traffic.Ceiling) {
		return "invalid_traffic_projection"
	}
	v.key, v.limits, v.source, v.runID = key, limits, source, key.id
	if anonymous {
		// anonymous is an explicit control accounting fact, not target permission.
		// skip pending run/source buckets and debit the ordinary run before open.
		if reason := v.reserveLocked(limits); reason != "" {
			return reason
		}
		v.metered = true
		return ""
	}
	budgetRelease, reason := v.server.traffic.acquirePending(key, source)
	if budgetRelease == nil {
		return reason
	}
	release := v.release
	v.release = func() { release(); budgetRelease() }
	return ""
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
	ordinary := v.ordinary && v.metered
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
	if v.closed || v.ordinary || v.attempted || !v.deadline.After(time.Now()) || h.PublicURLID != v.key.service || h.PublishRunID != v.runID || h.PublishRunNumber != v.key.run {
		return reject(tunnelv1.StalePublishRunNumber)
	}
	v.attempted = true
	var current PublicURL
	candidates, reason := s.config.Lookup(v.hostname)
	if reason == LookupCurrent {
		reason = LookupNotFound
		for _, candidate := range candidates {
			if candidate.PublishRunID == v.runID && candidate.ID == v.key.service && candidate.PublishRunNumber == v.key.run {
				current, reason = candidate, LookupCurrent
				break
			}
		}
	}
	if reason != LookupCurrent {
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
	if resource := v.reserveLocked(l); resource != "" {
		s.rejectCapacity(resource)
		return reject(tunnelv1.CapacityExceeded)
	}
	v.metered = true
	return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
}

func (v *visitorAdmission) reserve(limits TrafficLimits) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reserveLocked(limits)
}

func (v *visitorAdmission) meterOrdinaryBytes() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.metered = true
}

func (v *visitorAdmission) reserveLocked(limits TrafficLimits) string {
	if v.closed || v.ordinary || !v.deadline.After(time.Now()) {
		return "pending_expired"
	}
	s := v.server
	release, resource := s.admitClass(visitorConnection, v.key.service)
	if release == nil {
		return resource
	}
	budgetRelease, resource := s.traffic.acquire(v.key, limits)
	if budgetRelease == nil {
		release()
		return resource
	}
	v.release()
	v.release = func() { release(); budgetRelease() }
	v.ordinary = true
	if v.timer != nil {
		v.timer.Stop()
	}
	return ""
}

func (s *Server) observeTraffic(stage, result string) {
	if s.config.Metrics != nil {
		s.config.Metrics.ObserveTrafficAdmission(stage, result)
	}
}
