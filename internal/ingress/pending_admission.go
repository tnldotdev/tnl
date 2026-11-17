package ingress

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

type visitorCapacityState uint8

const (
	pendingCapacity visitorCapacityState = iota
	reservedCapacity
	closedCapacity
)

type visitorAdmission struct {
	mu               sync.Mutex
	server           *Server
	key              trafficKey
	limits           TrafficLimits
	source           netip.Addr
	state            visitorCapacityState
	processPending   bool
	metered          bool // ordinary byte accounting, not target permission.
	deadline         time.Time
	upload, download int64
	release          func()
	copyReady        chan struct{}
}

func (s *Server) newServiceAdmission() *visitorAdmission {
	return &visitorAdmission{server: s, release: func() {}, copyReady: make(chan struct{}),
		deadline: time.Now().Add(s.config.Pending.Timeout), upload: s.config.Pending.UploadBytes, download: s.config.Pending.DownloadBytes}
}

// unknown policy waits and restricted selections need process pending capacity.
// a cached anonymous selection acquires ordinary capacity directly instead.
func (s *Server) admitPendingService() (*visitorAdmission, string) {
	v := s.newServiceAdmission()
	if reason := v.admitPending(); reason != "" {
		return nil, reason
	}
	return v, ""
}

func (v *visitorAdmission) admitPending() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.admitPendingLocked()
}

func (v *visitorAdmission) admitPendingLocked() string {
	if v.state != pendingCapacity || !v.deadline.After(time.Now()) {
		return "pending_expired"
	}
	if !v.processPending {
		release, reason := v.server.admitClass(pendingConnection)
		if release == nil {
			return reason
		}
		v.release, v.processPending = release, true
	}
	return ""
}

func (v *visitorAdmission) selectRun(key trafficKey, limits TrafficLimits, source netip.Addr, anonymous bool) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state != pendingCapacity || v.key.service != "" {
		return "service_already_selected"
	}
	if !limits.Within(v.server.config.Traffic.Ceiling) {
		return "invalid_traffic_projection"
	}
	if !v.deadline.After(time.Now()) {
		return "pending_expired"
	}
	if anonymous {
		// anonymous is an explicit control accounting fact, not target permission.
		// skip pending run/source buckets and debit the ordinary run before open.
		v.key = key
		if reason := v.reserveLocked(limits); reason != "" {
			v.key = trafficKey{}
			return reason
		}
		v.metered = true
	} else {
		if reason := v.admitPendingLocked(); reason != "" {
			return reason
		}
		budgetRelease, reason := v.server.traffic.acquirePending(key, source)
		if budgetRelease == nil {
			return reason
		}
		release := v.release
		v.release = func() { release(); budgetRelease() }
	}
	v.key, v.limits, v.source = key, limits, source
	return ""
}

func (v *visitorAdmission) close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == closedCapacity {
		return
	}
	v.state = closedCapacity
	v.signalCopyLocked()
	v.release()
}

func (v *visitorAdmission) beforeWrite(ctx context.Context, upload bool, size int) error {
	_, err := v.reserveBytes(ctx, upload, size, false)
	return err
}

// only cached http copying may fragment at the pending bound and wait for the
// existing metering acknowledgment. direct callers retain strict overflow.
func (v *visitorAdmission) reserveHTTPCopy(ctx context.Context, upload bool, size int) (int, error) {
	return v.reserveBytes(ctx, upload, size, true)
}

func (v *visitorAdmission) reserveBytes(ctx context.Context, upload bool, size int, fragment bool) (int, error) {
	for {
		if fragment && ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		v.mu.Lock()
		if v.state == closedCapacity {
			v.mu.Unlock()
			return 0, net.ErrClosed
		}
		ordinary := v.state == reservedCapacity && v.metered
		allowed := size
		if !ordinary {
			remaining := &v.download
			if upload {
				remaining = &v.upload
			}
			if !v.deadline.After(time.Now()) || (!fragment && int64(size) > *remaining) {
				v.mu.Unlock()
				return 0, trafficError("pending_byte_or_time_budget")
			}
			if fragment {
				allowed = int(min(int64(size), *remaining))
				if allowed == 0 {
					ready, deadline := v.copyReady, v.deadline
					v.mu.Unlock()
					timer := time.NewTimer(time.Until(deadline))
					select {
					case <-ctx.Done():
						timer.Stop()
						return 0, context.Cause(ctx)
					case <-ready:
						timer.Stop()
					case <-timer.C:
					}
					continue
				}
			}
			// reserve before accounting or writing, without refunding uncertain
			// partial writes. both directions share this locked phase check.
			*remaining -= int64(allowed)
		}
		key := v.key
		v.mu.Unlock()
		// live copying uses the capacity guard's cancelable context, not a
		// context permanently fenced by the obsolete setup deadline.
		err := v.server.traffic.bytes(ctx, key, upload, allowed, ordinary)
		if err != nil {
			v.server.rejectCapacity("traffic_bandwidth")
			v.server.observeTraffic("bytes", "bandwidth")
		}
		return allowed, err
	}
}

func (v *visitorAdmission) reserve(limits TrafficLimits) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.reserveLocked(limits)
}

func (v *visitorAdmission) reserveForVisitor() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == closedCapacity || !v.deadline.After(time.Now()) {
		return "pending_expired"
	}
	if v.state == reservedCapacity {
		return ""
	}
	return v.reserveLocked(v.limits)
}

func (v *visitorAdmission) meterOrdinaryBytes() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == reservedCapacity && !v.metered {
		v.metered = true
		v.signalCopyLocked()
	}
}

func (v *visitorAdmission) signalCopyLocked() {
	select {
	case <-v.copyReady:
	default:
		close(v.copyReady)
	}
}

func (v *visitorAdmission) reserveLocked(limits TrafficLimits) string {
	if v.state != pendingCapacity || !v.deadline.After(time.Now()) {
		return "pending_expired"
	}
	s := v.server
	release, resource := s.admitClass(visitorConnection)
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
	v.state = reservedCapacity
	return ""
}

func (s *Server) observeTraffic(stage, result string) {
	if s.config.Metrics != nil {
		s.config.Metrics.ObserveTrafficAdmission(stage, result)
	}
}
