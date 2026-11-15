package ingress

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

type visitorAdmission struct {
	mu               sync.Mutex
	server           *Server
	key              trafficKey
	limits           TrafficLimits
	source           netip.Addr
	ordinary, closed bool
	metered          bool // ordinary byte accounting, not target permission.
	deadline         time.Time
	upload, download int64
	release          func()
}

// before control selects a run, only the process pending slot is known.
// control's anonymous fact selects ordinary accounting; other runs stay pending.
func (s *Server) admitPendingService() (*visitorAdmission, string) {
	release, reason := s.admitClass(pendingConnection)
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
	if v.closed {
		return
	}
	v.closed = true
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
	v.ordinary = true
	return ""
}

func (s *Server) observeTraffic(stage, result string) {
	if s.config.Metrics != nil {
		s.config.Metrics.ObserveTrafficAdmission(stage, result)
	}
}
