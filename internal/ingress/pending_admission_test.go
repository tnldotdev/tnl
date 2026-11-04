package ingress

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func pendingAdmissionFixture(t *testing.T) (*Server, *visitorAdmission, tunnelv1.AdmissionHeader, *PublicURL) {
	t.Helper()
	f := newTestForwarder(t, newForwardingTestMaterial(t))
	entry := forwardingTestEntry(time.Now(), "relay.internal:9445")
	entry.IpPolicy = "allow_all"
	route, err := f.PublicURL(entry)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := startIngress(t, Config{Lookup: func(string) ([]PublicURL, LookupReason) { return []PublicURL{route}, LookupCurrent }})
	v, reason := s.admitVisitor(route, netip.MustParseAddr("198.51.100.1"), true)
	if v == nil {
		t.Fatal(reason)
	}
	v.hostname = "route.example"
	public, peer := net.Pipe()
	t.Cleanup(func() { _ = public.Close(); _ = peer.Close() })
	remove := s.registerPendingVisitor("visitor_pending", v, public)
	t.Cleanup(func() { remove(); v.close() })
	return s, v, forwardingTestHeader(entry, "visitor_pending").Admission(), &route
}

func TestPendingPromotionTransfersCapacityExactlyOnce(t *testing.T) {
	s, v, h, _ := pendingAdmissionFixture(t)
	var group sync.WaitGroup
	var accepted atomic.Int32
	for range 20 {
		group.Go(func() {
			if s.PromotePendingAdmission(t.Context(), h).Type == tunnelv1.StreamAccepted {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 1 || s.Load() != 1 {
		t.Fatalf("accepted %d, ordinary %d", accepted.Load(), s.Load())
	}
	s.mu.Lock()
	pending := s.admitted[pendingConnection]
	s.mu.Unlock()
	if pending != 0 {
		t.Fatal("promotion retained pending capacity")
	}
	v.close()
	v.close()
	if s.Load() != 0 {
		t.Fatal("promotion leaked ordinary capacity")
	}
}

func TestPendingPromotionRechecksRunAssignmentAndCapacity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Server, *PublicURL)
		want   tunnelv1.ErrorCode
	}{
		{"run", func(_ *Server, r *PublicURL) { r.PublishRunNumber++ }, tunnelv1.StalePublishRunNumber},
		{"run-id", func(_ *Server, r *PublicURL) { r.PublishRunID = "replacement" }, tunnelv1.StalePublishRunNumber},
		{"assignment", func(_ *Server, r *PublicURL) {
			b := r.Backends[0].(forwardingBackend)
			b.header.ConnectionAssignmentRevision++
			r.Backends[0] = b
			r.assignments[0] = b.header.Admission()
		}, tunnelv1.StaleConnectionAssignment},
		{"capacity", func(s *Server, _ *PublicURL) {
			s.mu.Lock()
			s.admitted[visitorConnection] = s.config.MaxConnections
			s.mu.Unlock()
		}, tunnelv1.CapacityExceeded},
		{"draining", func(s *Server, _ *PublicURL) { s.mu.Lock(); s.closing = true; s.mu.Unlock() }, tunnelv1.Unavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _, h, route := pendingAdmissionFixture(t)
			test.change(s, route)
			result := s.PromotePendingAdmission(t.Context(), h)
			if result.Type != tunnelv1.StreamRejected || result.Code != test.want {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestPendingPromotionRejectsClosedVisitor(t *testing.T) {
	s, v, h, _ := pendingAdmissionFixture(t)
	v.close()
	result := s.PromotePendingAdmission(t.Context(), h)
	if result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.StalePublishRunNumber || s.Load() != 0 {
		t.Fatal("closed visitor acquired ordinary capacity", result, s.Load())
	}
}

func TestPendingPromotionFindsOnlyItsExactRunInPool(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*PublicURL)
		omit   bool
		reason LookupReason
		want   tunnelv1.ErrorCode
	}{
		{name: "exact run behind healthy sibling"},
		{name: "removed run", omit: true, want: tunnelv1.StalePublishRunNumber},
		{name: "changed public URL", change: func(r *PublicURL) { r.ID = "replacement" }, want: tunnelv1.StalePublishRunNumber},
		{name: "changed run number", change: func(r *PublicURL) { r.PublishRunNumber++ }, want: tunnelv1.StalePublishRunNumber},
		{name: "changed IP policy", change: func(r *PublicURL) { r.AllowAll = false }, want: tunnelv1.Unauthenticated},
		{name: "unavailable lookup", reason: LookupIngressUnavailable, want: tunnelv1.StalePublishRunNumber},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _, h, route := pendingAdmissionFixture(t)
			sibling := *route
			sibling.PublishRunID, sibling.PublishRunNumber = "healthy-sibling", route.PublishRunNumber+1
			if test.change != nil {
				test.change(route)
			}
			s.config.Lookup = func(string) ([]PublicURL, LookupReason) {
				candidates := []PublicURL{sibling}
				if !test.omit {
					candidates = append(candidates, *route)
				}
				return candidates, test.reason
			}
			// promotion checks an already-owned stream, not new pool capacity.
			s.poolRuns = map[string]int{route.PublishRunID: s.config.Traffic.Default.Connections}
			result := s.PromotePendingAdmission(t.Context(), h)
			if test.want == "" {
				if result.Type != tunnelv1.StreamAccepted || s.Load() != 1 {
					t.Fatal("exact run behind sibling was not promoted", result)
				}
			} else if result.Type != tunnelv1.StreamRejected || result.Code != test.want || s.Load() != 0 {
				t.Fatal("promotion switched to a sibling or accepted stale state", result)
			}
		})
	}
}

func TestPendingBytesAndTimeFailClosedWithoutOrdinaryCapacity(t *testing.T) {
	s, v, h, _ := pendingAdmissionFixture(t)
	if err := v.beforeWrite(t.Context(), true, int(s.config.Pending.UploadBytes)+1); err == nil {
		t.Fatal("pending upload exceeded bound")
	}
	if err := v.beforeWrite(t.Context(), false, int(s.config.Pending.DownloadBytes)+1); err == nil {
		t.Fatal("pending download exceeded bound")
	}
	v.mu.Lock()
	v.deadline = time.Now().Add(-time.Millisecond)
	v.mu.Unlock()
	if result := s.PromotePendingAdmission(t.Context(), h); result.Type != tunnelv1.StreamRejected {
		t.Fatal(result)
	}
	if s.Load() != 0 {
		t.Fatal("expired visitor acquired ordinary capacity")
	}
}

func TestPendingDeadlineClosesBothDirections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, _ := (TrafficConfig{}).Resolve()
		p, _ := (PendingConfig{}).Resolve()
		s := &Server{config: Config{Traffic: c, Pending: p}, pendingVisitors: map[string]*visitorAdmission{}}
		public, peer := net.Pipe()
		upstream, origin := net.Pipe()
		defer peer.Close()
		defer origin.Close()
		v := &visitorAdmission{server: s, release: func() {}, deadline: time.Now().Add(p.Timeout), upstream: upstream}
		remove := s.registerPendingVisitor("visitor", v, public)
		defer remove()
		defer v.close()
		time.Sleep(p.Timeout)
		synctest.Wait()
		if _, err := peer.Write([]byte("late")); err == nil {
			t.Fatal("public side remained open")
		}
		if _, err := origin.Write([]byte("late")); err == nil {
			t.Fatal("publisher side remained open")
		}
	})
}
