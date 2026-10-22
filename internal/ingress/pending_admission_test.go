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
	s, _ := startIngress(t, Config{Lookup: func(string) (PublicURL, LookupReason) { return route, LookupCurrent }})
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
