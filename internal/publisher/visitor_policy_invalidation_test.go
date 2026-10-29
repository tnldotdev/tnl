package publisher

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestVisitorPolicyRevisionClosesStreamsWithoutStoppingPublisher(t *testing.T) {
	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()
	route := &PublicURLServer{streams: map[net.Conn]*publicVisitorAdmission{stream: nil}}
	policy, update, token := httpPermissionFixture(t, false)
	view, _, _ := policy.Current()
	permission, err := visitortoken.VerifyBearer(token, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := policy.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() { _ = stream.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	update.View.VisitorPolicyRevision++
	now := time.Now()
	update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("old visitor stream survived authority revision")
	}
	if route.closed || route.draining {
		t.Fatal("authority change stopped team-owned publisher")
	}
}
