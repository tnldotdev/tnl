package worker

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/0xcadams/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEngineOwnsRouteLifecycle(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Capacity: 1, Profiles: testProfiles()})
	if err != nil {
		t.Fatal(err)
	}
	var created []*fakeDialer
	engine.newDialer = func(tailtransport.DialerConfig) (leaseDialer, error) {
		dialer := new(fakeDialer)
		created = append(created, dialer)
		return dialer, nil
	}
	assignment := testAssignment("route-1", 1)
	first, err := engine.Attach(context.Background(), assignment)
	if err != nil {
		t.Fatal(err)
	}
	if capacity := engine.Capacity(); capacity.Active != 1 || capacity.Limit != 1 || capacity.Draining {
		t.Fatalf("capacity = %#v", capacity)
	}
	if _, err := first.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Attach(context.Background(), testAssignment("route-2", 1)); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("capacity error = %v", err)
	}

	replacement, err := engine.Attach(context.Background(), testAssignment("route-1", 2))
	if err != nil {
		t.Fatal(err)
	}
	replacementDialer := created[len(created)-1]
	if created[0].closes.Load() != 1 {
		t.Fatal("replacement did not close old route")
	}
	if _, err := first.Open(context.Background()); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("old backend error = %v", err)
	}
	if _, err := engine.Attach(context.Background(), assignment); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("stale attach error = %v", err)
	}
	if err := engine.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Open(context.Background()); !errors.Is(err, ErrDraining) {
		t.Fatalf("open while draining error = %v", err)
	}
	if replacementDialer.drains.Load() != 1 {
		t.Fatal("engine did not drain active route")
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if replacementDialer.closes.Load() != 1 {
		t.Fatal("engine did not close active route")
	}
}

func testAssignment(routeID string, generation uint64) Assignment {
	return Assignment{
		RouteRef: RouteRef{RouteID: routeID, Generation: generation},
		Endpoint: tailtransport.Endpoint{Version: 1, ServerPublicKey: key.NewNode().Public().String(), RelayProfile: "test"},
		Key:      key.NewNode(),
	}
}

func testProfiles() map[string]*tailcfg.DERPRegion {
	return map[string]*tailcfg.DERPRegion{"test": {
		RegionID: 1,
		Nodes:    []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
	}}
}

type fakeDialer struct {
	drains atomic.Int32
	closes atomic.Int32
}

func (*fakeDialer) Start(context.Context) error { return nil }

func (*fakeDialer) Open(context.Context) (net.Conn, error) {
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func (d *fakeDialer) Drain(context.Context) error {
	d.drains.Add(1)
	return nil
}

func (d *fakeDialer) Close() error {
	d.closes.Add(1)
	return nil
}
