package visitorlease

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicEndpointChangeKeepsAuthorizedConnector(t *testing.T) {
	for _, change := range []string{"removed", "revision", "hostname", "port"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, permission := connectorGuardFixture(t)
				endpoint := controlv1.VisitorPublicEndpoint{Hostname: update.View.Hostname, Port: 25432, EndpointRevision: 4}
				update.PublicEndpoint = &endpoint
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				source := netip.MustParseAddr("192.0.2.1")
				var publicStops, connectorStops atomic.Int32
				public, err := lease.BindPublicConnection(endpoint, source, func() { publicStops.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer public.Close()
				connector, err := lease.BindConnector(permission, source, update.View.MetadataRevision, func() { connectorStops.Add(1) })
				if err != nil {
					t.Fatal(err)
				}
				defer connector.Close()
				next := endpoint
				switch change {
				case "removed":
					update.PublicEndpoint = nil
				case "revision":
					next.EndpointRevision++
				case "hostname":
					next.Hostname = "new.example"
				case "port":
					next.Port++
				}
				if change != "removed" {
					update.PublicEndpoint = &next
				}
				time.Sleep(time.Second)
				update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				if publicStops.Load() != 1 || connectorStops.Load() != 0 {
					t.Fatal("endpoint change did not stop only the public connection", publicStops.Load(), connectorStops.Load())
				}
				if _, err := connector.Current(); err != nil {
					t.Fatal("endpoint change revoked independent connector permission", err)
				}
				if guard, err := lease.BindPublicConnection(endpoint, source, func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
					if guard != nil {
						guard.Close()
					}
					t.Fatal("an old endpoint opened a new public connection", err)
				}
			})
		})
	}
}

func TestPublicEndpointFixedAuthorityFollowsRefreshAndExpiresWithoutControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		endpoint := controlv1.VisitorPublicEndpoint{Hostname: update.View.Hostname, Port: 443, EndpointRevision: 1}
		update.PublicEndpoint = &endpoint
		update.BoundConnections = true
		update.View.ValidUntil = time.Now().Add(10 * time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stops atomic.Int32
		guard, err := lease.BindPublicConnection(endpoint, netip.MustParseAddr("192.0.2.1"), func() { stops.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(5 * time.Second)
		update.View.ObservedAt, update.View.ValidUntil = time.Now(), time.Now().Add(10*time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		time.Sleep(6 * time.Second)
		synctest.Wait()
		if stops.Load() != 0 {
			t.Fatal("normal policy refresh stopped an unchanged public connection")
		}
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if stops.Load() != 1 {
			t.Fatal("an idle public connection outlived policy expiry", stops.Load())
		}
	})
}

func TestPublicEndpointExpiryKeepsOrdinaryIdleSocketButDeniesNewUse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		endpoint := controlv1.VisitorPublicEndpoint{Hostname: update.View.Hostname, Port: 443, EndpointRevision: 1}
		update.PublicEndpoint = &endpoint
		update.Anonymous = true
		update.View.ValidUntil = time.Now().Add(time.Second)
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		var stops atomic.Int32
		source := netip.MustParseAddr("192.0.2.1")
		guard, err := lease.BindPublicConnection(endpoint, source, func() { stops.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		time.Sleep(time.Second)
		synctest.Wait()
		if stops.Load() != 0 {
			t.Fatal("request-level expiry closed an ordinary idle socket")
		}
		if next, err := lease.BindPublicConnection(endpoint, source, func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
			if next != nil {
				next.Close()
			}
			t.Fatal("expired policy opened another connection", err)
		}
		if request, err := lease.BindAnonymous(source, func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
			if request != nil {
				request.Close()
			}
			t.Fatal("the idle socket granted a new request after policy expiry", err)
		}
	})
}

func TestPublicEndpointUsesCurrentIPPolicyAndCopiesCallerValues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, update, _ := fixture(t)
		endpoint := controlv1.VisitorPublicEndpoint{Hostname: update.View.Hostname, Port: 443, EndpointRevision: 1}
		update.PublicEndpoint = &endpoint
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		original := endpoint
		endpoint.Port = 8443
		var stops atomic.Int32
		guard, err := lease.BindPublicConnection(original, netip.MustParseAddr("192.0.2.1"), func() { stops.Add(1) })
		if err != nil {
			t.Fatal("caller mutation changed the installed endpoint", err)
		}
		defer guard.Close()
		allowed, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("198.51.100.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		ip, err := ippolicy.New([32]byte{1}, []ippolicy.Entry{allowed})
		if err != nil {
			t.Fatal(err)
		}
		update.PublicEndpoint, update.IP = &original, &ip
		if err := lease.Apply(lease.Begin(), update); err != nil {
			t.Fatal(err)
		}
		if stops.Load() != 1 {
			t.Fatal("a new IP restriction retained an excluded public connection")
		}
		if guard, err := lease.BindPublicConnection(original, netip.MustParseAddr("192.0.2.1"), func() {}); err == nil {
			guard.Close()
			t.Fatal("old source evidence bypassed current IP policy")
		}
	})
}

func TestPublicSourceDenialDoesNotRelabelUnavailableOrReplacedEndpoint(t *testing.T) {
	for _, boundary := range []string{"source", "expired", "disabled", "endpoint"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, _ := fixture(t)
				endpoint := controlv1.VisitorPublicEndpoint{Hostname: update.View.Hostname, Port: 443, EndpointRevision: 1}
				allowed, err := ippolicy.Hash([32]byte{1}, netip.MustParsePrefix("198.51.100.0/24"))
				if err != nil {
					t.Fatal(err)
				}
				ip, err := ippolicy.New([32]byte{1}, []ippolicy.Entry{allowed})
				if err != nil {
					t.Fatal(err)
				}
				update.PublicEndpoint, update.IP = &endpoint, &ip
				update.View.ValidUntil = time.Now().Add(time.Second)
				if boundary == "disabled" {
					update.Enabled = false
				}
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				if boundary == "expired" {
					time.Sleep(time.Second)
				}
				selected := endpoint
				if boundary == "endpoint" {
					selected.EndpointRevision++
				}
				guard, err := lease.BindPublicConnection(selected, netip.MustParseAddr("192.0.2.1"), func() {})
				if guard != nil {
					guard.Close()
				}
				if !errors.Is(err, visitortoken.ErrPolicy) || errors.Is(err, ErrSourceDenied) != (boundary == "source") {
					t.Fatal("source diagnostic replaced a different authority failure", err)
				}
			})
		})
	}
}
