package ingress

import (
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/testutil/ipdigest"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceHTTPProtectionRejectsCachedSourceAndExpiresWithoutControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, control, _ := serviceSelectionConfig(t, 2, true)
		server := serviceSelectionServer(t, config)
		lease := config.CurrentLease()
		started := time.Now()
		snapshot, err := control.ReadIngressServices(t.Context(), lease.IngressId, ingressv1.IngressLeaseIdentity{
			IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		for index := range snapshot.Runs {
			snapshot.Runs[index].TemporaryBlockKey = ipdigest.Key()
			snapshot.Runs[index].TemporaryBlocks = []httpprotection.TemporaryBlock{{
				SourceDigest: ipdigest.Hash("192.0.2.4"), ExpiresAt: snapshot.ObservedAt.Add(3 * time.Second),
			}}
		}
		// a slow response spends the block's lifetime rather than extending it.
		time.Sleep(2 * time.Second)
		if err := server.services.apply(started, lease, snapshot); err != nil {
			t.Fatal(err)
		}
		server.config.Control = preparedSelectionControl{}
		selectSource := func(source string) (selectedServiceRun, error) {
			t.Helper()
			capacity, reason := server.admitPendingService()
			if capacity == nil {
				t.Fatal(reason)
			}
			defer capacity.close()
			return server.selectPublicRun(t.Context(), lease, netip.MustParseAddrPort(source),
				netip.MustParseAddrPort("203.0.113.10:443"), "route.example", capacity)
		}
		selected, err := selectSource("192.0.2.4:42000")
		if !errors.Is(err, ErrServiceAdmission) || selected.denialReason != controlv1.ObservationIPPolicy {
			t.Fatal("cached source block did not reject before forwarding", err, selected.denialReason)
		}
		if _, err := selectSource("192.0.2.5:42000"); err != nil {
			t.Fatal("block widened to a neighboring source", err)
		}
		time.Sleep(time.Second)
		if _, err := selectSource("192.0.2.4:42000"); err != nil {
			t.Fatal("block outlived its absolute expiry without control", err)
		}
	})
}

func TestServiceHTTPProtectionSnapshotRejectsInvalidBlocks(t *testing.T) {
	for _, mode := range []string{"source", "expiry", "duplicate", "capacity", "native"} {
		t.Run(mode, func(t *testing.T) {
			lease, snapshot := serviceRoutingFixture(t)
			block := httpprotection.TemporaryBlock{SourceDigest: ipdigest.Hash("192.0.2.4"), ExpiresAt: snapshot.ObservedAt.Add(time.Minute)}
			snapshot.Runs[0].TemporaryBlockKey = ipdigest.Key()
			snapshot.Runs[0].TemporaryBlocks = []httpprotection.TemporaryBlock{block}
			switch mode {
			case "source":
				snapshot.Runs[0].TemporaryBlocks[0].SourceDigest = "not-a-digest"
			case "expiry":
				snapshot.Runs[0].TemporaryBlocks[0].ExpiresAt = time.Time{}
			case "duplicate":
				snapshot.Runs[0].TemporaryBlocks = append(snapshot.Runs[0].TemporaryBlocks, block)
			case "capacity":
				snapshot.Runs[0].TemporaryBlocks = make([]httpprotection.TemporaryBlock, httpprotection.MaxBlocks+1)
			case "native":
				snapshot.Runs[0].Protocol, snapshot.Runs[0].Port = "tcp", 20000
			}
			routing := NewServiceRouting()
			defer routing.Close()
			if err := routing.apply(time.Now(), lease, snapshot); err == nil {
				t.Fatal("routing installed invalid HTTP source blocks")
			}
		})
	}
}

func TestServiceHTTPProtectionRefreshedBlockRejectsNewBinding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		source := netip.MustParseAddr("192.0.2.4")
		route := routing.lookup("route.example", 443, lease, time.Now())[0]
		var stopped bool
		release, err := routing.bind(route, source, func() { stopped = true })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		time.Sleep(time.Second)
		snapshot.ObservedAt = time.Now()
		snapshot.Runs[0].TemporaryBlockKey = ipdigest.Key()
		snapshot.Runs[0].TemporaryBlocks = []httpprotection.TemporaryBlock{{SourceDigest: ipdigest.Hash(source.String()), ExpiresAt: time.Now().Add(time.Minute)}}
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if stopped {
			t.Fatal("source block interrupted an already-forwarded response")
		}
		if release, err := routing.bind(route, source, func() {}); err == nil {
			release()
			t.Fatal("refreshed block allowed a newly selected binding")
		}
		if err := routing.reserveHTTP(route, route.run.ConnectedRelays[0], lease, source, func() error {
			t.Error("refreshed block spent pending connection capacity")
			return nil
		}); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("refreshed block allowed pending HTTP admission", err)
		}
		if _, err := routing.waitForRelayReplacement(t.Context(), route, lease, source); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("a blocked source borrowed replacement relays")
		}
	})
}
