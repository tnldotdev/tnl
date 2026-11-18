package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func runAliasSnapshot(t *testing.T, count int) (Config, ingressv1.IngressLease, ingressv1.IngressServices) {
	t.Helper()
	config, _, _ := serviceSelectionConfig(t, count, true)
	lease := config.CurrentLease()
	snapshot, err := config.Control.ReadIngressServices(t.Context(), lease.IngressId, ingressv1.IngressLeaseIdentity{
		IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range snapshot.Runs {
		snapshot.Runs[i].RunHostname = new("r-" + strconv.Itoa(i+1) + ".example")
	}
	return config, lease, snapshot
}

func TestRunAliasSharesOneRunAndSourceSequenceWithCanonicalPool(t *testing.T) {
	_, lease, snapshot := runAliasSnapshot(t, 3)
	routing := NewServiceRouting()
	defer routing.Close()
	if err := routing.apply(time.Now(), lease, snapshot); err != nil {
		t.Fatal(err)
	}
	pool := routing.candidates("route.example", 443, lease, time.Now())
	if len(pool) != 3 {
		t.Fatal("aliases changed the canonical pool")
	}
	for i, run := range snapshot.Runs {
		exact := routing.candidates(*run.RunHostname, 443, lease, time.Now())
		if len(exact) != 1 || exact[0] != pool[i] || exact[0].sequence != pool[i].sequence {
			t.Fatal("alias did not borrow the exact pooled run and source counter")
		}
		if len(routing.lookup(*run.RunHostname, 8443, lease, time.Now())) != 0 {
			t.Fatal("alias selected a different port")
		}
	}
	// mutable input and lookup values must not change the installed address.
	alias := *snapshot.Runs[0].RunHostname
	*snapshot.Runs[0].RunHostname = "changed.example"
	found := routing.lookup(alias, 443, lease, time.Now())
	*found[0].run.RunHostname = "also-changed.example"
	found = routing.lookup(alias, 443, lease, time.Now())
	if len(found) != 1 || *found[0].run.RunHostname != alias || found[0].selectedHostname != alias {
		t.Fatal("caller mutation changed the installed alias")
	}
}

func TestRunAliasRejectsAmbiguousAndInvalidSnapshotsAtomically(t *testing.T) {
	for _, mode := range []string{"empty", "wildcard", "uppercase", "port", "native", "own canonical", "other canonical", "duplicate alias"} {
		for _, reverse := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					_, lease, snapshot := runAliasSnapshot(t, 2)
					routing := NewServiceRouting()
					defer routing.Close()
					if err := routing.apply(time.Now(), lease, snapshot); err != nil {
						t.Fatal(err)
					}
					original := *snapshot.Runs[0].RunHostname
					update := restorationCloneSnapshot(t, snapshot)
					switch mode {
					case "empty":
						update.Runs[0].RunHostname = new("")
					case "wildcard":
						update.Runs[0].RunHostname = new("*.example")
					case "uppercase":
						update.Runs[0].RunHostname = new("R-one.example")
					case "port":
						update.Runs[0].RunHostname = new("r-one.example:443")
					case "native":
						update.Runs[0].Protocol, update.Runs[0].Port, update.Runs[0].Anonymous = "tcp", 25443, false
					case "own canonical":
						update.Runs[0].RunHostname = new("route.example")
					case "other canonical":
						update.Runs[1].Hostname = "other.example"
						update.Runs[0].RunHostname = new("other.example")
					case "duplicate alias":
						update.Runs[1].RunHostname = new(*update.Runs[0].RunHostname)
					}
					if reverse {
						slices.Reverse(update.Runs)
					}
					time.Sleep(time.Millisecond)
					update.ObservedAt = time.Now()
					if err := routing.apply(time.Now(), lease, update); !errors.Is(err, ErrServiceAdmission) {
						t.Fatal("invalid alias snapshot was accepted", err)
					}
					if got := routing.lookup(original, 443, lease, time.Now()); len(got) != 1 ||
						got[0].run.ServiceRunId != snapshot.Runs[0].ServiceRunId ||
						!routing.observedAt.Equal(snapshot.ObservedAt) {
						t.Fatal("rejected snapshot changed installed routing")
					}
				})
			})
		}
	}
}

func TestRunAliasSelectionNeverFallsBackAndSharesCanonicalBudget(t *testing.T) {
	for _, mode := range []string{"healthy", "unknown alias", "expired", "relays expired", "IP denial", "capacity", "canonical spent total"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, lease, snapshot := runAliasSnapshot(t, 2)
				target := &snapshot.Runs[0]
				target.Traffic.TotalConnections = new(int64(1))
				server := serviceSelectionServer(t, config)
				server.config.Control = preparedSelectionControl{}
				if err := server.services.apply(time.Now(), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				key := trafficKey{service: target.ServiceId, id: target.ServiceRunId, run: uint64(target.RunNumber)}
				route := server.services.runs[target.ServiceRunId]
				switch mode {
				case "expired":
					route.until = time.Now()
				case "relays expired":
					for i := range route.run.ConnectedRelays {
						route.run.ConnectedRelays[i].ServingUntil = time.Now()
					}
				case "IP denial":
					deny, err := ippolicy.New([32]byte{1}, nil)
					if err != nil {
						t.Fatal(err)
					}
					route.ip = &deny
				case "capacity":
					server.traffic.runs[key] = &runTraffic{limits: route.traffic, active: route.traffic.Connections}
				case "canonical spent total":
					server.nextServiceRun.Store(0)
					capacity, reason := server.admitPendingService()
					if capacity == nil {
						t.Fatal(reason)
					}
					selected, err := selectCachedService(t.Context(), server, lease, capacity)
					capacity.close()
					if err != nil || selected.runID != target.ServiceRunId {
						t.Fatal("canonical fixture did not spend the exact run's budget", err)
					}
				}
				capacity, reason := server.admitPendingService()
				if capacity == nil {
					t.Fatal(reason)
				}
				defer capacity.close()
				hostname := *target.RunHostname
				if mode == "unknown alias" {
					hostname = "r-unknown.example"
				}
				wantErr := ErrServiceAdmission
				if mode == "unknown alias" || mode == "expired" {
					// a cache miss waits for a fresh snapshot under the original
					// admission deadline. this fixture does not publish another one.
					wantErr = context.DeadlineExceeded
					// distinguish a genuinely older snapshot from one that started
					// at the same fake clock tick as selection.
					time.Sleep(time.Millisecond)
				}
				selected, err := server.selectPublicRun(t.Context(), lease, netip.MustParseAddrPort("192.0.2.4:42000"),
					netip.MustParseAddrPort("203.0.113.10:443"), hostname, capacity)
				if mode == "healthy" {
					if err != nil || selected.runID != target.ServiceRunId || selected.number != target.RunNumber ||
						capacity.key != key || selected.http.selectedHostname != *target.RunHostname {
						t.Fatal("alias selected a different run or accounting key", err)
					}
				} else if !errors.Is(err, wantErr) || capacity.key != (trafficKey{}) {
					t.Fatal("unavailable alias fell back or retained capacity", err)
				}
				sibling := snapshot.Runs[1]
				if server.traffic.runs[trafficKey{service: sibling.ServiceId, id: sibling.ServiceRunId, run: uint64(sibling.RunNumber)}] != nil {
					t.Fatal("alias spent a sibling's budget")
				}
			})
		})
	}
}

func TestRunAliasForwardingKeepsExactRunAndFirstByteBoundary(t *testing.T) {
	for _, mode := range []string{"replace before first byte", "committed first attempt", "no replacement"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, lease, snapshot := runAliasSnapshot(t, 2)
				config.OpenTimeout = 100 * time.Millisecond
				snapshot.ObservedAt = snapshot.ObservedAt.Add(-time.Millisecond)
				target := &snapshot.Runs[0]
				target.Traffic.TotalConnections = new(int64(1))
				originalRelay := target.ConnectedRelays[0]
				problem := errors.New("exact-run relay opening failed")
				var headers []tunnelv1.ServiceForwardingHeader
				firstFailed := make(chan struct{})
				config.Forwarder = promotionTestForwarder(func(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (net.Conn, error) {
					headers = append(headers, header)
					if header.ServiceID != target.ServiceId || header.ServiceRunID != target.ServiceRunId || header.RunNumber != uint64(target.RunNumber) {
						t.Error("alias forwarded to a sibling run")
					}
					if err := reserve(ctx); err != nil {
						t.Error("exact-run capacity reservation failed", err)
					}
					committed := mode == "committed first attempt" || len(headers) > 1
					if len(headers) == 1 {
						close(firstFailed)
					}
					return nil, &tunnel.OpeningError{Committed: committed, Err: problem}
				})
				server := serviceSelectionServer(t, config)
				server.config.Control = preparedSelectionControl{}
				if err := server.services.apply(time.Now().Add(-time.Millisecond), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				updated := make(chan error, 1)
				if mode == "replace before first byte" {
					fresh := restorationCloneSnapshot(t, snapshot)
					fresh.Runs[0].ConnectedRelays[0].PublisherConnectionId = publicServiceTestID(t, "pc_")
					fresh.Runs[0].ConnectedRelays[0].ConnectionAssignmentRevision++
					go func() {
						<-firstFailed
						fresh.ObservedAt = time.Now()
						updated <- server.services.apply(time.Now(), lease, fresh)
					}()
				}
				connection, visitor := net.Pipe()
				defer visitor.Close()
				err := server.AcceptPublic(t.Context(), connection, netip.MustParseAddrPort("192.0.2.4:42000"),
					netip.MustParseAddrPort("203.0.113.10:443"), *target.RunHostname, nil)
				if !errors.Is(err, problem) {
					t.Fatal("forwarding lost the exact opening error", err)
				}
				wantAttempts := 1
				if mode == "replace before first byte" {
					if err := <-updated; err != nil {
						t.Fatal(err)
					}
					wantAttempts = 2
				}
				if len(headers) != wantAttempts || headers[0].PublisherConnectionID != originalRelay.PublisherConnectionId {
					t.Fatal("alias changed the first-byte retry boundary", len(headers))
				}
				if wantAttempts == 2 {
					before, after := headers[0], headers[1]
					if before.VisitorConnectionID != after.VisitorConnectionID || !before.ExpiresAt.Equal(after.ExpiresAt) ||
						after.ConnectionAssignmentRevision != before.ConnectionAssignmentRevision+1 ||
						after.PublisherConnectionID == before.PublisherConnectionID {
						t.Fatal("replacement changed the visitor, deadline, or assignment tuple")
					}
				}
				if mode == "no replacement" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("replacement wait did not retain its original setup deadline", err)
				}
				key := trafficKey{service: target.ServiceId, id: target.ServiceRunId, run: uint64(target.RunNumber)}
				budget := server.traffic.runs[key]
				if budget == nil || budget.connections != 1 || budget.active != 0 || server.Load() != 0 {
					t.Fatal("alias relay attempts duplicated or retained capacity", budget)
				}
				sibling := snapshot.Runs[1]
				if server.traffic.runs[trafficKey{service: sibling.ServiceId, id: sibling.ServiceRunId, run: uint64(sibling.RunNumber)}] != nil {
					t.Fatal("relay failure spent a sibling's quota")
				}
			})
		})
	}
}

func TestRunAliasWithdrawalFencesOnlyItsVisitorsAndPendingOpenings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, lease, snapshot := runAliasSnapshot(t, 2)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		alias := *snapshot.Runs[0].RunHostname
		exact := routing.lookup(alias, 443, lease, time.Now())[0]
		pool := routing.lookup("route.example", 443, lease, time.Now())[0]
		var aliasStops, canonicalStops atomic.Int32
		source := netip.MustParseAddr("192.0.2.4")
		for _, visitor := range []struct {
			route *serviceRoute
			stops *atomic.Int32
		}{{exact, &aliasStops}, {pool, &canonicalStops}} {
			release, err := routing.bind(visitor.route, source, func() { visitor.stops.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			defer release()
		}
		time.Sleep(time.Millisecond)
		snapshot.ObservedAt = time.Now()
		snapshot.Runs[0].RunHostname = nil
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if aliasStops.Load() != 1 || canonicalStops.Load() != 0 || len(routing.lookup(alias, 443, lease, time.Now())) != 0 {
			t.Fatal("alias withdrawal retained its visitor or interrupted the canonical connection")
		}
		if release, err := routing.bind(exact, source, func() {}); !errors.Is(err, ErrServiceAdmission) {
			if release != nil {
				release()
			}
			t.Fatal("withdrawn alias bound a pending visitor", err)
		}
		if err := routing.reserveHTTP(exact, exact.run.ConnectedRelays[0], lease, source, func() error {
			t.Error("withdrawn alias spent capacity")
			return nil
		}); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("withdrawn alias reserved capacity", err)
		}
		if _, err := routing.waitForRelayReplacement(t.Context(), exact, lease, source); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("withdrawn alias borrowed a relay replacement", err)
		}
	})
}

func TestRunAliasExpiresAndRetiresWithItsRun(t *testing.T) {
	for _, mode := range []string{"expiry", "retirement", "omission"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, lease, snapshot := runAliasSnapshot(t, 2)
				routing := NewServiceRouting()
				defer routing.Close()
				if err := routing.apply(time.Now(), lease, snapshot); err != nil {
					t.Fatal(err)
				}
				alias := *snapshot.Runs[0].RunHostname
				switch mode {
				case "expiry":
					time.Sleep(time.Until(snapshot.ValidUntil))
				case "retirement":
					run := snapshot.Runs[0]
					if !routing.retireTerminal(lease, []ingressv1.ServiceRunReference{{
						ServiceId: run.ServiceId, ServiceRunId: run.ServiceRunId, RunNumber: run.RunNumber,
					}}) {
						t.Fatal("run retirement failed")
					}
				case "omission":
					time.Sleep(time.Millisecond)
					snapshot.ObservedAt = time.Now()
					snapshot.Runs = snapshot.Runs[1:]
					if err := routing.apply(time.Now(), lease, snapshot); err != nil {
						t.Fatal(err)
					}
				}
				if len(routing.lookup(alias, 443, lease, time.Now())) != 0 {
					t.Fatal("unavailable run retained its alias")
				}
				wantPool := 1
				if mode == "expiry" {
					wantPool = 0
				}
				if len(routing.lookup("route.example", 443, lease, time.Now())) != wantPool {
					t.Fatal("alias removal changed sibling availability")
				}
			})
		})
	}
}
