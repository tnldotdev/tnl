package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestHTTPAccountingUsesVisitorLimitInsteadOfNativeClass(t *testing.T) {
	config, control, forwarder := serviceSelectionConfig(t, 1, true)
	config.MaxConnections, config.MaxServiceConnections = 2, 1
	opened := make(chan struct{}, 2)
	forwarder.openings[control.runs[0].ServiceRunId] = func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
		opened <- struct{}{}
		<-ctx.Done()
		return nil, context.Cause(ctx)
	}
	server := serviceSelectionHTTPServer(t, config)
	for range 2 {
		connection, visitor := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		ingressWorker(t, func() { cancel(); _ = visitor.Close() }, func() error {
			return server.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"),
				netip.MustParseAddrPort("203.0.113.10:443"), "route.example", nil)
		})
		ingressAwait(t, opened)
	}
	if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 2 {
		t.Fatal("HTTP did not use its configured ordinary capacity", pending, active)
	}
	server.mu.Lock()
	native := server.admitted[serviceConnection]
	server.mu.Unlock()
	if native != 0 {
		t.Fatal("HTTP borrowed the native service class", native)
	}
	if err := rejectServiceSelection(t, t.Context(), server); !errors.Is(err, ErrServiceAdmission) {
		t.Fatal("HTTP exceeded the configured visitor limit", err)
	}
	forwarder.mu.Lock()
	count := len(forwarder.observed)
	forwarder.mu.Unlock()
	if count != 2 {
		t.Fatal("capacity rejection opened another relay", count)
	}
}

func TestRestrictedHTTPAccountingSkipsOrdinaryExhaustionWithoutQuotaDebit(t *testing.T) {
	for _, reason := range []string{"service_connections", "service_connection_total", "service_connection_rate"} {
		t.Run(reason, func(t *testing.T) {
			server, lease, runs := cachedSelectionServer(t, 2, false)
			exhaustSelectionRun(t, server, runs[0], reason)
			capacity := server.newServiceAdmission()
			defer capacity.close()
			deadline := capacity.deadline
			selected, err := selectCachedService(t.Context(), server, lease, capacity)
			if err != nil || selected.runID != runs[1].ServiceRunId || !deadline.Equal(capacity.deadline) {
				t.Fatal("restricted selection did not skip the exhausted run within its original deadline", selected, err)
			}
			if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
				t.Fatal("restricted selection reserved ordinary process quota", pending, active)
			}
			server.traffic.mu.Lock()
			run := server.traffic.runs[selectionRunKey(runs[1])]
			exhaustedPending := server.traffic.pendingRuns[selectionRunKey(runs[0])]
			server.traffic.mu.Unlock()
			if run != nil || exhaustedPending != nil || capacity.metered {
				t.Fatal("availability check debited ordinary quota or spent a skipped run's pending budget")
			}
			capacity.close()
			if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 0 {
				t.Fatal("closing selected pending capacity retained its process slot", pending, active)
			}
		})
	}
}

func TestRestrictedHTTPAccountingRechecksConcurrentReservations(t *testing.T) {
	config, control, _ := serviceSelectionConfig(t, 1, false)
	resolved, err := config.Traffic.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	limits := resolved.Default
	limits.Connections, limits.TotalConnections = 1, 1
	control.runs[0].Traffic = publicServiceTraffic(limits)
	server := serviceSelectionHTTPServer(t, config)
	var visitors [2]*visitorAdmission
	for index := range visitors {
		visitors[index] = server.newServiceAdmission()
		defer visitors[index].close()
		if _, err := selectCachedService(t.Context(), server, config.CurrentLease(), visitors[index]); err != nil {
			t.Fatal("pending availability check held ordinary quota", err)
		}
	}
	if len(server.traffic.runs) != 0 {
		t.Fatal("pending selections created an ordinary quota record")
	}
	var group sync.WaitGroup
	var results [2]string
	for index, visitor := range visitors {
		group.Go(func() { results[index] = visitor.reserveForVisitor() })
	}
	group.Wait()
	winner := 0
	if results[0] != "" {
		winner = 1
	}
	if results[winner] != "" || results[1-winner] != "service_connections" {
		t.Fatal("concurrent authorized reservations exceeded one ordinary slot", results)
	}
	if reason := visitors[winner].reserveForVisitor(); reason != "" {
		t.Fatal("same visitor could not acknowledge its existing reservation", reason)
	}
	if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 1 {
		t.Fatal("reservation duplicated process capacity", pending, active)
	}
	visitors[winner].close()
	visitors[winner].close()
	if reason := visitors[1-winner].reserveForVisitor(); reason != "service_connection_total" {
		t.Fatal("close refunded the lifetime debit", reason)
	}
	visitors[1-winner].close()
	if reason := visitors[winner].reserveForVisitor(); reason == "" {
		t.Fatal("a closed visitor revived its reservation")
	}
	if !publicServiceCapacityReleased(server) {
		t.Fatal("reservation race leaked or double-released capacity")
	}
	run := server.traffic.runs[selectionRunKey(control.runs[0])]
	if run.active != 0 || run.connections != 1 {
		t.Fatal("reservation retries changed the exact run's lifetime debit", run)
	}
}

func TestAnonymousHTTPAccountingDoesNotBorrowSaturatedProcessPendingQuota(t *testing.T) {
	config, _, _ := serviceSelectionConfig(t, 1, true)
	config.Pending.Connections, config.Pending.ServiceConnections, config.Pending.SourceConnections = 1, 1, 1
	server := serviceSelectionHTTPServer(t, config)
	restricted, reason := server.admitPendingService()
	if restricted == nil {
		t.Fatal(reason)
	}
	defer restricted.close()
	anonymous := server.newServiceAdmission()
	defer anonymous.close()
	if _, err := selectCachedService(t.Context(), server, config.CurrentLease(), anonymous); err != nil {
		t.Fatal("cached anonymous accounting depended on unrelated pending capacity", err)
	}
	if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 1 {
		t.Fatal("anonymous accounting changed restricted capacity", pending, active)
	}
	if len(server.traffic.pendingRuns) != 0 || !anonymous.metered {
		t.Fatal("anonymous selection used a pending run budget or skipped ordinary metering")
	}
	anonymous.close()
	restricted.close()
	if !publicServiceCapacityReleased(server) {
		t.Fatal("independent accounting classes retained capacity")
	}
}

func TestRestrictedHTTPAccountingCloseRacesReservation(t *testing.T) {
	server, lease, runs := cachedSelectionServer(t, 1, false)
	visitor := server.newServiceAdmission()
	defer visitor.close()
	if _, err := selectCachedService(t.Context(), server, lease, visitor); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	var reason string
	group.Go(func() { reason = visitor.reserveForVisitor() })
	group.Go(visitor.close)
	group.Wait()
	visitor.close()
	if reason != "" && reason != "pending_expired" {
		t.Fatal("close/reservation race returned an unrelated failure", reason)
	}
	if !publicServiceCapacityReleased(server) {
		t.Fatal("close/reservation race leaked or double-released capacity")
	}
	run := server.traffic.runs[selectionRunKey(runs[0])]
	if reason == "" && (run == nil || run.connections != 1) || reason != "" && run != nil {
		t.Fatal("close/reservation race lost or invented an ordinary debit", reason, run)
	}
}

func TestUnknownHTTPAccountingWaitsOnlyWithBoundedPendingQuota(t *testing.T) {
	for _, mode := range []string{"missing", "expired anonymous"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, _, _ := serviceSelectionConfig(t, 1, true)
				config.Pending.Connections, config.Pending.ServiceConnections, config.Pending.SourceConnections = 1, 1, 1
				server := serviceSelectionServer(t, config)
				if mode == "expired anonymous" {
					applyServiceRoutingFixture(t, server)
					server.services.mu.Lock()
					for _, route := range server.services.runs {
						route.until = time.Now()
					}
					server.services.mu.Unlock()
				}
				time.Sleep(time.Nanosecond)
				first := server.newServiceAdmission()
				defer first.close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					_, err := selectCachedService(ctx, server, config.CurrentLease(), first)
					done <- err
				}()
				synctest.Wait()
				if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
					t.Fatal("unknown policy waited without pending capacity", pending, active)
				}
				second := server.newServiceAdmission()
				defer second.close()
				if selected, err := selectCachedService(t.Context(), server, config.CurrentLease(), second); !errors.Is(err, ErrServiceAdmission) ||
					selected.denialReason != "capacity" {
					t.Fatal("unknown policy exceeded the pending bound", selected, err)
				}
				cancel()
				if err := <-done; !errors.Is(err, context.Canceled) {
					t.Fatal("pending wait lost caller cancellation", err)
				}
				first.close()
				second.close()
				if !publicServiceCapacityReleased(server) {
					t.Fatal("unknown policy wait retained capacity")
				}
			})
		})
	}
}

func TestUnknownHTTPAccountingTransfersOnlyAfterBackgroundAnonymousPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, _, _ := serviceSelectionConfig(t, 1, true)
		config.Pending.Connections, config.Pending.ServiceConnections, config.Pending.SourceConnections = 1, 1, 1
		server := serviceSelectionServer(t, config)
		visitor := server.newServiceAdmission()
		defer visitor.close()
		deadline := visitor.deadline
		done := make(chan error, 1)
		go func() {
			_, err := selectCachedService(t.Context(), server, config.CurrentLease(), visitor)
			done <- err
		}()
		synctest.Wait()
		if pending, active := publicServiceAdmissionCounts(server); pending != 1 || active != 0 {
			t.Fatal("unknown policy did not hold exactly one pending slot", pending, active)
		}
		time.Sleep(time.Millisecond)
		applyServiceRoutingFixture(t, server)
		if err := <-done; err != nil {
			t.Fatal("background anonymous policy did not release the bounded wait", err)
		}
		if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 1 ||
			!visitor.deadline.Equal(deadline) || !visitor.metered {
			t.Fatal("background policy duplicated accounting or restarted the setup deadline", pending, active)
		}
		visitor.close()
		if !publicServiceCapacityReleased(server) {
			t.Fatal("background policy transfer retained capacity")
		}
	})
}
