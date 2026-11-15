package ingress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func selectionRunKey(run ingressv1.PublicServiceVisitorAdmission) trafficKey {
	return trafficKey{service: run.ServiceId, id: run.ServiceRunId, run: uint64(run.RunNumber)}
}

func exhaustSelectionRun(t *testing.T, server *Server, run ingressv1.PublicServiceVisitorAdmission, reason string) {
	t.Helper()
	key := selectionRunKey(run)
	limits, err := routingTraffic(run.Traffic)
	if err != nil {
		t.Fatal(err)
	}
	switch reason {
	case "service_connections":
		server.traffic.runs[key] = &runTraffic{limits: limits, active: limits.Connections}
	case "service_connection_total":
		server.traffic.runs[key] = &runTraffic{limits: limits, connections: *run.Traffic.TotalConnections}
	case "service_connection_rate":
		server.traffic.runs[key] = &runTraffic{limits: limits, newConnections: tokenBucket{last: time.Now()}}
	case "pending_service_connections":
		server.traffic.pendingRuns[key] = &pendingTraffic{active: server.config.Pending.ServiceConnections}
	case "pending_service_rate":
		server.traffic.pendingRuns[key] = &pendingTraffic{seen: time.Now(), attempts: tokenBucket{last: time.Now()}}
	default:
		t.Fatal("unknown selection exhaustion", reason)
	}
}

func TestPublicServiceSelectionSkipsOnlyLocallyExhaustedRun(t *testing.T) {
	for _, reason := range []string{"service_connections", "service_connection_total", "service_connection_rate", "pending_service_connections", "pending_service_rate"} {
		t.Run(reason, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, control, forwarder := serviceSelectionConfig(t, 2, !strings.HasPrefix(reason, "pending_"))
				total := int64(1)
				control.runs[0].Traffic.TotalConnections = &total
				server := serviceSelectionServer(t, config)
				control.before = func(context.Context, *ingressv1.PublicServiceVisitorAdmission) error {
					if server.Load() != 1 || server.admitted[serviceConnection] != 1 || server.admitted[pendingConnection] != 1 {
						t.Error("candidate search duplicated physical or process admission")
					}
					return nil
				}
				exhaustSelectionRun(t, server, control.runs[0], reason)
				if err := rejectServiceSelection(t, t.Context(), server); err == nil {
					t.Fatal("fixture without an open relay completed forwarding")
				}
				if len(control.claims) != 2 || len(forwarder.observed) != 1 || forwarder.observed[0].ServiceRunID != control.runs[1].ServiceRunId ||
					forwarder.observed[0].RunNumber != uint64(control.runs[1].RunNumber) {
					t.Fatal("new visitor did not select the exact healthy sibling", control.claims, forwarder.observed)
				}
				first, second := control.claims[0], control.claims[1]
				if first.VisitorConnectionId == second.VisitorConnectionId || len(first.ExcludedRuns) != 0 || len(second.ExcludedRuns) != 1 ||
					second.ExcludedRuns[0] != (ingressv1.ServiceRunReference{ServiceId: control.service, ServiceRunId: control.runs[0].ServiceRunId, RunNumber: 1}) {
					t.Fatal("sibling selection reused a reservation or changed its exclusion", first, second)
				}
				if len(control.actions) != 4 || control.actions[1] != "close "+first.VisitorConnectionId || control.actions[2] != "admit "+second.VisitorConnectionId ||
					!control.deadlines[0].Equal(control.deadlines[1]) || len(control.live) != 0 {
					t.Fatal("sibling selection overlapped reservations or extended its setup deadline", control.actions, control.deadlines)
				}
				if server.Load() != 0 {
					t.Fatal("sibling selection retained its physical visitor")
				}
				source := server.traffic.sources[trafficlimits.SourceNetwork(netip.MustParseAddr("192.0.2.4"))]
				if source == nil || source.connections != 0 || source.attempts.tokens != float64(server.config.Traffic.SourceBurst-1) {
					t.Fatal("candidate search charged source admission more than once", source)
				}
			})
		})
	}
}

func TestPublicServiceSelectionDoesNotSearchOnNonRunRejection(t *testing.T) {
	for _, mode := range []string{"pending source connections", "pending source rate", "ordinary process connections", "invalid traffic", "changed traffic", "source connections", "expired lease"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, control, forwarder := serviceSelectionConfig(t, 2, mode == "ordinary process connections" || mode == "changed traffic")
				config.MaxConnections = 1
				config.Pending.SourceConnections, config.Pending.SourceRate, config.Pending.SourceBurst = 1, 1, 1
				config.Traffic.SourceConnections = 1
				if mode == "expired lease" {
					lease := config.CurrentLease()
					lease.LeaseExpiresAt = time.Now()
					config.CurrentLease = func() ingressv1.IngressLease { return lease }
				}
				server := serviceSelectionServer(t, config)
				source := server.traffic.sourceLocked(netip.MustParseAddr("192.0.2.4"))
				source.seen = time.Now()
				wantClaims := 1
				switch mode {
				case "pending source connections":
					source.active = 1
				case "pending source rate":
					source.pending.last = time.Now()
				case "ordinary process connections":
					release, reason := server.admitClass(visitorConnection)
					if release == nil {
						t.Fatal(reason)
					}
					defer release()
				case "invalid traffic":
					control.runs[0].Traffic.Connections = server.config.Traffic.Ceiling.Connections + 1
				case "changed traffic":
					limits := server.config.Traffic.Default
					limits.Connections--
					server.traffic.runs[selectionRunKey(control.runs[0])] = &runTraffic{limits: limits, seen: time.Now()}
				case "source connections":
					source.connections = 1
					wantClaims = 0
				case "expired lease":
					wantClaims = 0
				}
				if err := rejectServiceSelection(t, t.Context(), server); err == nil || len(control.claims) != wantClaims || len(forwarder.observed) != 0 ||
					server.Load() != 0 || len(control.live) != 0 {
					t.Fatal("non-run rejection searched another candidate", err, control.claims, forwarder.observed)
				}
			})
		})
	}
}

func TestPublicServiceSelectionStopsAfterEightDistinctRuns(t *testing.T) {
	config, control, forwarder := serviceSelectionConfig(t, 9, true)
	server := serviceSelectionServer(t, config)
	for _, run := range control.runs {
		exhaustSelectionRun(t, server, run, "service_connections")
	}
	err := rejectServiceSelection(t, t.Context(), server)
	if !errors.Is(err, ErrServiceSelectionLimit) || strings.Contains(err.Error(), "full pool") || len(control.claims) != 8 || len(forwarder.observed) != 0 || len(control.live) != 0 {
		t.Fatal("selection was unbounded or claimed the entire pool was full", err, len(control.claims), forwarder.observed)
	}
	visitors := make(map[string]bool)
	for i, claim := range control.claims {
		if visitors[claim.VisitorConnectionId] || len(claim.ExcludedRuns) != i || !control.deadlines[i].Equal(control.deadlines[0]) ||
			control.actions[2*i] != "admit "+claim.VisitorConnectionId || control.actions[2*i+1] != "close "+claim.VisitorConnectionId {
			t.Fatal("selection changed visitor IDs, closure order, exclusions, or deadline", control.claims, control.actions)
		}
		visitors[claim.VisitorConnectionId] = true
	}
}

func TestPublicServiceSelectionDoesNotRetryAmbiguousFailures(t *testing.T) {
	for _, operation := range []string{"admit", "close"} {
		t.Run(operation, func(t *testing.T) {
			config, control, forwarder := serviceSelectionConfig(t, 2, true)
			problem := errors.New("response lost after control accepted the operation")
			if operation == "admit" {
				control.before = func(context.Context, *ingressv1.PublicServiceVisitorAdmission) error { return problem }
			} else {
				control.close = func(context.Context, ingressv1.PublicServiceVisitorLookup) error { return problem }
			}
			server := serviceSelectionServer(t, config)
			exhaustSelectionRun(t, server, control.runs[0], "service_connections")
			err := rejectServiceSelection(t, t.Context(), server)
			if !errors.Is(err, problem) || len(control.claims) != 1 || len(forwarder.observed) != 0 {
				t.Fatal("ambiguous failure selected another run", err, control.claims, forwarder.observed)
			}
			for _, action := range control.actions[1:] {
				if action != "close "+control.claims[0].VisitorConnectionId {
					t.Fatal("cleanup changed the uncertain reservation's visitor ID", control.actions)
				}
			}
		})
	}
}

func TestPublicServiceSelectionDenialUsesLastValidatedCandidateWithoutSelectingItsRun(t *testing.T) {
	config, control, _ := serviceSelectionConfig(t, 2, true)
	problem := errors.New("second admission response lost")
	control.before = func(context.Context, *ingressv1.PublicServiceVisitorAdmission) error {
		if len(control.claims) == 2 {
			return problem
		}
		return nil
	}
	events := make(chan serviceaudit.Observation, 1)
	config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool { events <- event; return true })
	server := serviceSelectionServer(t, config)
	exhaustSelectionRun(t, server, control.runs[0], "service_connections")
	if err := rejectServiceSelection(t, t.Context(), server); !errors.Is(err, problem) {
		t.Fatal(err)
	}
	event := ingressAwait(t, events)
	if event.ServiceID != control.service || event.VisitorConnectionID != control.claims[0].VisitorConnectionId ||
		event.RunID != "" || event.RunNumber != 0 || event.Outcome != "denied" || event.Reason != "unavailable" || len(events) != 0 {
		t.Fatal("failed selection invented a run or used an unconfirmed reservation for its audit", event)
	}
}

func TestPublicServiceSelectionRejectsChangedOrRepeatedRunIdentity(t *testing.T) {
	for _, mode := range []string{"service", "run ID", "run number", "visitor"} {
		t.Run(mode, func(t *testing.T) {
			config, control, forwarder := serviceSelectionConfig(t, 2, true)
			original := control.runs[0]
			control.before = func(_ context.Context, run *ingressv1.PublicServiceVisitorAdmission) error {
				if len(control.claims) == 2 {
					switch mode {
					case "service":
						run.ServiceId = publicServiceTestID(t, "svc_")
					case "run ID":
						run.ServiceRunId = original.ServiceRunId
					case "run number":
						run.RunNumber = original.RunNumber
					case "visitor":
						run.VisitorConnectionId = control.claims[0].VisitorConnectionId
					}
				}
				return nil
			}
			server := serviceSelectionServer(t, config)
			exhaustSelectionRun(t, server, original, "service_connections")
			err := rejectServiceSelection(t, t.Context(), server)
			if !errors.Is(err, ErrServiceAdmission) || len(control.claims) != 2 || len(forwarder.observed) != 0 || len(control.live) != 0 {
				t.Fatal("invalid sibling identity was selected or retried", err, control.claims, forwarder.observed)
			}
		})
	}
}

func TestPublicServiceSelectionKeepsOneDeadlineAndRejectsLateAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, control, forwarder := serviceSelectionConfig(t, 2, true)
		config.OpenTimeout = 50 * time.Millisecond
		control.before = func(ctx context.Context, run *ingressv1.PublicServiceVisitorAdmission) error {
			if len(control.claims) == 2 {
				// a client ignoring cancellation cannot extend this connection.
				<-ctx.Done()
				run.ExpiresAt = time.Now().Add(time.Minute)
			}
			return nil
		}
		server := serviceSelectionServer(t, config)
		exhaustSelectionRun(t, server, control.runs[0], "service_connections")
		started := time.Now()
		if err := rejectServiceSelection(t, t.Context(), server); err == nil || time.Since(started) != config.OpenTimeout ||
			len(control.claims) != 2 || !control.deadlines[0].Equal(control.deadlines[1]) || len(forwarder.observed) != 0 {
			t.Fatal("late response revived selection or extended its deadline", err, control.deadlines, time.Since(started))
		}
		if _, exists := server.traffic.runs[selectionRunKey(control.runs[1])]; exists {
			t.Fatal("late response spent another run's quota")
		}
	})
}

func TestPublicServiceSelectionCloseCannotRestartSetupDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, control, forwarder := serviceSelectionConfig(t, 2, true)
		config.OpenTimeout = 50 * time.Millisecond
		control.close = func(ctx context.Context, lookup ingressv1.PublicServiceVisitorLookup) error {
			deadline, bounded := ctx.Deadline()
			if !bounded {
				t.Fatal("reservation cleanup has no deadline")
			}
			if len(control.actions) == 2 {
				if !deadline.Equal(control.deadlines[0]) {
					t.Fatal("rejected reservation close restarted the setup deadline")
				}
				<-ctx.Done()
				return ctx.Err()
			}
			if deadline.After(time.Now().Add(5*time.Second)) || lookup.VisitorConnectionId != control.claims[0].VisitorConnectionId {
				t.Fatal("final cleanup changed the uncertain reservation or exceeded its cleanup bound")
			}
			return nil
		}
		server := serviceSelectionServer(t, config)
		exhaustSelectionRun(t, server, control.runs[0], "service_connections")
		started := time.Now()
		if err := rejectServiceSelection(t, t.Context(), server); !errors.Is(err, context.DeadlineExceeded) ||
			time.Since(started) != config.OpenTimeout || len(control.claims) != 1 || len(forwarder.observed) != 0 ||
			len(control.actions) != 3 || len(control.live) != 0 {
			t.Fatal("blocked close selected another run or lost final cleanup", err, control.actions)
		}
	})
}

func TestPublicServiceSelectionStopsWhenLeaseChangesBetweenCandidates(t *testing.T) {
	for _, mode := range []string{"expired", "draining", "replacement", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			config, control, forwarder := serviceSelectionConfig(t, 2, true)
			lease := config.CurrentLease()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control.close = func(context.Context, ingressv1.PublicServiceVisitorLookup) error {
				switch mode {
				case "expired":
					lease.LeaseExpiresAt = time.Now()
				case "draining":
					lease.Draining = true
				case "replacement":
					lease.IngressLeaseRevision++
				case "canceled":
					cancel()
				}
				return nil
			}
			config.CurrentLease = func() ingressv1.IngressLease { return lease }
			server := serviceSelectionServer(t, config)
			exhaustSelectionRun(t, server, control.runs[0], "service_connections")
			if err := rejectServiceSelection(t, ctx, server); err == nil || len(control.claims) != 1 || len(forwarder.observed) != 0 {
				t.Fatal("selection continued after losing the connection's authority", err, control.claims)
			}
		})
	}
}

func TestFailedServiceSelectionLeavesAdmissionUnselectedAndPendingRatesAtomic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, control, _ := serviceSelectionConfig(t, 3, false)
		config.Pending.SourceBurst, config.Pending.SourceRate = 1, 1
		config.Pending.SourceConnections = 16
		config.Pending.ServiceBurst, config.Pending.ServiceRate = 1, 1
		server := serviceSelectionServer(t, config)
		first, reason := server.admitPendingService()
		if first == nil {
			t.Fatal(reason)
		}
		defer first.close()
		deadline := first.deadline
		exhaustSelectionRun(t, server, control.runs[0], "pending_service_rate")
		limits := server.config.Traffic.Default
		source := netip.MustParseAddr("192.0.2.4")
		if reason := first.selectRun(selectionRunKey(control.runs[0]), limits, source, false); reason != "pending_service_rate" ||
			first.key != (trafficKey{}) || first.limits != (TrafficLimits{}) || first.source.IsValid() || first.ordinary || first.metered ||
			!first.deadline.Equal(deadline) {
			t.Fatal("failed selection retained its run or changed pending accounting", reason, first)
		}
		if reason := first.selectRun(selectionRunKey(control.runs[1]), limits, source, false); reason != "" {
			t.Fatal("rejected run consumed the visitor's only source token", reason)
		}
		second, reason := server.admitPendingService()
		if second == nil {
			t.Fatal(reason)
		}
		defer second.close()
		if reason := second.selectRun(selectionRunKey(control.runs[2]), limits, source, false); reason != "pending_source_rate" {
			t.Fatal("source exhaustion was bypassed", reason)
		}
		other := netip.MustParseAddr("198.51.100.4")
		if reason := second.selectRun(selectionRunKey(control.runs[2]), limits, other, false); reason != "" {
			t.Fatal("source rejection consumed the run's only token", reason)
		}
	})
}

func TestPublicServiceConcurrentSelectionReservesRunOnce(t *testing.T) {
	config, control, _ := serviceSelectionConfig(t, 1, true)
	server := serviceSelectionServer(t, config)
	limits := server.config.Traffic.Default
	limits.Connections, limits.TotalConnections = 1, 1
	var visitors [2]*visitorAdmission
	for i := range visitors {
		var reason string
		visitors[i], reason = server.admitPendingService()
		if visitors[i] == nil {
			t.Fatal(reason)
		}
		defer visitors[i].close()
	}
	var group sync.WaitGroup
	var results [2]string
	key := selectionRunKey(control.runs[0])
	for i, visitor := range visitors {
		group.Go(func() { results[i] = visitor.selectRun(key, limits, netip.MustParseAddr("192.0.2.4"), true) })
	}
	group.Wait()
	winner := 0
	if results[0] != "" {
		winner = 1
	}
	if results[winner] != "" || results[1-winner] != "service_connections" {
		t.Fatal("concurrent selection admitted more than one run slot", results)
	}
	visitors[winner].close()
	if reason := visitors[1-winner].selectRun(key, limits, netip.MustParseAddr("192.0.2.4"), true); reason != "service_connection_total" {
		t.Fatal("close refunded the winning connection's lifetime debit", reason)
	}
}

func TestPublicServiceFailedOpenKeepsLifetimeDebitAndDoesNotReselect(t *testing.T) {
	for _, committed := range []int{0, 1} {
		t.Run(fmt.Sprintf("visitor_bytes=%d", committed), func(t *testing.T) {
			config, control, forwarder := serviceSelectionConfig(t, 2, true)
			total := int64(1)
			control.runs[0].Traffic.TotalConnections = &total
			failed := newServiceFailureRelay(t, committed)
			sibling := newServiceTLSRelay(t)
			forwarder.openings[control.runs[0].ServiceRunId] = failed.open
			forwarder.openings[control.runs[1].ServiceRunId] = sibling.open
			metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
			config.Metrics = metrics
			server, address := startIngress(t, config)
			first := ingressClient(t, address, "route.example", "192.0.2.4:40001")
			if err := first.Handshake(); err == nil {
				t.Fatal("failed service run completed TLS")
			}
			_ = first.Close()
			outcome := ingressAwait(t, metrics.visitorOutcomes)
			server.active.Wait()
			if outcome != "open_failed" && committed == 0 || outcome != "committed_failed" && committed != 0 {
				t.Fatal("failed opening changed its byte commitment", outcome)
			}
			key := selectionRunKey(control.runs[0])
			run := server.traffic.runs[key]
			if len(control.claims) != 1 || sibling.opens.Load() != 0 || failed.opens.Load() != 1 || run == nil || run.active != 0 || run.connections != 1 {
				t.Fatal("failed open reselected a sibling or refunded its lifetime debit", control.claims, run, sibling.opens.Load())
			}
			next := ingressClient(t, address, "route.example", "192.0.2.4:40002")
			exchangePing(t, next)
			if result := ingressAwait(t, sibling.result); result.err != nil || result.request != "ping" {
				t.Fatal("new physical visitor could not use the healthy sibling", result)
			}
			ingressAwait(t, metrics.visitorOutcomes)
			server.active.Wait()
			if failed.opens.Load() != 1 || sibling.opens.Load() != 1 || len(control.claims) != 3 || run.connections != 1 ||
				control.claims[2].ExcludedRuns[0].ServiceRunId != key.id || metrics.visitorOpenFailures.Load() != 1 || metrics.visitorOpenSuccesses.Load() != 1 {
				t.Fatal("new visitor reopened the exhausted run or duplicated an opening charge")
			}
			if len(forwarder.observed) != 2 || forwarder.observed[0].ServiceRunID != control.runs[0].ServiceRunId ||
				forwarder.observed[1].ServiceRunID != control.runs[1].ServiceRunId || forwarder.observed[0].VisitorConnectionID == forwarder.observed[1].VisitorConnectionID {
				t.Fatal("failed and new physical visitors shared a run or visitor identity", forwarder.observed)
			}
		})
	}
}
