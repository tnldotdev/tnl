package ingress

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

// event requests stop at explicit barriers. a race-safe logical clock advances
// the actual controller and routing-table expiry checks; wall time is used only
// to schedule renewals and bound test failure, never to infer routing progress.
func TestControllerStalledRoutingUpdates(t *testing.T) {
	for _, mode := range []string{"public_url_expiry_event_recovery", "public_url_expiry_resnapshot_recovery"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
			var clock atomic.Int64
			clock.Store(start.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			expires := start.Add(10 * time.Second)
			initial := routingReliabilityEvent(start, 1)
			resnapshot := mode == "public_url_expiry_resnapshot_recovery"
			initial.Entry.PublicUrlExpiresAt = expires
			initial.PublicUrlExpiresAt = &initial.Entry.PublicUrlExpiresAt
			type eventReply struct {
				page ingressv1.IngressRoutingTablePage
				err  error
			}
			eventStarted := make(chan struct{})
			eventReplies := make(chan eventReply)
			snapshotStarted := make(chan struct{})
			snapshotReplies := make(chan ingressv1.IngressRoutingTableSnapshot)
			renewed := make(chan struct{}, 1)
			firstSnapshot := true
			client := leaseTestClient{
				register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
					return testIngressLease(start), nil
				},
				renew: func(context.Context) (ingressv1.IngressLease, error) {
					lease := testIngressLease(now())
					lease.RegisteredAt = start
					select {
					case renewed <- struct{}{}:
					default:
					}
					return lease, nil
				},
				snapshot: func(ctx context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
					if firstSnapshot {
						firstSnapshot = false
						return ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{initial}}, nil
					}
					select {
					case snapshotStarted <- struct{}{}:
					case <-ctx.Done():
						return ingressv1.IngressRoutingTableSnapshot{}, ctx.Err()
					}
					select {
					case snapshot := <-snapshotReplies:
						return snapshot, nil
					case <-ctx.Done():
						return ingressv1.IngressRoutingTableSnapshot{}, ctx.Err()
					}
				},
				events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
					select {
					case eventStarted <- struct{}{}:
					case <-ctx.Done():
						return ingressv1.IngressRoutingTablePage{}, ctx.Err()
					}
					select {
					case reply := <-eventReplies:
						return reply.page, reply.err
					case <-ctx.Done():
						return ingressv1.IngressRoutingTablePage{}, ctx.Err()
					}
				},
			}
			metrics := observability.New("ingress")
			controller := testLeaseController(t, client)
			controller.now, controller.observer = now, metrics
			metrics.RegisterIngressRouting(controller.RoutingStatus)
			ctx, cancel := context.WithCancel(ingressContext(t))
			result := ingressWorker(t, cancel, func() error { return controller.Run(ctx) })
			select {
			case <-eventStarted: // the initial snapshot has been applied.
			case err := <-result:
				t.Fatalf("controller startup: %v", err)
			case <-ctx.Done():
				t.Fatal("controller startup timed out")
			}
			assertRoutingMetrics(t, metrics, map[string]float64{
				"initialized": 1, "caught_up": 0, "applied_revision": 1,
				"latest_observed_revision":                1,
				"last_successful_check_timestamp_seconds": float64(start.Unix()),
				"last_caught_up_timestamp_seconds":        0,
			})
			initialLease := controller.Lease()
			advance := func(at time.Time) {
				t.Helper()
				clock.Store(at.UnixNano())
				for controller.Lease().RenewedAt.Before(at) {
					ingressAwait(t, renewed)
				}
			}
			reply := func(response eventReply) {
				t.Helper()
				select {
				case eventReplies <- response:
				case <-ctx.Done():
					t.Fatal("controller stopped before event reply")
				}
			}

			// a quiet, successful long poll confirms freshness without new events.
			checked := start.Add(time.Second)
			advance(checked)
			reply(eventReply{page: ingressv1.IngressRoutingTablePage{ThroughRevision: 1, NextRevision: 1}})
			ingressAwait(t, eventStarted)
			assertRoutingMetrics(t, metrics, map[string]float64{
				"caught_up": 1, "last_successful_check_timestamp_seconds": float64(checked.Unix()),
				"last_caught_up_timestamp_seconds": float64(checked.Unix()),
			})

			// reuse the server harness for real visitor TLS and byte forwarding.
			before, after := newTLSBackend(t), newTLSBackend(t)
			firstAttempt := newFailAfterProxyBackend(t, 0)
			_, address := startIngress(t, Config{Metrics: metrics, Lookup: func(host string) (PublicURL, string) {
				entry, ok := controller.Lookup(host, now())
				if !ok {
					return PublicURL{}, "not_found"
				}
				backends := []routebackend.Backend{before}
				if entry.PolicyRevision > 1 {
					backends = []routebackend.Backend{firstAttempt, after}
				}
				return PublicURL{ID: entry.PublicUrlId, PublishRunNumber: uint64(entry.PublishRunNumber), Backends: backends, AllowAll: true}, ""
			}})
			advance(expires.Add(-time.Nanosecond))
			if _, ok := controller.Lookup("route.example", now()); !ok {
				t.Fatal("cached route rejected before expiry")
			}
			exchangePing(t, ingressClient(t, address, "route.example", ""))
			if got := ingressAwait(t, before.result); got.err != nil || got.request != "ping" {
				t.Fatalf("forward before expiry: %+v", got)
			}
			advance(expires)
			lease := controller.Lease()
			if !lease.RenewedAt.After(initialLease.RenewedAt) || !lease.LeaseExpiresAt.After(initialLease.LeaseExpiresAt) {
				t.Fatalf("lease did not advance while event fetch was blocked: before=%+v after=%+v", initialLease, lease)
			}
			if !controller.Ready(now()) {
				t.Fatal("existing readiness must remain live-lease plus initialized map during the stall")
			}
			if _, ok := controller.Lookup("route.example", now()); ok {
				t.Fatal("cached route survived its exact expiry boundary")
			}
			visitor := ingressClient(t, address, "route.example", "")
			if err := visitor.Handshake(); err == nil {
				t.Fatal("visitor forwarded through expired cached routing state")
			}
			_ = visitor.Close()
			if before.opens.Load() != 1 || after.opens.Load() != 0 || firstAttempt.opens.Load() != 0 {
				t.Fatal("expired lookup attempted a backend")
			}
			assertRoutingMetrics(t, metrics, map[string]float64{
				"last_successful_check_timestamp_seconds": float64(checked.Unix()),
				"last_caught_up_timestamp_seconds":        float64(checked.Unix()),
				"applied_revision":                        1, "latest_observed_revision": 1,
				"caught_up": 1, "update_failures_total": 0, "resnapshots_total": 0,
			})
			if operationSamples(t, metrics, "IngressRenewLease", "success") < 2 || operationSamples(t, metrics, "IngressFetchEvents", "success") != 1 {
				t.Fatal("metrics did not separate progressing lease renewals from the stalled event fetch")
			}

			advance(expires.Add(time.Second))
			recovered := routingReliabilityEvent(now(), 2)
			if resnapshot {
				reply(eventReply{err: serviceapi.NewProblemError(409, "routing_table_resnapshot_required", "snapshot required")})
				ingressAwait(t, snapshotStarted)
				if controller.Ready(now()) {
					t.Fatal("resnapshot-required response did not clear readiness")
				}
				assertRoutingMetrics(t, metrics, map[string]float64{
					"initialized": 1, "caught_up": 0, "resnapshots_total": 1, "update_failures_total": 0,
				})
				select {
				case snapshotReplies <- ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2, Entries: []ingressv1.IngressRoutingTableEvent{recovered}}:
				case <-ctx.Done():
					t.Fatal("controller stopped before resnapshot reply")
				}
				ingressAwait(t, eventStarted)
				assertRoutingMetrics(t, metrics, map[string]float64{
					"initialized": 1, "caught_up": 0, "applied_revision": 2, "latest_observed_revision": 2,
				})
			} else {
				// applying part of a page sequence is progress, not catch-up.
				reply(eventReply{page: ingressv1.IngressRoutingTablePage{
					ThroughRevision: 3, NextRevision: 2, More: true, Events: []ingressv1.IngressRoutingTableEvent{recovered},
				}})
				ingressAwait(t, eventStarted)
				assertRoutingMetrics(t, metrics, map[string]float64{
					"caught_up": 0, "applied_revision": 2, "latest_observed_revision": 3,
					"last_successful_check_timestamp_seconds": float64(now().Unix()),
					"last_caught_up_timestamp_seconds":        float64(checked.Unix()),
				})
			}
			advance(expires.Add(2 * time.Second))
			finalRevision := int64(2)
			page := ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2}
			if !resnapshot {
				finalRevision = 3
				page = ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{routingReliabilityEvent(now(), 3)}}
			}
			reply(eventReply{page: page})
			ingressAwait(t, eventStarted)
			assertRoutingMetrics(t, metrics, map[string]float64{
				"caught_up": 1, "applied_revision": float64(finalRevision), "latest_observed_revision": float64(finalRevision),
				"last_successful_check_timestamp_seconds": float64(now().Unix()),
				"last_caught_up_timestamp_seconds":        float64(now().Unix()),
			})
			if entry, ok := controller.Lookup("route.example", now()); !ok || entry.PolicyRevision != finalRevision || !controller.Ready(now()) {
				t.Fatalf("routing did not recover: entry=%+v found=%t", entry, ok)
			}
			exchangePing(t, ingressClient(t, address, "route.example", ""))
			if got := ingressAwait(t, after.result); got.err != nil || got.request != "ping" || got.visitorConnectionID != firstAttempt.visitorConnectionID() {
				t.Fatalf("forward after recovery, with retry before visitor bytes: %+v", got)
			}
			if firstAttempt.opens.Load() != 1 || after.opens.Load() != 1 {
				t.Fatal("recovered route did not retry exactly once before visitor bytes")
			}
			lease = controller.Lease()
			if controller.Ready(lease.LeaseExpiresAt) {
				t.Fatal("ingress ready at exact ingress lease expiry")
			}
			if _, ok := controller.Lookup("route.example", lease.LeaseExpiresAt); ok {
				t.Fatal("route available at ingress lease expiry")
			}
			for _, operation := range []string{"IngressFetchSnapshot", "IngressApplySnapshot", "IngressApplyEvents"} {
				if operationSamples(t, metrics, operation, "success") == 0 {
					t.Fatalf("missing production operation span %s", operation)
				}
			}

			if !resnapshot {
				// invalid updates must not advance the successful-check timestamp or
				// partially mutate the last applied revision.
				advance(now().Add(time.Second))
				reply(eventReply{page: ingressv1.IngressRoutingTablePage{ThroughRevision: 4, NextRevision: 4}})
				if err := ingressAwait(t, result); !errors.Is(err, ErrRoutingTableRevision) {
					t.Fatalf("invalid page result = %v", err)
				}
				assertRoutingMetrics(t, metrics, map[string]float64{
					"caught_up": 0, "update_failures_total": 1, "applied_revision": 3, "latest_observed_revision": 3,
					"last_successful_check_timestamp_seconds": float64(expires.Add(2 * time.Second).Unix()),
				})
				if operationSamples(t, metrics, "IngressApplyEvents", "error") != 1 {
					t.Fatal("invalid application was not measured")
				}
			} else {
				cancel()
				if err := ingressAwait(t, result); err != nil {
					t.Fatal(err)
				}
				assertRoutingMetrics(t, metrics, map[string]float64{"update_failures_total": 0, "resnapshots_total": 1})
				if operationSamples(t, metrics, "IngressFetchEvents", "canceled") != 1 || operationSamples(t, metrics, "IngressFetchEvents", "error") != 1 {
					t.Fatal("fetch cancellation and resnapshot response were not measured separately")
				}
			}
		})
	}
}

func routingReliabilityEvent(now time.Time, revision int64) ingressv1.IngressRoutingTableEvent {
	entry := forwardingTestEntry(now, "relay.example:443")
	entry.CanonicalHostname = "route.example"
	entry.PolicyRevision = revision
	entry.IpPolicy = ingressv1.AllowAll
	return ingressv1.IngressRoutingTableEvent{
		RoutingTableRevision: revision, Kind: ingressv1.PublicUrlUpsert, PublicUrlId: entry.PublicUrlId,
		PublishRunNumber: entry.PublishRunNumber, CanonicalHostname: entry.CanonicalHostname,
		EntryRevision: revision, Entry: entry, PublicUrlExpiresAt: &entry.PublicUrlExpiresAt, CreatedAt: now,
	}
}

func assertRoutingMetrics(t *testing.T, metrics *observability.Metrics, want map[string]float64) {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for suffix, expected := range want {
		found := false
		for _, family := range families {
			if family.GetName() != "tnl_ingress_routing_"+suffix {
				continue
			}
			found = true
			if len(family.Metric) != 1 || len(family.Metric[0].Label) != 0 {
				t.Fatalf("routing metric must have one unlabeled sample: %v", family)
			}
			metric := family.Metric[0]
			got := metric.GetGauge().GetValue()
			if metric.Counter != nil {
				got = metric.Counter.GetValue()
			}
			if got != expected {
				t.Errorf("%s = %v, want %v", family.GetName(), got, expected)
			}
		}
		if !found {
			t.Errorf("missing routing metric %s", suffix)
		}
	}
}

func operationSamples(t *testing.T, metrics *observability.Metrics, operation, outcome string) uint64 {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "tnl_ingress_operation_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["operation"] == operation && labels["outcome"] == outcome {
				return metric.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}
