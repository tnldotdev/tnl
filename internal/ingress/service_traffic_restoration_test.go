package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// new serving observations use real source authority issuance; omission itself
// supplies neither a terminal proof nor permission to reset a run's totals.
func restorationTrafficSnapshot(t *testing.T, lease ingressv1.IngressLease, runs ...ingressv1.IngressServiceRun) ingressv1.IngressServices {
	t.Helper()
	now := time.Now()
	snapshot := ingressv1.IngressServices{ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}
	for _, run := range runs {
		run.ValidUntil = snapshot.ValidUntil
		run.ConnectedRelays = append([]ingressv1.ServiceRelay(nil), run.ConnectedRelays...)
		for index := range run.ConnectedRelays {
			run.ConnectedRelays[index].ServingUntil = lease.ServingUntil
		}
		authority, key, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, tunnelv1.VisitorSourceAuthority{
			ServiceID: run.ServiceId, ServiceRunID: run.ServiceRunId, RunNumber: uint64(run.RunNumber),
			EndpointRevision: run.EndpointRevision, IngressID: lease.IngressId, IngressRunID: lease.IngressRunId,
			IngressLeaseRevision: uint64(lease.IngressLeaseRevision), VisitorPolicyRevision: 1, ValidUntil: run.ValidUntil.Unix(),
		}, now)
		if err != nil {
			t.Fatal(err)
		}
		run.SourceAuthority, err = authority.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		run.SourceKey = key[:]
		snapshot.Runs = append(snapshot.Runs, run)
	}
	return snapshot
}

func TestServiceTrafficRestorationExhaustedTotalsSurviveRoutingOmissionAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, initial := serviceRoutingFixture(t)
		lease.ServingUntil = time.Now().Add(5 * time.Minute)
		config, control, _, _ := publicServiceTestConfig(t)
		config.CurrentLease = func() ingressv1.IngressLease { return lease }
		server := serviceSelectionServer(t, config)
		run := initial.Runs[0]
		limits := server.config.Traffic.Default
		limits.TotalConnections, limits.TotalUploadBytes, limits.TotalDownloadBytes = 1, 4, 4
		run.Traffic = publicServiceTraffic(limits)
		if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease, run)); err != nil {
			t.Fatal(err)
		}
		key := trafficKey{service: run.ServiceId, id: run.ServiceRunId, run: uint64(run.RunNumber)}
		release, reason := server.traffic.acquire(key, limits)
		if release == nil {
			t.Fatal(reason)
		}
		for _, upload := range []bool{true, false} {
			if err := server.traffic.bytes(t.Context(), key, upload, 4, true); err != nil {
				t.Fatal(err)
			}
		}
		release()
		// these are two actual full-snapshot omissions, separated by the original
		// two 31s prune phases, not direct meter-only aging.
		for range 2 {
			time.Sleep(time.Millisecond)
			if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease)); err != nil {
				t.Fatal(err)
			}
			if routes := server.services.lookup(run.Hostname, 443, lease, time.Now()); len(routes) != 0 {
				t.Fatal("omitted run remained selectable")
			}
			time.Sleep(31 * time.Second)
			server.traffic.mu.Lock()
			server.traffic.prune(time.Now())
			server.traffic.mu.Unlock()
			server.retireClosedTrafficRuns(t.Context(), lease)
		}
		if len(control.closedRuns) != 0 {
			t.Fatal("omission fixture invented a terminal proof")
		}
		if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease, run)); err != nil {
			t.Fatal("same live run could not recover", err)
		}
		routes := server.services.lookup(run.Hostname, 443, lease, time.Now())
		if len(routes) != 1 || routes[0].run.ServiceRunId != key.id {
			t.Fatal("recovery did not restore the exact same run")
		}
		if release, reason := server.traffic.acquire(key, limits); release != nil || reason != "service_connection_total" {
			if release != nil {
				release()
			}
			t.Fatal("routing recovery reset exhausted connection total", reason)
		}
		for _, upload := range []bool{true, false} {
			if err := server.traffic.bytes(t.Context(), key, upload, 1, true); err != trafficError("service_byte_total") {
				t.Fatal("routing recovery reset exhausted directional total", upload, err)
			}
		}
		server.traffic.mu.Lock()
		total := *server.traffic.runs[key]
		server.traffic.mu.Unlock()
		if total.connections != 1 || total.upload != 4 || total.download != 4 || total.active != 0 {
			t.Fatal("omission, pruning, or recovery changed exact cumulative totals", total)
		}
	})
}

type restorationClosureControl struct {
	PublicServiceControl
	expected ingressv1.ServiceRunClosureLookup
	ingress  string
	calls    int
}

func (c *restorationClosureControl) ClosedServiceRuns(_ context.Context, id string, request ingressv1.ServiceRunClosureLookup) (ingressv1.ServiceRunClosures, error) {
	c.calls++
	if id != c.ingress || !reflect.DeepEqual(request, c.expected) {
		return ingressv1.ServiceRunClosures{}, errors.New("terminal query changed exact ingress lease or run")
	}
	return ingressv1.ServiceRunClosures{Closed: append([]ingressv1.ServiceRunReference(nil), request.ServiceRuns...)}, nil
}

func TestServiceTrafficRestorationTrustedTerminalQueryCannotReviveSameRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		lease.ServingUntil = time.Now().Add(5 * time.Minute)
		config, base, _, _ := publicServiceTestConfig(t)
		config.CurrentLease = func() ingressv1.IngressLease { return lease }
		run := snapshot.Runs[0]
		ref := ingressv1.ServiceRunReference{ServiceId: run.ServiceId, ServiceRunId: run.ServiceRunId, RunNumber: run.RunNumber}
		control := &restorationClosureControl{PublicServiceControl: base, ingress: lease.IngressId,
			expected: ingressv1.ServiceRunClosureLookup{IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
				ServiceRuns: []ingressv1.ServiceRunReference{ref}}}
		config.Control = control
		server := serviceSelectionServer(t, config)
		if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease, run)); err != nil {
			t.Fatal(err)
		}
		limits := server.config.Traffic.Default
		limits.TotalConnections = 1
		key := trafficKey{service: ref.ServiceId, id: ref.ServiceRunId, run: uint64(ref.RunNumber)}
		release, reason := server.traffic.acquire(key, limits)
		if release == nil {
			t.Fatal(reason)
		}
		release()
		time.Sleep(time.Millisecond)
		if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease)); err != nil {
			t.Fatal(err)
		}
		// only the actual validated control-query path can retire this budget.
		server.retireClosedTrafficRuns(t.Context(), lease)
		server.traffic.mu.Lock()
		_, retained := server.traffic.runs[key]
		server.traffic.mu.Unlock()
		if control.calls != 1 || retained {
			t.Fatal("exact trusted closure query did not retire its inactive run", control.calls, retained)
		}
		time.Sleep(time.Millisecond)
		if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease, run)); err == nil {
			t.Error("a later snapshot revived a proven-terminal same run after its budget retired")
		}
		if routes := server.services.lookup(run.Hostname, 443, lease, time.Now()); len(routes) != 0 {
			t.Error("proven-terminal same run became selectable again")
		}
	})
}

func TestServiceTrafficRestorationExactPoolReleaseAndReselection(t *testing.T) {
	config, control, _ := serviceSelectionConfig(t, 2, true)
	for index := range control.runs {
		control.runs[index].Traffic.Connections = 1
	}
	server := serviceSelectionHTTPServer(t, config)
	lease := config.CurrentLease()
	selectRun := func(v *visitorAdmission) (selectedServiceRun, error) {
		return server.selectPublicRun(ingressContext(t), lease, netip.MustParseAddrPort("192.0.2.4:42000"),
			netip.MustParseAddrPort("203.0.113.10:443"), "route.example", v)
	}
	visitors := make([]*visitorAdmission, 3)
	for index := range visitors {
		v, reason := server.admitPendingService()
		if v == nil {
			t.Fatal(reason)
		}
		visitors[index] = v
		defer v.close()
	}
	first, err := selectRun(visitors[0])
	if err != nil || first.runID != control.runs[0].ServiceRunId {
		t.Fatal("first visitor did not select first run", first, err)
	}
	second, err := selectRun(visitors[1])
	if err != nil || second.runID != control.runs[1].ServiceRunId {
		t.Fatal("second visitor did not select sibling", second, err)
	}
	if _, err := selectRun(visitors[2]); err == nil || visitors[2].key != (trafficKey{}) {
		t.Fatal("full pool selected a run or acquired ordinary capacity", err, visitors[2].key)
	}
	visitors[0].close()
	visitors[0].close()
	server.nextServiceRun.Store(0)
	third, err := selectRun(visitors[2])
	if err != nil || third.runID != first.runID || visitors[1].key != selectionRunKey(control.runs[1]) {
		t.Fatal("releasing first run moved established sibling or prevented exact reuse", third, err)
	}
	server.traffic.mu.Lock()
	firstActive := server.traffic.runs[selectionRunKey(control.runs[0])].active
	secondActive := server.traffic.runs[selectionRunKey(control.runs[1])].active
	server.traffic.mu.Unlock()
	if firstActive != 1 || secondActive != 1 || len(control.claims) != 0 {
		t.Fatal("release/reselection changed capacity ownership", firstActive, secondActive, len(control.claims))
	}
}

func TestServiceTrafficRestorationPendingBudgetsAndClosedOwner(t *testing.T) {
	server, control, _, _ := publicServiceTestSetup(t)
	key := trafficKey{service: control.service, id: control.run, run: 1}
	visitor := serviceTrafficVisitor(t, server, key, server.config.Traffic.Default)
	for _, upload := range []bool{true, false} {
		size := server.config.Pending.DownloadBytes
		if upload {
			size = server.config.Pending.UploadBytes
		}
		if err := visitor.beforeWrite(t.Context(), upload, int(size)+1); err != trafficError("pending_byte_or_time_budget") {
			t.Fatal("pending directional bound did not fail closed", upload, err)
		}
	}
	visitor.mu.Lock()
	visitor.deadline = time.Now().Add(-time.Millisecond)
	visitor.mu.Unlock()
	if reason := visitor.reserveForVisitor(); reason != "pending_expired" {
		t.Fatal("expired visitor acquired ordinary capacity", reason)
	}
	visitor.close()
	if reason := visitor.reserveForVisitor(); reason != "pending_expired" {
		t.Fatal("closed visitor acquired ordinary capacity", reason)
	}
	if pending, active := publicServiceAdmissionCounts(server); pending != 0 || active != 0 || server.Load() != 0 {
		t.Fatal("expired/closed visitor retained capacity", pending, active, server.Load())
	}
}

func restorationTrafficIPPolicy(t *testing.T, prefix string) *controlv1.VisitorPolicyIP {
	t.Helper()
	key := [32]byte{1}
	hashed, err := ippolicy.Hash(key, netip.MustParsePrefix(prefix))
	if err != nil {
		t.Fatal(err)
	}
	return &controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{{
		Family: controlv1.HashedIPPrefixFamily(hashed.Family), PrefixLength: hashed.Bits, Digest: hashed.Digest,
	}}}
}

func TestServiceTrafficRestorationPendingAuthorizationRechecksExactRunAndAssignment(t *testing.T) {
	for _, mode := range []string{"exact behind sibling", "removed", "service changed", "number changed", "assignment changed", "IP denied", "unavailable", "process full", "draining", "closed visitor"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, control, forwarder := serviceSelectionConfig(t, 2, false)
				config.MaxConnections = 1
				selected := control.runs[0]
				upstream, publisher := net.Pipe()
				defer publisher.Close()
				reservations := make(chan func(context.Context) error, 1)
				headers := make(chan tunnelv1.ServiceForwardingHeader, 1)
				forwarder.openings[selected.ServiceRunId] = func(_ context.Context, header tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (net.Conn, error) {
					headers <- header
					reservations <- reserve
					return upstream, nil
				}
				server := serviceSelectionHTTPServer(t, config)
				lease := config.CurrentLease()
				original := server.services.runs[selected.ServiceRunId].run
				sibling := server.services.runs[control.runs[1].ServiceRunId].run
				connection, visitor := net.Pipe()
				defer visitor.Close()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					done <- server.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"),
						netip.MustParseAddrPort("203.0.113.10:443"), "route.example", []byte("ping"))
				}()
				defer func() { cancel(); _ = publisher.Close(); _ = visitor.Close(); <-done }()
				metadata, reader, err := proxyproto.Decode(publisher)
				if err != nil {
					t.Fatal(err)
				}
				var ping [4]byte
				if _, err := io.ReadFull(reader, ping[:]); err != nil || string(ping[:]) != "ping" || metadata.VisitorSourceProof == "" {
					t.Fatal("selected pending stream lost initial bytes or source", err)
				}
				header, reserve := <-headers, <-reservations
				synctest.Wait()
				time.Sleep(time.Millisecond)
				runs := []ingressv1.IngressServiceRun{sibling, original}
				switch mode {
				case "removed":
					runs = runs[:1]
				case "service changed":
					service := publicServiceTestID(t, "svc_")
					runs[0].ServiceId, runs[1].ServiceId = service, service
				case "number changed":
					runs[1].RunNumber++
				case "assignment changed":
					runs[1].ConnectedRelays = append([]ingressv1.ServiceRelay(nil), original.ConnectedRelays...)
					runs[1].ConnectedRelays[0].ConnectionAssignmentRevision++
				case "IP denied":
					runs[1].Ip = restorationTrafficIPPolicy(t, "198.51.100.0/24")
				case "unavailable":
					runs = nil
				}
				if err := server.services.apply(time.Now(), lease, restorationTrafficSnapshot(t, lease, runs...)); err != nil {
					t.Fatal("replacement observation was not valid at current wire boundary", err)
				}
				if mode == "process full" {
					release, reason := server.admitClass(visitorConnection)
					if release == nil {
						t.Fatal("could not occupy ordinary process capacity", reason)
					}
					defer release()
				}
				if mode == "draining" {
					server.StopAccepting()
				}
				if mode == "closed visitor" {
					cancel()
					_ = visitor.Close()
				}
				synctest.Wait()
				call, finish := context.WithDeadline(t.Context(), header.ExpiresAt)
				err = reserve(call)
				finish()
				if mode == "exact behind sibling" {
					if err != nil {
						t.Fatal("healthy sibling displaced already-selected exact pending run", err)
					}
				} else if err == nil {
					t.Error("stale pending stream acquired authorization/capacity after " + mode)
				}
				if mode == "process full" {
					var rejected *tunnel.ProtocolError
					if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
						t.Fatal("process-full pending reservation lost exact capacity outcome", err)
					}
				}
				server.traffic.mu.Lock()
				other := server.traffic.runs[selectionRunKey(control.runs[1])]
				server.traffic.mu.Unlock()
				if other != nil || header.ServiceRunID != selected.ServiceRunId || header.RunNumber != uint64(selected.RunNumber) ||
					header.PublisherConnectionID != selected.ConnectedRelays[0].PublisherConnectionId || len(control.claims) != 0 {
					t.Fatal("pending authorization switched run, assignment, or control path", header)
				}
			})
		})
	}
}

func TestServiceTrafficRestorationIPDenialAuditKeepsExactSource(t *testing.T) {
	var opens atomic.Int32
	config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
		opens.Add(1)
		return nil, errors.New("denied source reached relay")
	})
	control := config.Control.(*httpsServiceControl)
	control.sources = netip.MustParsePrefix("198.51.100.0/24")
	events := make(chan serviceaudit.Observation, 2)
	config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool { events <- event; return true })
	server := serviceSelectionHTTPServer(t, config)
	connection, visitor := net.Pipe()
	defer visitor.Close()
	source := netip.MustParseAddrPort("192.0.2.8:1234")
	if err := server.AcceptPublic(t.Context(), connection, source, netip.MustParseAddrPort("203.0.113.1:443"), "route.example", nil); !errors.Is(err, ErrServiceAdmission) {
		t.Fatal("IP denial did not fail admission", err)
	}
	event := ingressAwait(t, events)
	if event.Validate() != nil || event.ServiceID != control.service || event.Outcome != "denied" ||
		event.Reason != "ip_policy" || event.SourceIP != source.Addr().String() || event.EventType != "connection.open" ||
		event.RunID != "" || event.RunNumber != 0 || len(event.RoutingAuthority) == 0 ||
		len(events) != 0 || opens.Load() != 0 || len(control.claims) != 0 || !publicServiceCapacityReleased(server) {
		t.Fatalf("IP denial lost exact once-only audit or source: %+v", event)
	}
}

func TestServiceTrafficRestorationHTTPUnavailableAuditDoesNotInventRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, control, forwarder := serviceSelectionConfig(t, 1, true)
		config.OpenTimeout = time.Second
		events := make(chan serviceaudit.Observation, 2)
		config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool { events <- event; return true })
		forwarder.openings[control.runs[0].ServiceRunId] = func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
			return nil, ErrServiceAdmission
		}
		server := serviceSelectionServer(t, config)
		lease := config.CurrentLease()
		now := time.Now()
		snapshot, err := control.ReadIngressServices(t.Context(), lease.IngressId, ingressv1.IngressLeaseIdentity{
			IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		})
		if err != nil {
			t.Fatal(err)
		}
		for index := range snapshot.Runs[0].ConnectedRelays {
			snapshot.Runs[0].ConnectedRelays[index].ServingUntil = now.Add(time.Second)
		}
		if err := server.services.apply(now, lease, snapshot); err != nil {
			t.Fatal("valid short relay lease could not install", err)
		}
		// the endpoint and signed run observation remain current, but its last
		// relay lease has expired. no invalid snapshot or stored-state mutation.
		time.Sleep(time.Second)
		connection, visitor := net.Pipe()
		defer visitor.Close()
		if err := server.AcceptPublic(t.Context(), connection, netip.MustParseAddrPort("192.0.2.8:1234"),
			netip.MustParseAddrPort("203.0.113.1:443"), "route.example", nil); !errors.Is(err, ErrServiceAdmission) {
			t.Fatal("known unavailable HTTP service did not fail closed", err)
		}
		var event serviceaudit.Observation
		select {
		case event = <-events:
		default:
			t.Fatal("known unavailable HTTP service emitted no service-level denial audit")
		}
		if event.Validate() != nil || event.ServiceID != control.service || event.Outcome != "denied" || event.Reason != "unavailable" ||
			event.RunID != "" || event.RunNumber != 0 || event.SourceIP != "192.0.2.8" || len(events) != 0 ||
			len(forwarder.observed) != 0 || len(control.claims) != 0 || !publicServiceCapacityReleased(server) {
			t.Fatalf("known unavailable HTTP denial invented a selected run: %+v", event)
		}
	})
}

type restorationSetupBarrierConn struct {
	net.Conn
	cleared chan struct{}
	release <-chan struct{}
	clears  int
}

func (c *restorationSetupBarrierConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.clears++
		if c.clears == 2 {
			close(c.cleared)
			<-c.release
		}
	}
	return c.Conn.SetDeadline(deadline)
}

func TestServiceTrafficRestorationPostSetupTrackingFailureHasExactUploadMeter(t *testing.T) {
	upstream, publisher := net.Pipe()
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	connection := &restorationSetupBarrierConn{Conn: upstream, cleared: make(chan struct{}), release: release}
	initial := restorationMaximumClientHello()
	received := make(chan []byte, 1)
	read := ingressWorker(t, func() { unblock(); _ = publisher.Close() }, func() error {
		defer publisher.Close()
		_, reader, err := proxyproto.Decode(publisher)
		if err != nil {
			return err
		}
		got := make([]byte, len(initial))
		if _, err := io.ReadFull(reader, got); err != nil {
			return err
		}
		received <- got
		_, err = io.Copy(io.Discard, reader)
		return err
	})
	config := serviceIngressConfig(t, func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
		return connection, nil
	})
	config.Control.(*httpsServiceControl).anonymous = true
	metrics := &testMetrics{visitorOutcomes: make(chan string, 1)}
	config.Metrics = metrics
	server := serviceSelectionHTTPServer(t, config)
	public, visitor := net.Pipe()
	defer visitor.Close()
	done := ingressWorker(t, func() { unblock(); _ = visitor.Close() }, func() error {
		return server.AcceptPublic(ingressContext(t), public, netip.MustParseAddrPort("192.0.2.4:42000"),
			netip.MustParseAddrPort("203.0.113.10:443"), "route.example", initial)
	})
	ingressAwait(t, connection.cleared)
	if got := ingressAwait(t, received); !bytes.Equal(got, initial) {
		t.Fatal("setup did not actually commit the exact inspected bytes", len(got))
	}
	// HTTP live-visitor tracking is now ServiceRouting.bind, after writeSetup.
	// closing that owner at this barrier injects an actual post-setup failure.
	server.services.Close()
	unblock()
	if err := ingressAwait(t, done); !errors.Is(err, ErrServiceAdmission) {
		t.Fatal("post-setup tracking failure lost admission cause", err)
	}
	if err := ingressAwait(t, read); err != nil {
		t.Fatal(err)
	}
	upload, download := restorationForwardedTotals(metrics)
	if outcome := ingressAwait(t, metrics.visitorOutcomes); outcome != "committed_failed" ||
		upload != int64(len(initial)) || download != 0 || metrics.visitorOpenSuccesses.Load() != 1 ||
		metrics.visitorOpenFailures.Load() != 0 || len(server.backends) != 0 || !publicServiceCapacityReleased(server) {
		t.Fatalf("post-setup tracking meter: outcome=%s upload=%d download=%d", outcome, upload, download)
	}
}

func TestServiceTrafficRestorationGatedCapacityAndFailedOpenOutcomes(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		t.Run(map[bool]string{false: "lifetime", true: "pending"}[restricted], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			t.Cleanup(unblock)
			cause := errors.New("publisher unavailable")
			var opens atomic.Int32
			config := serviceIngressConfig(t, func(ctx context.Context, _ tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
				opens.Add(1)
				close(entered)
				select {
				case <-release:
					return nil, cause
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			})
			control := config.Control.(*httpsServiceControl)
			control.anonymous = !restricted
			if restricted {
				config.Pending.Connections, config.Pending.ServiceConnections, config.Pending.SourceConnections = 2, 1, 1
			} else {
				control.traffic.TotalConnections = new(int64(1))
			}
			metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
			config.Metrics = metrics
			server, address := startIngress(t, config)
			startServiceRoutingFixture(t, server)
			first := ingressClient(t, address, "route.example", "192.0.2.4:40001")
			result := ingressWorker(t, func() { unblock(); _ = first.Close() }, first.Handshake)
			ingressAwait(t, entered)
			second := ingressClient(t, address, "route.example", "192.0.2.4:40002")
			if err := second.Handshake(); err == nil {
				t.Fatal("full run completed visitor TLS")
			}
			unblock()
			if err := ingressAwait(t, result); err == nil {
				t.Fatal("failed publisher completed TLS")
			}
			outcomes := map[string]int{}
			for range 2 {
				outcomes[ingressAwait(t, metrics.visitorOutcomes)]++
			}
			upload, download := restorationForwardedTotals(metrics)
			if outcomes["capacity_denied"] != 1 || outcomes["open_failed"] != 1 ||
				opens.Load() != 1 || upload != 0 || download != 0 || metrics.visitorOpenFailures.Load() != 1 ||
				metrics.visitorOpenSuccesses.Load() != 0 || !publicServiceCapacityReleased(server) {
				t.Fatal("gated denial/open failure lost exact outcomes or zero-byte meters", outcomes, opens.Load(), upload, download)
			}
		})
	}
}
