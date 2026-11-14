package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type trafficWriteRecorder struct {
	net.Conn
	writes []int
}

func (c *trafficWriteRecorder) Write(value []byte) (int, error) {
	c.writes = append(c.writes, len(value))
	return len(value), nil
}

func TestBudgetConnCannotBypassDirectionalAccounting(t *testing.T) {
	connection := new(trafficWriteRecorder)
	var charged int
	budget := &budgetConn{Conn: connection, beforeWrite: func(size int) error { charged += size; return nil }}
	if _, ok := any(budget).(io.ReaderFrom); ok {
		t.Fatal("ReaderFrom bypasses the write budget")
	}
	if _, ok := any(budget).(io.WriterTo); ok {
		t.Fatal("WriterTo bypasses the write budget")
	}
	size := (64 << 10) + 1
	written, err := budget.Write(make([]byte, size))
	if err != nil || written != size || charged != size || len(connection.writes) != 3 ||
		connection.writes[0] != 32<<10 || connection.writes[1] != 32<<10 || connection.writes[2] != 1 {
		t.Fatal("encrypted writes bypassed bounded accounting", written, charged, connection.writes, err)
	}
}

func serviceTrafficVisitor(t *testing.T, p *PublicServices, key trafficKey, limits TrafficLimits) *visitorAdmission {
	t.Helper()
	v, reason := p.server.admitPendingService()
	if v == nil {
		t.Fatal(reason)
	}
	t.Cleanup(v.close)
	if reason := v.selectRun(key, limits, netip.MustParseAddr("192.0.2.4"), false); reason != "" {
		t.Fatal(reason)
	}
	return v
}

func TestPublicServicePromotionDebitsLifetimeOnce(t *testing.T) {
	p, c, _, _ := publicServiceTestSetup(t)
	key := trafficKey{service: c.service, id: c.run, run: 1}
	limits := p.server.config.Traffic.Default
	limits.Connections, limits.TotalConnections = 1, 1
	first := serviceTrafficVisitor(t, p, key, limits)
	var group sync.WaitGroup
	var accepted atomic.Int32
	for range 20 {
		group.Go(func() {
			if first.reserve(limits) == "" {
				accepted.Add(1)
			}
		})
	}
	group.Wait()
	if accepted.Load() != 1 {
		t.Fatal("promotion was not exactly once", accepted.Load())
	}
	second := serviceTrafficVisitor(t, p, key, limits)
	if reason := second.reserve(limits); reason != "service_connections" {
		t.Fatal("ordinary concurrency was not separate from pending capacity", reason)
	}
	first.close()
	if reason := second.reserve(limits); reason != "service_connection_total" {
		t.Fatal("closing released the lifetime connection debit", reason)
	}
	p.server.traffic.mu.Lock()
	run := *p.server.traffic.runs[key]
	p.server.traffic.mu.Unlock()
	if run.active != 0 || run.connections != 1 {
		t.Fatal("promotion changed its lifetime debit on retry or close", run)
	}
}

func TestPublicServicePhysicalLoadCountsPendingAndPromotedVisitorOnce(t *testing.T) {
	p, c, _, _ := publicServiceTestSetup(t)
	connection, peer := net.Pipe()
	defer connection.Close()
	defer peer.Close()
	_, release, ok := p.acquireSession(t.Context(), connection)
	if !ok {
		t.Fatal("physical connection was not acquired")
	}
	defer release()
	limits := p.server.config.Traffic.Default
	v := serviceTrafficVisitor(t, p, trafficKey{service: c.service, id: c.run, run: 1}, limits)
	if pending, active := publicServiceAdmissionCounts(p); pending != 1 || active != 0 || p.Load() != 1 {
		t.Fatal("pending connection had incorrect physical load", pending, active, p.Load())
	}
	if reason := v.reserve(limits); reason != "" {
		t.Fatal(reason)
	}
	v.meterOrdinaryBytes()
	if pending, active := publicServiceAdmissionCounts(p); pending != 0 || active != 1 || p.Load() != 1 {
		t.Fatal("promotion counted a physical visitor twice", pending, active, p.Load())
	}
	v.close()
	release()
	if p.Load() != 0 || !publicServiceCapacityReleased(p) {
		t.Fatal("closed physical visitor retained load")
	}
}

func TestPublicServiceReservationKeepsUnacknowledgedBytesPending(t *testing.T) {
	p, c, _, _ := publicServiceTestSetup(t)
	key := trafficKey{service: c.service, id: c.run, run: 1}
	limits := p.server.config.Traffic.Default
	v := serviceTrafficVisitor(t, p, key, limits)
	if reason := v.reserve(limits); reason != "" {
		t.Fatal(reason)
	}
	size := int(p.server.config.Pending.UploadBytes) + 1
	if err := v.beforeWrite(t.Context(), true, size); err == nil {
		t.Fatal("budget reservation bypassed pending bytes before acknowledgment")
	}
	v.meterOrdinaryBytes()
	if err := v.beforeWrite(t.Context(), true, size); err != nil {
		t.Fatal("acknowledged visitor retained its pending byte budget", err)
	}
	p.server.traffic.mu.Lock()
	uploaded := p.server.traffic.runs[key].upload
	p.server.traffic.mu.Unlock()
	if uploaded != int64(size) {
		t.Fatal("ordinary bytes were not debited once", uploaded)
	}
}

func TestPublicServiceDirectionalTotalsShareOnlyTheExactRunAndProcess(t *testing.T) {
	p, c, _, _ := publicServiceTestSetup(t)
	key := trafficKey{service: c.service, id: c.run, run: 1}
	limits := p.server.config.Traffic.Default
	limits.TotalUploadBytes, limits.TotalDownloadBytes = 4, 8
	first := serviceTrafficVisitor(t, p, key, limits)
	second := serviceTrafficVisitor(t, p, key, limits)
	for _, v := range []*visitorAdmission{first, second} {
		if reason := v.reserve(limits); reason != "" {
			t.Fatal(reason)
		}
		v.meterOrdinaryBytes()
	}
	if err := first.beforeWrite(t.Context(), true, 4); err != nil {
		t.Fatal(err)
	}
	if err := second.beforeWrite(t.Context(), true, 1); err == nil {
		t.Fatal("another connection reset the run's upload total")
	}
	if err := second.beforeWrite(t.Context(), false, 8); err != nil {
		t.Fatal("upload consumed download capacity", err)
	}
	if err := first.beforeWrite(t.Context(), false, 1); err == nil {
		t.Fatal("another connection reset the run's download total")
	}
	first.close()
	second.close()
	otherProcess := trafficFixture(t)
	release, reason := otherProcess.acquire(key, limits)
	if release == nil {
		t.Fatal(reason)
	}
	defer release()
	if err := otherProcess.bytes(t.Context(), key, true, 4, true); err != nil {
		t.Fatal("one ingress process consumed another process's run budget", err)
	}
}

func TestPublicServiceAnonymousAccountingSkipsPendingBudgetsAndKeepsRestrictedSetupIndependent(t *testing.T) {
	p, c, _, _ := publicServiceTestSetup(t)
	a := p.server.traffic
	a.pending.SourceConnections, a.pending.PublicURLConnections = 1, 1
	key := trafficKey{service: c.service, id: c.run, run: 1}
	limits := a.config.Default
	limits.TotalConnections, limits.TotalUploadBytes = 1, 4
	restricted := serviceTrafficVisitor(t, p, key, limits)
	anonymous, reason := p.server.admitPendingService()
	if anonymous == nil {
		t.Fatal(reason)
	}
	defer anonymous.close()
	if reason := anonymous.selectRun(key, limits, restricted.source, true); reason != "" {
		t.Fatal("anonymous accounting consumed an occupied pending budget", reason)
	}
	if pending, active := publicServiceAdmissionCounts(p); pending != 1 || active != 1 {
		t.Fatal("anonymous selection did not transfer its process slot", pending, active)
	}
	if err := anonymous.beforeWrite(t.Context(), true, 4); err != nil {
		t.Fatal("anonymous bytes were not metered before publisher authorization", err)
	}
	if err := anonymous.beforeWrite(t.Context(), true, 1); err == nil {
		t.Fatal("anonymous bytes bypassed the ordinary lifetime total")
	}
	if err := restricted.beforeWrite(t.Context(), true, 4); err != nil {
		t.Fatal("anonymous exhaustion consumed the restricted setup budget", err)
	}
	anonymous.close()
	restricted.close()
	// a restricted setup remains possible after the ordinary total is exhausted;
	// publisher authorization must still acquire that ordinary quota later.
	next := serviceTrafficVisitor(t, p, key, limits)
	if reason := next.reserve(limits); reason != "service_connection_total" {
		t.Fatal("anonymous close released its lifetime debit", reason)
	}
}

func TestPublicServiceAnonymousAccountingStillWaitsForPublisherAuthorization(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.anonymous, c.pending, f.failFirst, f.holdAfterReply = true, true, true, true
	total := int64(1)
	c.traffic.TotalConnections = &total
	c.recheckStarted, c.promoteStarted = make(chan struct{}, 1), make(chan struct{}, 1)
	const hostname = "anonymous.example.test"
	p.config.Control = &httpsServiceControl{publicServiceControlFixture: c,
		services: map[string]httpsService{hostname: {service: c.service, run: c.run}}, claims: make(chan ingressv1.PublicServiceVisitorClaim, 1)}
	events := make(chan serviceaudit.Observation, 2)
	p.config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool { events <- event; return true })
	connection, visitor := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		defer connection.Close()
		done <- p.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"),
			netip.MustParseAddrPort("203.0.113.8:443"), hostname, []byte("ping"))
	}()
	defer func() { cancel(); _ = visitor.Close(); <-done }()
	_ = visitor.SetDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(visitor, reply); err != nil || string(reply) != "pong" {
		t.Fatal("anonymous setup forwarding failed", string(reply), err)
	}
	select {
	case <-c.recheckStarted:
	case <-time.After(time.Second):
		t.Fatal("publisher authorization was not checked")
	}
	select {
	case <-c.promoteStarted:
		t.Fatal("anonymous accounting acknowledged target authorization")
	case <-events:
		t.Fatal("anonymous accounting emitted authorized admission")
	default:
	}
	a := p.server.traffic
	key := trafficKey{service: c.service, id: c.run, run: 1}
	a.mu.Lock()
	run := *a.runs[key]
	pendingRuns, sources := len(a.pendingRuns), len(a.sources)
	a.mu.Unlock()
	if run.connections != 1 || run.upload != 4 || run.download != 4 || pendingRuns != 0 || sources != 0 || f.count() != 2 {
		t.Fatal("anonymous accounting reset on fallback or charged metadata/pending budgets", run, pendingRuns, sources, f.count())
	}
	c.mu.Lock()
	c.pending, c.authenticated = false, true
	c.mu.Unlock()
	select {
	case <-c.promoteStarted:
	case <-time.After(time.Second):
		t.Fatal("publisher-authorized anonymous visitor did not acknowledge its budget")
	}
	select {
	case event := <-events:
		if event.Outcome != "allowed" {
			t.Fatal("publisher-authorized admission was not recorded", event)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-reserved anonymous quota was debited again instead of acknowledged")
	}
	a.mu.Lock()
	connections := a.runs[key].connections
	a.mu.Unlock()
	if connections != 1 {
		t.Fatal("publisher authorization debited the anonymous connection twice", connections)
	}
}

func TestAnonymousMalformedTLSUsesProcessAndSourceAdmissionWithoutPromotion(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	s := p.server
	s.config.MaxClientHelloConnections = 1
	left, peer := net.Pipe()
	connection := &addressConn{Conn: left, remote: netip.MustParseAddrPort("192.0.2.4:42000"), local: netip.MustParseAddrPort("203.0.113.8:443")}
	if !s.admit(connection) {
		t.Fatal("initial inspection rejected")
	}
	other, otherPeer := net.Pipe()
	defer other.Close()
	defer otherPeer.Close()
	if s.admit(other) {
		t.Fatal("malformed visitor bypassed the process inspection cap")
	}
	done := make(chan error, 1)
	go func() {
		defer s.active.Done()
		defer s.release(connection)
		finish := sync.OnceFunc(s.finishInspection)
		defer finish()
		done <- s.handle(connection, finish)
	}()
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = peer.Write([]byte{0, 0, 0, 0, 0})
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("malformed inspection did not join")
	}
	s.active.Wait()
	a := s.traffic
	a.mu.Lock()
	source := a.sources[trafficlimits.SourceNetwork(connection.remote.Addr())]
	charged := source != nil && source.attempts.tokens < float64(a.config.SourceBurst) && source.connections == 0 &&
		a.connections.tokens < float64(a.config.ProcessBurst)
	ordinary, pending := len(a.runs), len(a.pendingRuns)
	a.mu.Unlock()
	if !charged || ordinary != 0 || pending != 0 || f.count() != 0 || c.closed != 0 || !publicServiceCapacityReleased(p) {
		t.Fatal("malformed anonymous TLS bypassed admission or promoted/forwarded", charged, ordinary, pending, f.count())
	}
}

func TestPublicServiceChargesInitialBytesOnceAcrossFallbackWithoutMetadata(t *testing.T) {
	p, c, f, _ := publicServiceTestSetup(t)
	c.pending, f.failFirst, f.holdAfterReply = true, true, true
	connection, visitor := net.Pipe()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		defer connection.Close()
		done <- p.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"),
			netip.MustParseAddrPort("203.0.113.8:20000"), "", []byte("ping"))
	}()
	defer func() { cancel(); _ = visitor.Close(); <-done }()
	_ = visitor.SetDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(visitor, reply); err != nil || string(reply) != "pong" {
		t.Fatal("prefix forwarding failed", string(reply), err)
	}
	a := p.server.traffic
	a.mu.Lock()
	upload, download := a.uploads.tokens, a.downloads.tokens
	a.mu.Unlock()
	if f.count() != 2 || upload != float64(a.config.ProcessUpload)-4 || download != float64(a.config.ProcessDownload)-4 {
		t.Fatalf("prefix/metadata charged incorrectly: attempts=%d upload=%g download=%g", f.count(), upload, download)
	}
}

func TestPublicServiceTerminalLookupIsExactAndOutsideMeterLock(t *testing.T) {
	p, c, _, lease := publicServiceTestSetup(t)
	a := p.server.traffic
	key := trafficKey{service: c.service, id: c.run, run: 1}
	sibling := trafficKey{service: c.service, id: "sibling", run: 2}
	limits := a.config.Default
	limits.TotalConnections = 1
	for _, key := range []trafficKey{key, sibling} {
		release, reason := a.acquire(key, limits)
		if release == nil {
			t.Fatal(reason)
		}
		release()
	}
	c.closedRuns = []ingressv1.ServiceRunReference{{ServiceId: key.service, ServiceRunId: key.id, RunNumber: int64(key.run)}}
	c.closureStarted, c.closureGate = make(chan struct{}, 1), make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); p.retireClosedTrafficRuns(t.Context(), lease) }()
	select {
	case <-c.closureStarted:
	case <-time.After(time.Second):
		t.Fatal("terminal lookup did not start")
	}
	unblock := sync.OnceFunc(func() { close(c.closureGate) })
	defer func() { unblock(); <-done }()
	meterDone := make(chan struct{})
	go func() {
		defer close(meterDone)
		release, _ := a.source(netip.MustParseAddr("192.0.2.7"))
		if release != nil {
			release()
		}
	}()
	select {
	case <-meterDone:
	case <-time.After(time.Second):
		t.Fatal("control lookup held the traffic mutex")
	}
	unblock()
	<-done
	a.mu.Lock()
	_, retained := a.runs[key]
	_, retainedSibling := a.runs[sibling]
	a.mu.Unlock()
	if retained || !retainedSibling {
		t.Fatal("terminal lookup did not retire only its exact closed tuple")
	}
}

func TestPublicServiceTerminalLookupRetainsUnknownAndRejectsUnrequestedProof(t *testing.T) {
	for _, mode := range []string{"unknown", "outage", "different service", "different run", "different number", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			p, c, _, lease := publicServiceTestSetup(t)
			a := p.server.traffic
			key := trafficKey{service: c.service, id: c.run, run: 1}
			limits := a.config.Default
			limits.TotalConnections = 1
			release, _ := a.acquire(key, limits)
			release()
			ref := ingressv1.ServiceRunReference{ServiceId: key.service, ServiceRunId: key.id, RunNumber: 1}
			switch mode {
			case "outage":
				c.closureErr = errors.New("control unavailable")
			case "different service":
				ref.ServiceId = "other"
			case "different run":
				ref.ServiceRunId = "other"
			case "different number":
				ref.RunNumber++
			}
			if mode != "unknown" {
				c.closedRuns = []ingressv1.ServiceRunReference{ref}
			}
			if mode == "duplicate" {
				c.closedRuns = append(c.closedRuns, ref)
			}
			p.retireClosedTrafficRuns(t.Context(), lease)
			if release, reason := a.acquire(key, limits); release != nil || reason != "service_connection_total" {
				t.Fatal("missing or malformed proof reset a finite total", reason)
			}
		})
	}
}

func TestTrafficTerminalCandidatesAreBoundedAndDoNotStarveUncheckedRuns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := trafficFixture(t)
		limits := a.config.Default
		limits.TotalConnections = 1
		for n := uint64(1); n <= 129; n++ {
			a.runs[trafficKey{service: "service", id: "run", run: n}] = &runTraffic{limits: limits}
		}
		first := a.terminalCandidates(time.Now())
		if len(first) != 128 || len(a.terminalCandidates(time.Now())) != 0 {
			t.Fatal("terminal query was unbounded or not throttled")
		}
		seen := make(map[ingressv1.ServiceRunReference]bool, len(first))
		for _, run := range first {
			seen[run] = true
		}
		time.Sleep(31 * time.Second)
		next := a.terminalCandidates(time.Now())
		if len(next) != 128 || seen[next[0]] {
			t.Fatal("previously unknown runs starved an unchecked run")
		}
	})
}

func TestHTTPControlClientClosedServiceRuns(t *testing.T) {
	expected := ingressv1.ServiceRunClosureLookup{IngressRunId: "process", IngressLeaseRevision: 7,
		ServiceRuns: []ingressv1.ServiceRunReference{{ServiceId: "service", ServiceRunId: "run", RunNumber: 3}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/ingresses/ingress/public-services/closed-runs" {
			t.Error("wrong terminal lookup operation", r.Method, r.URL.Path)
		}
		var body ingressv1.ServiceRunClosureLookup
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IngressRunId != expected.IngressRunId ||
			body.IngressLeaseRevision != expected.IngressLeaseRevision || len(body.ServiceRuns) != 1 || body.ServiceRuns[0] != expected.ServiceRuns[0] {
			t.Error("terminal lookup changed exact lease/run facts", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ingressv1.ServiceRunClosures{Closed: expected.ServiceRuns})
	}))
	defer server.Close()
	generated, err := ingressv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewHTTPControlClient(generated)
	if err != nil {
		t.Fatal(err)
	}
	closed, err := control.ClosedServiceRuns(t.Context(), "ingress", expected)
	if err != nil || len(closed.Closed) != 1 || closed.Closed[0] != expected.ServiceRuns[0] {
		t.Fatal("terminal lookup changed response", closed, err)
	}
}
