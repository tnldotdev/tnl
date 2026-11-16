package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// observe only batches acknowledged by the real control API. the publisher
// still owns its production queue, report scheduling, credentials, and flush.
type heldVisitorAuditControl struct {
	*publisheridentity.Native
	committed *eventRecorder[serviceaudit.Observation]
}

func (c heldVisitorAuditControl) ReportServiceRunObservations(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, batch serviceaudit.Batch) error {
	if err := c.Native.ReportServiceRunObservations(ctx, service, run, number, token, batch); err != nil {
		return err
	}
	for _, event := range batch.Events {
		c.committed.append(event)
	}
	return nil
}

type heldVisitorAuditRun struct {
	handle        *integrationPublisher
	ready         controlv1.ServiceRunPreparation
	committed     eventRecorder[serviceaudit.Observation]
	calls, active atomic.Int32
	finished      chan error
	joined        int
	response      *http.Response
	visitor       *tls.Conn
	reader        *bufio.Reader
	prefix, tail  string
}

func TestIntegrationHeldVisitorsShareIngressAndKeepExactAuditHistories(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newSplitPublishFixture(t, "held-visitors")
	quic, _ := f.connectors()
	// one transport is sufficient for this composition proof; the transport
	// matrix belongs to the existing public stream and run-capacity suites.
	tcp, _ := disabledIntegrationConnector("TLS/TCP disabled by held visitor proof")
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var runs []*heldVisitorAuditRun
	for index := range 2 {
		run := &heldVisitorAuditRun{
			finished: make(chan error, 4),
			prefix:   fmt.Sprintf("held-%d\n", index), tail: fmt.Sprintf("finished-%d\n", index),
		}
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run.calls.Add(1)
			run.active.Add(1)
			var result error
			defer func() { run.active.Add(-1); run.finished <- result }()
			w.Header().Set("Content-Type", "application/octet-stream")
			if _, result = io.WriteString(w, run.prefix); result != nil {
				return
			}
			if result = http.NewResponseController(w).Flush(); result != nil {
				return
			}
			select {
			case <-release:
				_, result = io.WriteString(w, run.tail)
			case <-r.Context().Done():
				result = context.Cause(r.Context())
			}
		}))
		// after the target listener closes, every entered handler has sent its
		// independent result, including handlers from a failed assertion path.
		f.owner.cleanupResource(t, func() {
			for run.joined < int(run.calls.Load()) {
				select {
				case err := <-run.finished:
					run.joined++
					if err != nil {
						t.Error("held application cleanup", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("held application cleanup did not join")
					return
				}
			}
		})
		cleanupIntegrationHTTPServer(t, target, f.owner)
		hostname := fmt.Sprintf("%d-%s", index, f.identity.hostname)
		_, config := f.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{
			Hostname: &hostname,
			Http:     &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)}},
		})
		// leave physical connection room for an overflow request to complete TLS
		// and receive the exact HTTP concurrency rejection, not an earlier EOF.
		native, ok := config.Control.(*publisheridentity.Native)
		if !ok {
			t.Fatal("held visitor fixture requires its scoped native publisher")
		}
		scoped, err := native.WithTraffic(&trafficlimits.Selection{Connections: new(4)})
		if err != nil {
			t.Fatal(err)
		}
		config.StreamCapacity = 4
		config.Control, config.Access = heldVisitorAuditControl{Native: scoped, committed: &run.committed}, scoped.Access
		run.handle = startOwnedIntegrationPublisher(t, f.owner, config, func() string {
			return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
		})
		run.ready = f.waitReadyHostname(t, run.handle, hostname)
		if run.ready.Traffic.Connections != 4 {
			t.Fatal("physical connection approval did not retain overflow room")
		}
		runs = append(runs, run)
	}
	if runs[0].ready.ServiceId == runs[1].ready.ServiceId || runs[0].ready.ServiceRunId == runs[1].ready.ServiceRunId ||
		runs[0].ready.PublisherIdentityId == runs[1].ready.PublisherIdentityId {
		t.Fatal("two held services did not have distinct runs and publisher identities")
	}
	assertSplitLeases(t, f.inspect, 1, 2, 0, 0)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// each body must finish, and its target handler must join, before a
	// publisher or relay is stopped. cleanup retains independent failures.
	defer func() {
		unblock()
		for _, run := range runs {
			if run.response != nil {
				if err := run.response.Body.Close(); err != nil {
					t.Error("close held visitor response", err)
				}
			}
			if run.visitor != nil {
				if err := run.visitor.Close(); err != nil {
					t.Error("close held visitor TLS", err)
				}
			}
		}
	}()
	for _, run := range runs {
		openHeldAuditVisitor(t, ctx, f, run)
		state := run.visitor.ConnectionState()
		if run.response.StatusCode != http.StatusOK || len(state.VerifiedChains) == 0 || state.ServerName != run.ready.Hostname {
			t.Fatal("held visitor lost its selected service or verified visitor TLS")
		}
		prefix := make([]byte, len(run.prefix))
		if _, err := io.ReadFull(run.response.Body, prefix); err != nil || string(prefix) != run.prefix {
			t.Fatal("held visitor did not receive its own application's prefix", err)
		}
	}
	for _, run := range runs {
		if run.active.Load() != 1 || run.calls.Load() != 1 {
			t.Fatal("both service runs were not carrying held application traffic together")
		}
		response, _, err := f.visitor.requestURLContext(ctx, http.MethodGet, serviceHTTPAddress(run.ready)+"/overflow", nil)
		if err != nil {
			t.Fatal("overflow failed before its HTTP capacity decision", err)
		}
		if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Tnl-Error-Code") != "TNL_REQUEST_LIMIT_REACHED" {
			t.Fatal("overflow did not receive the configured HTTP concurrency rejection", response.StatusCode)
		}
		if run.active.Load() != 1 || run.calls.Load() != 1 {
			t.Fatal("overflow entered the application or evicted its admitted visitor")
		}
		// ingress owns selection denials, not HTTP access decisions. exercise
		// its real producer/queue too, with this service's denied source policy.
		assertHeldVisitorIngressSourceDenied(t, ctx, f, run.ready.Hostname)
	}
	for _, run := range runs {
		if run.active.Load() != 1 || run.calls.Load() != 1 {
			t.Fatal("a denial changed either simultaneously held application")
		}
	}
	unblock()
	for _, run := range runs {
		tail, readErr := io.ReadAll(run.response.Body)
		closeErr := run.response.Body.Close()
		run.response = nil
		if err := errors.Join(readErr, closeErr); err != nil || string(tail) != run.tail {
			t.Fatal("admitted application response did not finish exactly once", err)
		}
		if err := run.visitor.CloseWrite(); err != nil {
			t.Fatal("held visitor TLS write half did not finish", err)
		}
		var extra [1]byte
		if n, err := run.reader.Read(extra[:]); n != 0 || err != io.EOF {
			t.Fatal("held visitor TLS did not finish without extra application bytes", n, err)
		}
		select {
		case err := <-run.finished:
			run.joined++
			if err != nil {
				t.Fatal("held application did not finish cleanly", err)
			}
		case <-ctx.Done():
			t.Fatal("held application handler did not join", context.Cause(ctx))
		}
		if run.active.Load() != 0 || run.calls.Load() != 1 {
			t.Fatal("completed application retained work or replayed a request")
		}
	}
	for _, run := range runs {
		// a complete response at the visitor is not a joined publisher stream.
		// retain the live run and relays until its real close producer commits.
		cursor := 0
		for {
			event, err := run.committed.next(ctx, &cursor)
			if err != nil {
				t.Fatal("publisher did not commit its visitor retirement before shutdown", err)
			}
			if event.EventType == "connection.close" {
				if event.Outcome != "closed" || event.Reason != "closed" {
					t.Fatal("publisher visitor retirement failed before shutdown", event.Outcome, event.Reason)
				}
				break
			}
		}
	}
	for _, run := range runs {
		err := run.visitor.Close()
		run.visitor = nil
		if err != nil {
			t.Fatal("completed held visitor TLS did not close", err)
		}
		stopIntegrationPublisher(t, run.handle)
	}
	// joined process shutdown flushes the real ingress queue before inspecting
	// durable histories. relays stay alive through both publisher joins.
	stopIntegrationProcess(t, f.ingress)
	seenVisitors := make(map[string]bool)
	for _, run := range runs {
		assertHeldVisitorAuditHistory(t, f.inspect, f.identity.teamID, run, seenVisitors)
	}
}

func openHeldAuditVisitor(t *testing.T, ctx context.Context, f *splitPublishFixture, run *heldVisitorAuditRun) {
	t.Helper()
	// borrow the existing visitor's dialer, so both exact hostnames go through
	// the same live public front listener and the same ingress process.
	raw, err := f.visitor.transport.DialContext(ctx, "tcp", net.JoinHostPort(run.ready.Hostname, "443"))
	if err != nil {
		t.Fatal(err)
	}
	config := f.visitor.transport.TLSClientConfig.Clone()
	config.ServerName, config.NextProtos = run.ready.Hostname, []string{"http/1.1"}
	run.visitor = tls.Client(raw, config)
	deadline, _ := ctx.Deadline()
	if err := run.visitor.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := run.visitor.HandshakeContext(ctx); err != nil {
		t.Fatal("held visitor TLS handshake", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, serviceHTTPAddress(run.ready)+"/held-application", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	if err := request.Write(run.visitor); err != nil {
		t.Fatal("write held application request", err)
	}
	run.reader = bufio.NewReader(run.visitor)
	run.response, err = http.ReadResponse(run.reader, request)
	if err != nil {
		t.Fatal("held visitor did not receive application headers", err)
	}
}

func assertHeldVisitorIngressSourceDenied(t *testing.T, ctx context.Context, f *splitPublishFixture, hostname string) {
	t.Helper()
	raw, err := new(net.Dialer).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
	if err != nil {
		t.Fatal(err)
	}
	secure := tls.Client(raw, &tls.Config{RootCAs: f.pebble.roots, ServerName: hostname, MinVersion: tls.VersionTLS13})
	defer func() {
		if err := secure.Close(); err != nil {
			t.Error("close denied visitor TLS", err)
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	// this is the same trusted PROXY boundary used by the fixture's front
	// listener; no forwarding, policy, audit sink, or relay is replaced.
	metadata, err := proxyproto.Encode(proxyproto.Header{
		Source: netip.MustParseAddrPort("192.0.2.7:40000"), Destination: netip.MustParseAddrPort("127.0.0.1:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := raw.Write(metadata); err != nil || n != len(metadata) {
		t.Fatal("write denied visitor's trusted socket metadata", n, err)
	}
	if err := secure.HandshakeContext(ctx); err != io.EOF {
		t.Fatal("source denial did not close before visitor TLS", err)
	}
}

func assertHeldVisitorAuditHistory(t *testing.T, database *sql.DB, team string, run *heldVisitorAuditRun, seen map[string]bool) {
	t.Helper()
	committed, reportErr := run.committed.snapshot()
	if reportErr != nil || len(committed) != 5 {
		t.Fatal("joined publisher did not commit its complete held/overflow audit", len(committed), reportErr)
	}
	byID := make(map[string]serviceaudit.Observation)
	for _, event := range committed {
		if _, duplicate := byID[event.EventID]; duplicate || event.ServiceID != run.ready.ServiceId ||
			event.RunID != run.ready.ServiceRunId || event.RunNumber != run.ready.RunNumber || event.SourceIP != "127.0.0.1" {
			t.Fatal("real queued publisher observation lost its exact service/run/visitor scope")
		}
		byID[event.EventID] = event
	}
	rows, err := database.QueryContext(integrationOperationContext(t), `
		SELECT to_jsonb(e) || jsonb_build_object('cursor',e.cursor::text,'source_ip',host(e.source_ip))
		FROM control.service_audit_events e WHERE service_id=$1 AND visitor_connection_id IS NOT NULL ORDER BY cursor
	`, run.ready.ServiceId)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Error("close held visitor audit rows", err)
		}
	}()
	histories := make(map[string][]string)
	ingressDenials := 0
	for rows.Next() {
		var raw []byte
		var event serviceaudit.Event
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if event.TeamID != team || event.ServiceID != run.ready.ServiceId || event.VisitorConnectionID == "" ||
			event.ActorIdentityID != "" || event.DeviceID != "" {
			t.Fatal("durable visitor audit lost its team/service or invented an actor")
		}
		for _, excluded := range []string{"/held-application", "/overflow", run.prefix, run.tail, run.ready.RunToken} {
			if excluded != "" && strings.Contains(string(raw), excluded) {
				t.Fatal("audit retained application data or a credential")
			}
		}
		if event.RunID == "" {
			if event.EventType != "connection.open" || event.Outcome != "denied" || event.Reason != "ip_policy" ||
				event.SourceIP != "192.0.2.7" || event.PublisherIdentityID != "" || seen[event.VisitorConnectionID] {
				t.Fatal("real ingress queue lost its run-less source-policy denial")
			}
			seen[event.VisitorConnectionID] = true
			ingressDenials++
			continue
		}
		queued, exists := byID[event.ID]
		if !exists || queued.VisitorConnectionID != event.VisitorConnectionID || queued.EventType != event.EventType ||
			queued.Outcome != event.Outcome || queued.Reason != event.Reason || event.RunID != run.ready.ServiceRunId ||
			event.PublisherIdentityID != run.ready.PublisherIdentityId || event.SourceIP != "127.0.0.1" {
			t.Fatal("durable history differs from its real queued publisher event")
		}
		delete(byID, event.ID)
		histories[event.VisitorConnectionID] = append(histories[event.VisitorConnectionID], event.EventType+"/"+event.Outcome+"/"+event.Reason)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantHeld := []string{"connection.open/allowed/", "http.decision/allowed/", "connection.close/closed/closed"}
	wantOverflow := []string{"http.decision/denied/capacity", "connection.open/denied/authorization"}
	held, overflow := 0, 0
	for visitor, history := range histories {
		if seen[visitor] {
			t.Fatal("visitor connection ID crossed service/run histories")
		}
		seen[visitor] = true
		t.Logf("durable visitor: visitor_connection_id=%s service_id=%s run_id=%s events=%d", visitor, run.ready.ServiceId, run.ready.ServiceRunId, len(history))
		switch {
		case reflect.DeepEqual(history, wantHeld):
			held++
		case reflect.DeepEqual(history, wantOverflow):
			overflow++
		default:
			t.Fatal("unexpected held/overflow audit history", history)
		}
	}
	if len(byID) != 0 || held != 1 || overflow != 1 || ingressDenials != 1 {
		t.Fatal("queued observations did not durably retain exactly one held, overflow, and ingress-denied visitor per service", held, overflow, ingressDenials)
	}
	t.Logf("durable audit: service_id=%s run_id=%s held=%d overflow=%d ingress_denied=%d", run.ready.ServiceId, run.ready.ServiceRunId, held, overflow, ingressDenials)
}
