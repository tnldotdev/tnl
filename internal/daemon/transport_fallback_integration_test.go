package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherFallsBackWhenQUICStalls(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "fallback")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "WSS fallback")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	var quicAttempts eventRecorder[struct{}]
	quic := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		quicAttempts.append(struct{}{})
		<-ctx.Done()
		return nil, context.Cause(ctx)
	})
	_, tcp := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, handle)

	if attempts, _ := quicAttempts.snapshot(); len(attempts) < 2 {
		t.Fatal("publisher connection did not try QUIC before falling back")
	}
	response, body, err := fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "WSS fallback" {
		t.Fatalf("fallback visitor response = %s, %q", response.Status, body)
	}
}

func TestIntegrationPublisherFallsBackAfterQUICConnectionFails(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "quic-recovery")
	var heldRequests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/held" {
			heldRequests.Add(1)
			_, _ = io.WriteString(response, "first\n")
			response.(http.Flusher).Flush()
			<-request.Context().Done()
			return
		}
		_, _ = io.WriteString(response, "after recovery")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	quicBase, tcpBase := fixture.connectors()
	var recovering atomic.Bool
	quicSessions := make(chan muxsession.Session, 4)
	quic := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		session, err := quicBase.Connect(ctx, endpoint)
		if err == nil {
			quicSessions <- session
		}
		return session, err
	})
	tcp := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		if !recovering.Load() {
			// the fault must interrupt admitted QUIC sessions, not unused
			// candidates that already lost the initial transport race.
			<-ctx.Done()
			return nil, context.Cause(ctx)
		}
		return tcpBase.Connect(ctx, endpoint)
	})
	_, config := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{})
	handle := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
	ready := fixture.waitReady(t, handle)
	events := handle.observedEvents()
	if initial := events[len(events)-1]; initial.Transports != [2]tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportQUIC} {
		t.Fatal("fault injection requires two serving QUIC publisher connections", initial)
	}

	request, err := http.NewRequest(http.MethodGet, serviceHTTPAddress(ready)+"/held", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.visitor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if first, err := reader.ReadString('\n'); err != nil || first != "first\n" {
		t.Fatalf("held visitor first chunk = %q, %v", first, err)
	}
	originalA := readSplitConnectionState(t, fixture.inspect, ready.ServiceId, ready.RunNumber, standaloneRelays[0].serviceID)
	originalB := readSplitConnectionState(t, fixture.inspect, ready.ServiceId, ready.RunNumber, standaloneRelays[1].serviceID)
	recovering.Store(true)
	for range 2 {
		select {
		case session := <-quicSessions:
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("both initial QUIC publisher connections did not establish")
		}
	}
	remaining, err := io.ReadAll(reader)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || len(remaining) != 0 {
		t.Fatalf("interrupted visitor stream = %q, %v; want interrupted without replay", remaining, err)
	}

	recoveryCtx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	statusCursor := 0
	for {
		status, err := handle.events.next(recoveryCtx, &statusCursor)
		if err != nil {
			t.Fatalf("publisher did not recover on WSS: %v, result %v%s", err, handle.result(), fixture.diagnostics())
		}
		if status.Ready && status.Transports == [2]tunnel.Transport{tunnel.TransportWSS, tunnel.TransportWSS} {
			break
		}
	}
	// the first TCP fallback does not prove both old QUIC claims have retired.
	// count only current replacement identities. ingress may borrow their
	// background routing snapshot before sending any new visitor byte.
	waitForIntegrationCondition(t, 25*time.Second, func(ctx context.Context) (bool, error) {
		var readyReplacements int
		var slots string
		err := fixture.inspect.QueryRowContext(ctx, `
			SELECT count(*) FILTER (WHERE state='ready' AND session_open AND publisher_connection_id NOT IN ($3,$4)),
			  COALESCE(json_agg(json_build_object('id',publisher_connection_id,'state',state,
			    'revision',connection_assignment_revision,'open',session_open))::text,'[]')
			FROM control.service_connection_slots WHERE service_id=$1 AND run_number=$2
		`, ready.ServiceId, ready.RunNumber, originalA.publisherConnectionID, originalB.publisherConnectionID).Scan(&readyReplacements, &slots)
		if err != nil {
			return false, err
		}
		if readyReplacements != 2 {
			return false, fmt.Errorf("ready replacements = %d; slots = %s; publisher result = %v", readyReplacements, slots, handle.result())
		}
		return true, nil
	})
	waitForReadyPublisherConnections(t, fixture.inspect, ready.ServiceId, ready.RunNumber, 2)
	assertServiceRunNumber(t, fixture.inspect, ready.ServiceId, ready.RunNumber)
	// replacement readiness is not recovery: only a publisher byte successfully
	// written to a visitor completes the exact run's durable episode.
	var episode int64
	var openedAt time.Time
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `
		SELECT id,opened_at FROM control.service_recovery_episodes
		WHERE service_id=$1 AND service_run_id=$2 AND run_number=$3 AND state='open' AND observed_at IS NULL
	`, ready.ServiceId, ready.ServiceRunId, ready.RunNumber).Scan(&episode, &openedAt); err != nil {
		t.Fatal("replacement readiness completed or lost the recovery episode", err)
	}
	fixture.visitor.transport.CloseIdleConnections()
	after, body, err := fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready)+"/after", nil)
	if err != nil || after.StatusCode != http.StatusOK || string(body) != "after recovery" {
		t.Fatalf("visitor after recovery = %v, %q, %v", after, body, err)
	}
	if count := heldRequests.Load(); count != 1 {
		t.Fatalf("interrupted visitor stream reached the local service %d times; want once", count)
	}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var observed bool
		err := fixture.inspect.QueryRowContext(ctx, `SELECT state='observed' AND observed_at>=opened_at
			AND abs(recovery_seconds-extract(epoch FROM observed_at-opened_at)::double precision)<0.000001
			FROM control.service_recovery_episodes WHERE id=$1`, episode).Scan(&observed)
		return observed, err
	})
	var episodes, observations int
	if err := fixture.inspect.QueryRowContext(integrationOperationContext(t), `SELECT
		(SELECT count(*) FROM control.service_recovery_episodes WHERE service_run_id=$1),
		(SELECT observation_count FROM control.service_recovery_histogram WHERE id=1)`,
		ready.ServiceRunId).Scan(&episodes, &observations); err != nil || episodes != 1 || observations != 1 {
		t.Fatal("recovery did not record one exact-run observation", episodes, observations, err)
	}
	t.Logf("service recovery episode %d opened at %s and completed after actual visitor delivery", episode, openedAt)
	select {
	case <-quicSessions:
		t.Fatal("replacement attempted QUIC before WSS")
	default:
	}
}
