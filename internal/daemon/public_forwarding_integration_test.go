package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegrationPublicForwardingScalesIngressWithoutPublisherAttachments(t *testing.T) {
	f := newSplitPublishFixture(t, "public-scale")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	ticks := [2]chan string{make(chan string), make(chan string)}
	var opened [2]atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := -1
		switch r.URL.Path {
		case "/held/0":
			index = 0
		case "/held/1":
			index = 1
		default:
			_, _ = io.WriteString(w, r.URL.Path)
			return
		}
		opened[index].Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "initial\n")
		w.(http.Flusher).Flush()
		for {
			select {
			case tick, ok := <-ticks[index]:
				if !ok {
					return
				}
				_, _ = fmt.Fprintln(w, tick)
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, _ := disabledIntegrationConnector("public scale proof uses TLS/TCP publisher slots")
	_, tcp := f.connectors()
	tcp, attachments := observeIntegrationConnector(tcp)
	publisher := f.startPublisher(t, target.URL, quic, tcp)
	ready := f.waitReady(t, publisher)
	defer func() {
		if t.Failed() {
			logIntegrationPublishRunAuthority(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, "public-scale-failure")
		}
	}()
	before := [2]splitConnectionState{
		readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, "relay-a"),
		readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, "relay-b"),
	}
	if attachments.successful.Load() != 2 || attachments.attempts.Load() != 2 {
		t.Fatalf("initial publisher attachments: successful=%d attempts=%d", attachments.successful.Load(), attachments.attempts.Load())
	}
	assertSlots := func(phase string) {
		t.Helper()
		assertPublishRunNumber(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber)
		assertSplitRoutePlacement(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber)
		for index, service := range []string{"relay-a", "relay-b"} {
			if after := readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, service); after != before[index] {
				t.Fatalf("%s replaced publisher slot: before=%+v after=%+v", phase, before[index], after)
			}
		}
		if attachments.successful.Load() != 2 || attachments.attempts.Load() != 2 {
			t.Fatalf("%s added publisher attachments: successful=%d attempts=%d", phase, attachments.successful.Load(), attachments.attempts.Load())
		}
		select {
		case <-publisher.done:
			t.Fatalf("%s stopped publisher: %v", phase, publisher.result())
		default:
		}
	}
	assertRequest := func(visitor *integrationVisitor, phase string) {
		t.Helper()
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, ready.PublicURL+"/"+phase, nil)
		if err != nil {
			t.Fatalf("%s visitor: %v", phase, err)
		}
		if response.StatusCode != http.StatusOK || string(body) != "/"+phase {
			t.Fatalf("%s response: status=%d body=%q", phase, response.StatusCode, body)
		}
		assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
	}
	openHeld := func(visitor *integrationVisitor, index int) (*http.Response, *bufio.Reader) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/held/%d", ready.PublicURL, index), nil)
		if err != nil {
			t.Fatal(err)
		}
		// the request context bounds this held stream; the shared fixture's
		// ordinary ten-second HTTP deadline must not stand in for a relay fault.
		client := *visitor.client
		client.Timeout = 0
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		reader := bufio.NewReader(response.Body)
		if line, err := reader.ReadString('\n'); err != nil || line != "initial\n" {
			t.Fatalf("held stream %d: %q, %v", index, line, err)
		}
		return response, reader
	}
	assertHeld := func(reader *bufio.Reader, index int, phase string) {
		t.Helper()
		select {
		case ticks[index] <- phase:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if line, err := reader.ReadString('\n'); err != nil || line != phase+"\n" {
			t.Fatalf("%s held stream %d: %q, %v", phase, index, line, err)
		}
		if opened[index].Load() != 1 {
			t.Fatalf("%s replayed held target %d: opens=%d", phase, index, opened[index].Load())
		}
	}
	first, firstReader := openHeld(f.visitor, 0)
	startIngress := func(id string) (*integrationProcess, *integrationVisitor) {
		t.Helper()
		sockets := runtimeListeners{ingress: serviceRuntimeListener(t), metrics: serviceRuntimeListener(t)}
		config := f.ingressConfig
		config.IngressID = id
		config.IngressListen, config.MetricsListen = sockets.ingress.Addr().String(), sockets.metrics.Addr().String()
		config.IngressUDPListen = ""
		process := startIntegrationProcessWithOptions(t, config, integrationProcessOptions{
			acmeHTTPClient: f.pebble.httpClient, serviceHTTPClient: f.serviceHTTP,
			relayClientTLS: f.roots, owner: f.owner, listeners: sockets,
		})
		waitForProcessReady(t, process)
		visitor := newIntegrationVisitor(t, f.pebble.roots, config.IngressListen, f.owner)
		return process, visitor
	}
	secondProcess, secondVisitor := startIngress("ingress-public-second")
	second, secondReader := openHeld(secondVisitor, 1)
	// hold both original visitors beyond their pre-scale allocation deadline.
	// process readiness alone cannot prove renewed publisher-observed capacity.
	var initialDeadline time.Time
	if err := f.inspect.QueryRowContext(integrationOperationContext(t), `SELECT max(valid_until)
		FROM control.stream_capacity_allocations WHERE resource_id=$1 AND run_number=$2 AND retired_at IS NULL`,
		ready.PublicURLID, ready.PublishRunNumber).Scan(&initialDeadline); err != nil {
		t.Fatal(err)
	}
	thirdProcess, thirdVisitor := startIngress("ingress-public-third")
	waitForIngressRoutingCurrent(t, f.inspect, 3)
	// this fixture has five-second process leases, which also clip allocations.
	// its successful visitor TLS handshakes already consumed prepared capacity;
	// require all three exact current owners, not five extra seconds of authority.
	waitForIntegrationCondition(t, 5*time.Second, func(ctx context.Context) (bool, error) {
		var observed int
		err := f.inspect.QueryRowContext(ctx, `SELECT count(DISTINCT a.ingress_id)
			FROM control.stream_capacity_allocations a JOIN control.ingress_leases l
			ON l.ingress_id=a.ingress_id AND l.ingress_run_id=a.ingress_run_id
			AND l.ingress_lease_revision=a.ingress_lease_revision
			WHERE a.resource_kind='public_url' AND a.resource_id=$1 AND a.run_number=$2
			AND a.publisher_observed_until>now() AND a.retired_at IS NULL
			AND a.valid_until>now() AND NOT l.draining AND l.lease_expires_at>now()`,
			ready.PublicURLID, ready.PublishRunNumber).Scan(&observed)
		return err == nil && observed == 3, err
	})
	waitUntilIntegrationTime(t, initialDeadline.Add(25*time.Millisecond))
	for index, visitor := range []*integrationVisitor{f.visitor, secondVisitor, thirdVisitor} {
		assertRequest(visitor, fmt.Sprintf("three-ingresses-%d", index))
	}
	assertHeld(firstReader, 0, "after-scale")
	assertHeld(secondReader, 1, "after-scale")
	assertSlots("three ingresses")

	f.ingress.cancel()
	waitForIngressRoutingCurrent(t, f.inspect, 2)
	waitForIntegrationCondition(t, time.Second, func(ctx context.Context) (bool, error) {
		connection, err := new(net.Dialer).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
		if err == nil {
			_ = connection.Close()
			return false, nil
		}
		return true, nil
	})
	select {
	case <-f.ingress.done:
		t.Fatal("ingress stopped before draining its held visitor")
	default:
	}
	assertRequest(secondVisitor, "during-drain-second")
	assertRequest(thirdVisitor, "during-drain-third")
	assertHeld(firstReader, 0, "during-drain")
	assertHeld(secondReader, 1, "during-sibling-drain")
	close(ticks[0])
	if _, err := io.Copy(io.Discard, first.Body); err != nil {
		t.Fatalf("drained visitor: %v", err)
	}
	_ = first.Body.Close()
	waitForIntegrationProcess(t, f.ingress)
	assertSlots("drained ingress")

	close(ticks[1])
	if _, err := io.Copy(io.Discard, second.Body); err != nil {
		t.Fatal(err)
	}
	_ = second.Body.Close()
	stopIntegrationProcess(t, secondProcess)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	assertRequest(thirdVisitor, "only-third-ingress")
	assertSlots("removed ingress")
	stopIntegrationProcess(t, thirdProcess)
	t.Log("three public ingresses served one run through the original two publisher slots; held visitors survived scale-out and bounded drain; the third served after both siblings stopped")
}
