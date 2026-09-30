package tnldruntime

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tunnel"
)

func TestIntegrationPublisherFallsBackWhenQUICStalls(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "fallback")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "TLS/TCP fallback")
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
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "TLS/TCP fallback" {
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
	quicSessions := make(chan muxsession.Session, 4)
	quic := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		session, err := quicBase.Connect(ctx, endpoint)
		if err == nil {
			quicSessions <- session
		}
		return session, err
	})
	tcp := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		return tcpBase.Connect(ctx, endpoint)
	})
	config := fixture.identity.publisherConfig(target.URL, quic, tcp)
	config.FallbackDelay = time.Second
	handle := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
	ready := fixture.waitReady(t, handle)

	request, err := http.NewRequest(http.MethodGet, ready.PublicURL+"/held", nil)
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
	if err == nil || len(remaining) != 0 {
		t.Fatalf("interrupted visitor stream = %q, %v; want interrupted without replay", remaining, err)
	}

	recoveryCtx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	for {
		event, err := handle.events.next(recoveryCtx, &handle.cursor)
		if err != nil {
			t.Fatalf("publisher did not recover on TLS/TCP: %v, result %v%s", err, handle.result(), fixture.diagnostics())
		}
		if event.Type == publisher.EventTransportFallback {
			if event.Transport != tunnel.TransportTLSTCP || event.PublishRunNumber != ready.PublishRunNumber {
				t.Fatalf("recovery fallback event = %#v", event)
			}
			break
		}
	}
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	fixture.visitor.transport.CloseIdleConnections()
	after, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after", nil)
	if err != nil || after.StatusCode != http.StatusOK || string(body) != "after recovery" {
		t.Fatalf("visitor after recovery = %v, %q, %v", after, body, err)
	}
	if count := heldRequests.Load(); count != 1 {
		t.Fatalf("interrupted visitor stream reached the local service %d times; want once", count)
	}
	select {
	case <-quicSessions:
		t.Fatal("replacement attempted QUIC before TLS/TCP")
	default:
	}
}
