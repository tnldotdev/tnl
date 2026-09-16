package tnldruntime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"golang.org/x/net/websocket"
)

func TestIntegrationStandalonePublishAndVisit(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "visit")
	type targetRequest struct {
		host    string
		path    string
		headers http.Header
	}
	targetRequests := make(chan targetRequest, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case targetRequests <- targetRequest{
			host: request.Host, path: request.URL.RequestURI(), headers: request.Header.Clone(),
		}:
		default:
		}
		response.Header().Set("X-Tnl-Integration", "publisher")
		_, _ = io.WriteString(response, "visitor reached local service")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	quicConnector, tcpConnector := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	ready := fixture.waitReady(t, handle)
	request, err := http.NewRequest(http.MethodGet, ready.PublicURL+"/through-tnl?source=integration", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Forwarded", "for=198.51.100.1")
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	request.Header.Set("X-Forwarded-Host", "spoofed.example")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Real-IP", "198.51.100.1")
	response, body, err := fixture.visitor.request(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "visitor reached local service" ||
		response.Header.Get("X-Tnl-Integration") != "publisher" {
		t.Fatalf("visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationRouteCertificate(t, response, fixture.identity.hostname)

	select {
	case observed := <-targetRequests:
		if observed.host != fixture.identity.hostname || observed.path != "/through-tnl?source=integration" {
			t.Fatalf("local service request = %#v", observed)
		}
		if observed.headers.Get("X-Forwarded-For") != "127.0.0.1" ||
			observed.headers.Get("X-Forwarded-Host") != fixture.identity.hostname ||
			observed.headers.Get("X-Forwarded-Proto") != "https" ||
			observed.headers.Get("Forwarded") != "" || observed.headers.Get("X-Real-IP") != "" {
			t.Fatalf("local service forwarding headers = %#v", observed.headers)
		}
	case <-time.After(time.Second):
		t.Fatal("local service did not observe the visitor request")
	}

	fixture.visitor.transport.CloseIdleConnections()
	stopIntegrationPublisher(t, handle)
	stopIntegrationProcess(t, fixture.process)
	assertStandaloneUsage(t, fixture.databaseURL, fixture.inspect, ready.RouteID, ready.RouteVersion)
}

func TestIntegrationPublisherTransportMatrix(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newStandalonePublishFixture(t, "transport-"+transport)
			var (
				mu       sync.Mutex
				requests = make(map[string]int)
			)
			target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
				if err != nil {
					http.Error(response, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				requests[request.URL.Path]++
				mu.Unlock()
				if request.Method == http.MethodPost {
					_, _ = response.Write(body)
					return
				}
				_, _ = io.WriteString(response, request.URL.Path)
			}))
			cleanupIntegrationHTTPServer(t, target, fixture.owner)

			quicBase, tcpBase := fixture.connectors()
			var quicStats, tcpStats *integrationConnectorStats
			var quicConnector, tcpConnector muxsession.Connector
			if transport == "quic" {
				quicConnector, quicStats = observeIntegrationConnector(quicBase)
				tcpConnector, tcpStats = disabledIntegrationConnector("TLS/TCP disabled by integration test")
			} else {
				quicConnector, quicStats = disabledIntegrationConnector("QUIC disabled by integration test")
				tcpConnector, tcpStats = observeIntegrationConnector(tcpBase)
			}
			handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
			ready := fixture.waitReady(t, handle)

			const concurrentRequests = 16
			results := make(chan error, concurrentRequests)
			for index := range concurrentRequests {
				go func() {
					path := fmt.Sprintf("/parallel/%d", index)
					request, err := http.NewRequest(http.MethodGet, ready.PublicURL+path, nil)
					if err != nil {
						results <- err
						return
					}
					response, body, err := fixture.visitor.request(request)
					if err != nil {
						results <- err
						return
					}
					if response.StatusCode != http.StatusOK || string(body) != path {
						results <- fmt.Errorf("%s response = %s, %q", path, response.Status, body)
						return
					}
					results <- nil
				}()
			}
			join, cancelJoin := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancelJoin()
			for range concurrentRequests {
				select {
				case err := <-results:
					if err != nil {
						t.Error(err)
					}
				case <-join.Done():
					t.Fatal("concurrent visitor requests did not finish")
				}
			}
			if t.Failed() {
				t.FailNow()
			}
			fallbacks := 0
			for _, event := range handle.observedEvents() {
				if event.Type == publisher.EventTransportFallback {
					fallbacks++
					if event.Transport != tunnel.TransportTLSTCP || event.RouteVersion != ready.RouteVersion {
						t.Fatalf("transport fallback event = %#v", event)
					}
				}
			}
			if transport == "quic" && fallbacks != 0 {
				t.Fatalf("QUIC publisher emitted %d transport fallback events", fallbacks)
			}
			if transport == "tls-tcp" && fallbacks != 1 {
				t.Fatalf("TLS/TCP publisher emitted %d transport fallback events; want 1", fallbacks)
			}

			largeBody := bytes.Repeat([]byte("tnl-transport-payload-"), (1<<20)/len("tnl-transport-payload-")+1)
			largeBody = largeBody[:1<<20]
			request, err := http.NewRequest(http.MethodPost, ready.PublicURL+"/large-post", bytes.NewReader(largeBody))
			if err != nil {
				t.Fatal(err)
			}
			response, body, err := fixture.visitor.request(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || !bytes.Equal(body, largeBody) {
				t.Fatalf("large POST response = %s, %d bytes", response.Status, len(body))
			}

			mu.Lock()
			defer mu.Unlock()
			if len(requests) != concurrentRequests+1 {
				t.Fatalf("local service observed %d distinct requests, want %d", len(requests), concurrentRequests+1)
			}
			for path, count := range requests {
				if count != 1 {
					t.Fatalf("local service observed %s %d times", path, count)
				}
			}
			if transport == "quic" {
				if quicStats.successful.Load() != 2 || tcpStats.successful.Load() != 0 {
					t.Fatalf("transport sessions = QUIC %d, TLS/TCP %d", quicStats.successful.Load(), tcpStats.successful.Load())
				}
			} else if tcpStats.successful.Load() != 2 || quicStats.successful.Load() != 0 || quicStats.attempts.Load() < 2 {
				t.Fatalf(
					"transport sessions = QUIC %d/%d attempts, TLS/TCP %d",
					quicStats.successful.Load(), quicStats.attempts.Load(), tcpStats.successful.Load(),
				)
			}
		})
	}
}

func TestIntegrationLongLivedHTTPStreams(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newStandalonePublishFixture(t, "long-lived-http-"+transport)
			websocketGate := make(chan struct{})
			sseGate := make(chan struct{})
			streamGate := make(chan struct{})
			// Release handlers even if an assertion fails before the first read.
			releaseWebSocket := sync.OnceFunc(func() { close(websocketGate) })
			releaseSSE := sync.OnceFunc(func() { close(sseGate) })
			releaseStream := sync.OnceFunc(func() { close(streamGate) })
			defer releaseWebSocket()
			defer releaseSSE()
			defer releaseStream()
			mux := http.NewServeMux()
			mux.Handle("/websocket", websocket.Handler(func(connection *websocket.Conn) {
				defer connection.Close()
				if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					return
				}
				if err := websocket.Message.Send(connection, "connected"); err != nil {
					return
				}
				if err := waitForDoneWithin(websocketGate, 10*time.Second); err != nil {
					return
				}
				_ = websocket.Message.Send(connection, "update")
			}))
			mux.HandleFunc("/events", func(response http.ResponseWriter, _ *http.Request) {
				flusher, ok := response.(http.Flusher)
				if !ok {
					http.Error(response, "streaming unsupported", http.StatusInternalServerError)
					return
				}
				response.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(response, "data: connected\n\n")
				flusher.Flush()
				if err := waitForDoneWithin(sseGate, 10*time.Second); err != nil {
					return
				}
				_, _ = io.WriteString(response, "data: update\n\n")
				flusher.Flush()
			})
			mux.HandleFunc("/stream", func(response http.ResponseWriter, _ *http.Request) {
				flusher, ok := response.(http.Flusher)
				if !ok {
					http.Error(response, "streaming unsupported", http.StatusInternalServerError)
					return
				}
				response.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(response, "first\n")
				flusher.Flush()
				if err := waitForDoneWithin(streamGate, 10*time.Second); err != nil {
					return
				}
				_, _ = io.WriteString(response, "second\n")
				flusher.Flush()
			})
			target := httptest.NewServer(mux)
			cleanupIntegrationHTTPServer(t, target, fixture.owner)

			quicBase, tcpBase := fixture.connectors()
			var quicConnector, tcpConnector muxsession.Connector
			if transport == "quic" {
				quicConnector = quicBase
				tcpConnector, _ = disabledIntegrationConnector("TLS/TCP disabled by integration test")
			} else {
				quicConnector, _ = disabledIntegrationConnector("QUIC disabled by integration test")
				tcpConnector = tcpBase
			}
			handle := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
			ready := fixture.waitReady(t, handle)

			assertIntegrationWebSocketPushes(t, fixture, releaseWebSocket)
			assertIntegrationSSEPushes(t, fixture, ready.PublicURL, releaseSSE)
			assertIntegrationStreamingResponse(t, fixture, ready.PublicURL, releaseStream)
			stopIntegrationPublisher(t, handle)
		})
	}
}

func TestIntegrationPublisherRestartReusesCertificate(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "restart")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "publisher restart")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quicConnector, tcpConnector := fixture.connectors()

	first := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	firstReady := fixture.waitReady(t, first)
	firstResponse, body, err := fixture.visitor.requestURL(http.MethodGet, firstReady.PublicURL+"/before", nil)
	if err != nil {
		t.Fatal(err)
	}
	if firstResponse.StatusCode != http.StatusOK || string(body) != "publisher restart" {
		t.Fatalf("first visitor response = %s, %q", firstResponse.Status, body)
	}
	assertIntegrationRouteCertificate(t, firstResponse, fixture.identity.hostname)
	firstSerial := firstResponse.TLS.PeerCertificates[0].SerialNumber.String()
	firstOrderCount := integrationRouteOrderCount(t, fixture.inspect, firstReady.RouteID)

	stopIntegrationPublisher(t, first)
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var closed bool
		err := fixture.inspect.QueryRowContext(ctx, `
			SELECT closed_at IS NOT NULL
			FROM control.route_sessions
			WHERE route_id = $1 AND route_version = $2
		`, firstReady.RouteID, firstReady.RouteVersion).Scan(&closed)
		return err == nil && closed, err
	})
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	response, _, unavailableErr := fixture.visitor.requestURL(http.MethodGet, firstReady.PublicURL+"/unavailable", nil)
	if unavailableErr == nil && response.StatusCode == http.StatusOK {
		t.Fatal("route remained available after the publisher stopped")
	}

	second := fixture.startPublisher(t, target.URL, quicConnector, tcpConnector)
	secondReady := fixture.waitReady(t, second)
	if secondReady.RouteID != firstReady.RouteID || secondReady.RouteVersion != firstReady.RouteVersion+1 {
		t.Fatalf("restarted route = %q version %d, want %q version %d", secondReady.RouteID, secondReady.RouteVersion, firstReady.RouteID, firstReady.RouteVersion+1)
	}
	secondResponse, body, err := fixture.visitor.requestURL(http.MethodGet, secondReady.PublicURL+"/after", nil)
	if err != nil {
		t.Fatal(err)
	}
	if secondResponse.StatusCode != http.StatusOK || string(body) != "publisher restart" {
		t.Fatalf("second visitor response = %s, %q", secondResponse.Status, body)
	}
	assertIntegrationRouteCertificate(t, secondResponse, fixture.identity.hostname)
	secondSerial := secondResponse.TLS.PeerCertificates[0].SerialNumber.String()
	if secondSerial != firstSerial {
		t.Fatalf("restarted certificate serial = %s, want %s", secondSerial, firstSerial)
	}
	if orderCount := integrationRouteOrderCount(t, fixture.inspect, secondReady.RouteID); orderCount != firstOrderCount {
		t.Fatalf("route ACME order count = %d, want %d", orderCount, firstOrderCount)
	}
}
