package service

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"go.opentelemetry.io/otel/trace"
)

type observationVisitor struct {
	net.Conn
	unregister func()
	once       sync.Once
}

func (c *observationVisitor) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.unregister)
	return err
}

func TestServiceRecoveryObservationRestorationRegisteredHTTPVisitorsStayRunLocal(t *testing.T) {
	for _, transport := range []tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportWSS} {
		t.Run(string(transport), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			metrics := observability.New("publisher")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			ctx = observability.WithMetrics(ctx, metrics)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			defer target.Close()
			type run struct {
				id     string
				peers  [2]*tunnel.Session
				client *http.Client
				lost   <-chan struct{}
			}
			start := func() run {
				t.Helper()
				cfg, control := lifecycleFixture(t)
				approved, err := control.GetPublisherService(ctx, cfg.ServiceID, "")
				if err != nil {
					t.Fatal(err)
				}
				approved.Protocol, approved.Endpoint.Port, approved.Endpoint.Public = controlv1.ServiceProtocolHTTP, 443, true
				control.approved = &approved
				cfg.Control = sourceForwardingControl{control}
				cfg.Metadata.Protocol, cfg.Target = controlv1.ServiceProtocolHTTP, target.Listener.Addr().String()
				relay := newObservationRelay(t, &cfg, control, transport, nil)
				bounds := make(chan *Bound, 2)
				cfg.Connect = func(ctx context.Context, bound *Bound, slot uint8, options ConnectOptions) (SlotSession, error) {
					claimed, err := bound.ConnectSlot(ctx, slot, options)
					if err == nil {
						bounds <- bound
					}
					return claimed, err
				}
				ready, lost := make(chan struct{}), make(chan struct{})
				var announced atomic.Bool
				var once sync.Once
				cfg.Ready = func() error { announced.Store(true); close(ready); return nil }
				cfg.ObserveReadiness = func(status RunStatus) {
					if announced.Load() && !status.Draining && !status.Connected[0] && status.Connected[1] {
						once.Do(func() { close(lost) })
					}
				}
				life, stop := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { done <- Publish(life, cfg) }()
				var client *http.Client
				t.Cleanup(func() {
					if client != nil {
						client.CloseIdleConnections()
					}
					stop()
					if err := claimedAwait(t, done); err != nil {
						t.Error("recovery publication did not join cleanly", err)
					}
					relay.stop()
				})
				claimedAwait(t, ready)
				bound := claimedAwait(t, bounds)
				result := run{id: cfg.ServiceID, lost: lost}
				for slot := range 2 {
					result.peers[slot] = claimedAwait(t, relay.accepted[slot])
				}
				certificate, err := bound.prepared.currentCertificate()
				if err != nil {
					t.Fatal(err)
				}
				wire := &http.Transport{TLSClientConfig: &tls.Config{ServerName: approved.Endpoint.Hostname, RootCAs: visitorfixture.Roots(t, *certificate)},
					MaxConnsPerHost: 1, DialContext: func(call context.Context, _, _ string) (net.Conn, error) {
						header := privateHeader(t, bound.prepared.connectionRef(control.setup.PublisherConnections[1]))
						header.PublicService.DestinationPort = 443
						unregister, err := result.peers[1].RegisterServiceCapacity(call, header, func(context.Context) error { return nil })
						if err != nil {
							return nil, err
						}
						stream, err := result.peers[1].OpenServiceForwardingStream(call, header)
						if err != nil {
							unregister()
							return nil, err
						}
						visitor := &observationVisitor{Conn: stream, unregister: unregister}
						if err = stream.SetDeadline(time.Now().Add(5 * time.Second)); err == nil {
							_, err = stream.Write(publicSourceMetadata(t, bound.prepared, header))
						}
						if err != nil {
							_ = visitor.Close()
							return nil, err
						}
						return visitor, nil
					}}
				client = &http.Client{Transport: wire, Timeout: 5 * time.Second}
				result.client = client
				return result
			}
			first, second := start(), start()
			if err := first.peers[0].Close(); err != nil {
				t.Fatal(err)
			}
			claimedAwait(t, first.lost)
			labels := func(id string) map[string]string {
				return map[string]string{"tnl_service_id": id, "tnl_service_protocol": "http"}
			}
			lostLabels := labels(first.id)
			lostLabels["tnl_event"] = "unexpected_close"
			if observationMetricCount(t, metrics, "tnl_publisher_connection_events_total", lostLabels) != 1 {
				t.Fatal("production slot loss did not create exactly one unexpected-close observation")
			}
			request := func(r run) {
				t.Helper()
				response, err := r.client.Get("https://service.worktree.member.example.test/recovered")
				if err != nil {
					t.Fatal("registered HTTP visitor did not reach its target", err)
				}
				_, readErr := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent {
					t.Fatal("registered HTTP response changed", response.StatusCode, readErr, closeErr)
				}
			}
			request(second)
			if observationMetricCount(t, metrics, "tnl_publisher_recovery_duration_seconds", labels(first.id)) != 0 ||
				observationMetricCount(t, metrics, "tnl_publisher_recovery_duration_seconds", labels(second.id)) != 0 {
				t.Fatal("another run's 204 closed the lost run's recovery episode")
			}
			request(first)
			request(first)
			if observationMetricCount(t, metrics, "tnl_publisher_recovery_duration_seconds", labels(first.id)) != 1 ||
				observationMetricCount(t, metrics, "tnl_publisher_recovery_duration_seconds", labels(second.id)) != 0 {
				t.Fatal("two registered own-run responses did not close exactly one recovery episode")
			}
		})
	}
}

func TestServiceRecoveryObservationRestorationTruncatedHTTPKeepsRequestOwner(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			ctx, recorder := observationPublisher(t)
			identity := observability.Identity{TeamID: "team", PublisherIdentityID: "publisher", ServiceID: "svc_AAAAAAAAAAAAAAAAAAAAAA"}
			ctx = observability.ReplaceIdentity(observationHTTPContext(ctx), identity)
			ctx, finish := observability.Start(ctx, "fixture.truncated_response")
			defer finish(nil)
			traceID := trace.SpanContextFromContext(ctx).TraceID()
			checked := make(chan struct{}, 1)
			summaries := make(chan inspection.Summary, 1)
			client, _, _, token, stop := observationHTTPFixture(t, ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n")
				if err := buffered.Flush(); err != nil {
					t.Error(err)
				}
			}), h2, false, func(f *HTTP) {
				f.InspectionMode = inspection.SummaryMode
				f.ObserveSummary = func(summary inspection.Summary) { summaries <- summary }
				f.AdmitRequest = func(r *http.Request) error {
					server, ok := r.Context().Value(http.ServerContextKey).(*http.Server)
					address, addressOK := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
					if !ok || server == nil || !addressOK || address.String() != "pipe" ||
						observability.IdentityFromContext(r.Context()) != identity || observability.FromContext(r.Context()) != recorder.Owner ||
						!traceID.IsValid() || trace.SpanContextFromContext(r.Context()).TraceID() != traceID {
						t.Error("real truncated response lost net/http context, publisher identity, metrics, or trace owner")
					}
					checked <- struct{}{}
					return nil
				}
			})
			request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/truncated?private=query", nil)
			request.Header.Set("Tnl-Visitor-Token", token.Reveal())
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("visitor did not receive target headers", err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if response.ProtoMajor != wantProtocol || response.StatusCode != http.StatusOK || string(body) != "part" ||
				readErr == nil || errors.Is(readErr, context.DeadlineExceeded) {
				t.Fatal("real truncated response completed or stalled", response.Proto, response.Status, string(body), readErr)
			}
			claimedAwait(t, checked)
			summary := claimedAwait(t, summaries)
			stop()
			if summary.Status != 200 || summary.Result != inspection.ResultError || summary.Origin != "local_service" || summary.Path != "/truncated" {
				t.Fatal("real truncated response lost its error summary", summary)
			}
			if observationMetricCount(t, recorder.Owner, "tnl_publisher_http_request_duration_seconds", map[string]string{
				"tnl_outcome": "error", "tnl_response_origin": "local_service", "http_response_status_code": "200", "tnl_service_protocol": "http",
			}) != 1 || observationMetricCount(t, recorder.Owner, "tnl_publisher_http_request_duration_seconds", nil) != 1 {
				t.Fatal("real local-service HTTP 200 body error was not recorded exactly once")
			}
			requests := recorder.Attempts(t, "publisher.http")
			if len(requests) != 1 {
				t.Fatal("truncated response exported duplicate HTTP lifetimes", len(requests))
			}
		})
	}
}
