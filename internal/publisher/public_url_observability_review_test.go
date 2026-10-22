package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"go.opentelemetry.io/otel/trace"
)

func TestPublicURLTruncatedTargetBodyAbortsVisitorResponse(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				connection, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				// omit the final chunk: only an aborted visitor response preserves
				// this upstream failure when the proxy reframes the response body.
				_, _ = buffered.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\npart\r\n")
				if err := buffered.Flush(); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			metrics := observability.New("publisher")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			owner := observability.ReplaceIdentity(observability.WithMetrics(t.Context(), metrics), observability.Identity{TeamID: "team", PublisherIdentityID: "publisher"})
			owner, finish := observability.Start(owner, "fixture.public_url")
			defer finish(nil)
			traceID := trace.SpanContextFromContext(owner).TraceID()
			checked := make(chan struct{}, 1)
			summaries := make(chan inspection.Summary, 1)
			route, err := newTestPublicURLServer(PublicURLServerConfig{Context: owner, Hostname: "route.example", PublicURLID: "url-truncated", Target: upstream.URL,
				ObserveSummary: func(summary inspection.Summary) { summaries <- summary },
				Certificate:    publicURLTestCertificate(t, "route.example"), AdmitRequest: func(r *http.Request) error {
					if r.Context().Value(http.ServerContextKey) == nil || r.Context().Value(http.LocalAddrContextKey) == nil {
						t.Error("visitor scope discarded net/http server context")
					}
					id := observability.IdentityFromContext(r.Context())
					if id.TeamID != "team" || id.PublicURLID != "url-truncated" || observability.FromContext(r.Context()) != metrics || trace.SpanContextFromContext(r.Context()).TraceID() != traceID {
						t.Error("request lost its publisher ownership or visitor trace")
					}
					checked <- struct{}{}
					return nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = route.Close() })
			if err := route.Start(); err != nil {
				t.Fatal(err)
			}
			response, err := singleConnectionRouteClient(t, route, h2).Get("https://route.example/truncated")
			if err != nil {
				t.Fatal("visitor did not receive the streamed response headers", err)
			}
			defer response.Body.Close()
			wantProtocol := 1
			if h2 {
				wantProtocol = 2
			}
			if response.ProtoMajor != wantProtocol || response.StatusCode != http.StatusOK {
				t.Fatal("test did not use the intended successful HTTP response", response.ProtoMajor, response.Status)
			}
			body, readErr := io.ReadAll(response.Body)
			if readErr == nil || errors.Is(readErr, context.DeadlineExceeded) {
				t.Fatalf("truncated target body completed cleanly or stalled: body=%q err=%v", body, readErr)
			}
			awaitPublisherTest(t, checked)
			summary := awaitPublisherTest(t, summaries)
			if summary.Status != 200 || summary.Result != inspection.ResultError || summary.Origin != "local_service" || summary.Path != "/truncated" {
				t.Fatalf("truncated response inspection = %+v", summary)
			}
			families, err := metrics.Gather()
			if err != nil {
				t.Fatal(err)
			}
			var failed uint64
			for _, family := range families {
				if family.GetName() != "tnl_publisher_http_request_duration_seconds" {
					continue
				}
				for _, point := range family.Metric {
					labels := map[string]string{}
					for _, label := range point.Label {
						labels[label.GetName()] = label.GetValue()
					}
					if labels["tnl_outcome"] == "error" && labels["tnl_response_origin"] == "local_service" && labels["http_response_status_code"] == "200" && labels["tnl_service_protocol"] == "http" {
						failed += point.GetHistogram().GetSampleCount()
					}
				}
			}
			if failed != 1 {
				t.Fatal("truncated HTTP response was recorded as a clean success", failed)
			}
		})
	}
}

func reviewPublisherMetric(t *testing.T, metrics *observability.Metrics, familyName, publicURLID, event string) uint64 {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, point := range family.Metric {
			labels := map[string]string{}
			for _, label := range point.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["tnl_public_url_id"] != publicURLID || event != "" && labels["tnl_event"] != event {
				continue
			}
			if labels["tnl_service_protocol"] != "http" {
				t.Fatal("public publisher metric lost its protocol", familyName, labels)
			}
			if point.Histogram != nil {
				count += point.GetHistogram().GetSampleCount()
			} else {
				count += uint64(point.GetCounter().GetValue())
			}
		}
	}
	return count
}

func TestPublicURLManagerRecoveryReachesRegisteredHTTPVisitorsAndStaysRunLocal(t *testing.T) {
	for _, kind := range []string{"quic", "tls-tcp"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			metrics := observability.New("publisher")
			t.Cleanup(func() { _ = metrics.Shutdown(context.Background()) })
			ctx = observability.WithMetrics(ctx, metrics)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			defer target.Close()
			type run struct {
				urlID   string
				peers   [2]*relay.PublisherConnection
				reports chan error
				client  *http.Client
			}
			start := func(label string) run {
				t.Helper()
				control := newCertificateTestControl(t, "route.example", publicURLCertificateTestPlan())
				control.setup.PublicUrl.Id += label
				control.setup.PublishRun.Id += label
				control.setup.PublishRun.PublicUrlId = control.setup.PublicUrl.Id
				runOwner := observability.NarrowIdentity(ctx, observability.Identity{PublicURLID: control.setup.PublicUrl.Id})
				route, err := newTestPublicURLServer(PublicURLServerConfig{Context: runOwner, Hostname: "route.example", Target: target.URL, PublicURLID: control.setup.PublicUrl.Id,
					PublishRunID: control.setup.PublishRun.Id, PublishRunNumber: 1, Certificate: publicURLTestCertificate(t, "route.example"), PromoteVisitor: func(context.Context, Visitor) error { return nil }})
				if err != nil {
					t.Fatal(err)
				}
				if err := route.Start(); err != nil {
					t.Fatal(err)
				}
				connector, accepted, _ := drainTestConnections(t, ctx, control, kind)
				quic, tcp := connector, connector
				disabled := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
					return nil, errors.New("fixture transport disabled")
				})
				if kind == "quic" {
					tcp = disabled
				} else {
					quic = disabled
				}
				reports := make(chan error, 4)
				manager, err := newPublisherConnectionManager(runOwner, publisherConnectionManagerConfig{QUICConnector: quic, TCPConnector: tcp, FallbackDelay: time.Hour, ReconnectDelay: time.Second,
					Report: func(err error) { reports <- err }}, route, control.setup.PublishRun.Id, control.setup.PublicUrl.Id, 1)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { manager.Close(); _ = route.Close() })
				if err := manager.Update(control.setup.PublisherConnections); err != nil {
					t.Fatal(err)
				}
				if err := manager.WaitReady(ctx, 2); err != nil {
					t.Fatal(err)
				}
				result := run{urlID: control.setup.PublicUrl.Id, reports: reports}
				for range 2 {
					peer := awaitPublisherTest(t, accepted)
					if peer.err != nil {
						t.Fatal(peer.err)
					}
					result.peers[peer.connection.Ref().ConnectionSlot] = peer.connection
				}
				transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootsForCertificate(t, *route.certificate.Load()), ServerName: "route.example"},
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						stream, err := result.peers[1].OpenVisitor(ctx, "review-visitor")
						if err != nil {
							return nil, err
						}
						metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
						if err == nil {
							_, err = stream.Write(metadata)
						}
						if err != nil {
							_ = stream.Close()
						}
						return stream, err
					}}
				t.Cleanup(transport.CloseIdleConnections)
				result.client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
				return result
			}
			first, second := start("a"), start("b")
			if err := first.peers[0].Close(); err != nil {
				t.Fatal(err)
			}
			awaitPublisherTest(t, first.reports)
			if reviewPublisherMetric(t, metrics, "tnl_publisher_connection_events_total", first.urlID, "unexpected_close") != 1 {
				t.Fatal("manager did not observe exactly one unexpected connection loss")
			}
			request := func(r run) {
				t.Helper()
				response, err := r.client.Get("https://route.example/recovered")
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 204 {
					t.Fatal("registered publisher stream did not reach its HTTP target", err, response.Status)
				}
			}
			request(second)
			if reviewPublisherMetric(t, metrics, "tnl_publisher_recovery_duration_seconds", first.urlID, "") != 0 || reviewPublisherMetric(t, metrics, "tnl_publisher_recovery_duration_seconds", second.urlID, "") != 0 {
				t.Fatal("a different run's response closed the recovery episode")
			}
			request(first)
			request(first)
			if reviewPublisherMetric(t, metrics, "tnl_publisher_recovery_duration_seconds", first.urlID, "") != 1 || reviewPublisherMetric(t, metrics, "tnl_publisher_recovery_duration_seconds", second.urlID, "") != 0 {
				t.Fatal("HTTP response did not close exactly one run-local recovery episode")
			}
		})
	}
}
