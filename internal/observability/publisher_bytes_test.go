package observability

import (
	"bufio"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/trace"
)

// keep socket and payload-copy costs out of the per-chunk metric measurement.
// the counter and its warmed aggregation series are the real local SDK owner.
type publisherByteConn struct {
	net.Conn
}

func (*publisherByteConn) Read(p []byte) (int, error)  { return len(p), nil }
func (*publisherByteConn) Write(p []byte) (int, error) { return len(p), nil }

func publisherByteContext(ctx context.Context) context.Context {
	ctx = ReplaceIdentity(ctx, Identity{
		TeamID: "team", PublisherGroupID: "group", PublisherIdentityID: "publisher",
		DeploymentID: "deployment", ReplicaKey: "replica", ServiceID: "service",
	})
	return WithFields(ctx, Fields{Component: "publisher", ServiceProtocol: ProtocolPostgres, AccessPath: "connector", Exposure: "private"})
}

func TestPublisherConnBytesKeepScopeDirectionAndAllowlist(t *testing.T) {
	owner := New("publisher")
	defer owner.Shutdown(context.Background())
	ctx := publisherByteContext(WithMetrics(t.Context(), owner))
	other := ReplaceIdentity(ctx, Identity{TeamID: "other-team", PublicURLID: "url"})
	other = WithFields(other, Fields{
		Component: "publisher", ServiceProtocol: ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public",
		Transport: TransportQUIC, TLSLeg: "target", Direction: "visitor_to_relay", ResponseOrigin: "local_service",
	})
	want := map[string]map[string]string{
		"service": {
			"tnl_team_id": "team", "tnl_publisher_group_id": "group", "tnl_publisher_identity_id": "publisher",
			"tnl_deployment_id": "deployment", "tnl_replica_key": "replica", "tnl_service_id": "service", "tnl_service_kind": "service",
			"tnl_component": "publisher", "tnl_service_protocol": "postgres", "tnl_access_path": "connector", "tnl_exposure": "private",
		},
		"url": {
			"tnl_team_id": "other-team", "tnl_public_url_id": "url", "tnl_service_kind": "public_url",
			"tnl_component": "publisher", "tnl_service_protocol": "http", "tnl_access_path": "public_endpoint", "tnl_exposure": "public",
		},
	}
	for _, scoped := range []context.Context{ctx, other} {
		conn, finish := PublisherStream(scoped, &publisherByteConn{})
		_, _ = conn.Read(make([]byte, 3))
		_, _ = conn.Write(make([]byte, 5))
		finish(nil)
	}
	points := publisherBytePoints(t, owner)
	if len(points) != 4 {
		t.Fatalf("byte series=%d want=4", len(points))
	}
	for _, point := range points {
		labels := map[string]string{}
		for _, label := range point.Label {
			labels[label.GetName()] = label.GetValue()
		}
		scope := labels["tnl_service_id"]
		if scope == "" {
			scope = labels["tnl_public_url_id"]
		}
		expected := maps.Clone(want[scope])
		if expected == nil {
			t.Fatalf("unexpected scope: %v", labels)
		}
		expected["tnl_direction"] = labels["tnl_direction"]
		bytes := map[string]float64{"target_to_visitor": 3, "visitor_to_target": 5}[labels["tnl_direction"]]
		if !maps.Equal(labels, expected) || bytes == 0 || point.GetCounter().GetValue() != bytes {
			t.Fatalf("byte scope/direction changed: labels=%v value=%v", labels, point.GetCounter().GetValue())
		}
	}
}

type publisherByteResultConn struct {
	net.Conn
	n   int
	err error
}

func (c publisherByteResultConn) Read([]byte) (int, error)  { return c.n, c.err }
func (c publisherByteResultConn) Write([]byte) (int, error) { return c.n, c.err }

func TestPublisherConnBytesPreservePartialResultsAndErrors(t *testing.T) {
	for _, operation := range []string{"read", "write"} {
		for _, result := range []struct {
			name string
			n    int
			err  error
		}{
			{"empty", 0, nil}, {"empty-error", 0, net.ErrClosed}, {"empty-eof", 0, io.EOF},
			{"partial", 3, nil}, {"partial-error", 3, net.ErrClosed}, {"partial-eof", 3, io.EOF},
		} {
			t.Run(operation+"/"+result.name, func(t *testing.T) {
				owner := New("publisher")
				defer owner.Shutdown(context.Background())
				o := &httpObservation{origin: "local_service", forwarding: true}
				ctx := context.WithValue(WithMetrics(t.Context(), owner), httpObservationKey{}, o)
				conn := newPublisherConn(ctx, publisherByteResultConn{n: result.n, err: result.err}, "target_to_visitor", "visitor_to_target")
				transfer := conn.Read
				if operation == "write" {
					transfer = conn.Write
				}
				if n, err := transfer(make([]byte, 8)); n != result.n || err != result.err {
					t.Fatalf("underlying result changed: n=%d err=%v", n, err)
				}
				wantError := result.err
				if operation == "read" && errors.Is(result.err, io.EOF) {
					wantError = nil
				}
				if o.err != wantError {
					t.Fatalf("HTTP error observation=%v want=%v", o.err, wantError)
				}
				points := publisherBytePoints(t, owner)
				if result.n == 0 {
					if len(points) != 0 {
						t.Fatal("empty transfer created a byte series")
					}
				} else if len(points) != 1 || points[0].GetCounter().GetValue() != float64(result.n) {
					t.Fatal("partial successful bytes were lost or overcounted", points)
				}
			})
		}
	}
}

type publisherByteHijacker struct {
	*httptest.ResponseRecorder
	conn net.Conn
	rw   *bufio.ReadWriter
}

func (w publisherByteHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.rw, nil
}

func TestPublisherConnBytesHijackChecksCurrentHTTPGates(t *testing.T) {
	owner := New("publisher")
	defer owner.Shutdown(context.Background())
	rw := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(io.Discard))
	writer := publisherByteHijacker{httptest.NewRecorder(), &publisherByteConn{}, rw}
	request := httptest.NewRequest("GET", "/", nil).WithContext(publisherByteContext(WithMetrics(t.Context(), owner)))
	PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil || buffered != rw {
			t.Fatalf("hijack changed the buffered connection: %v", err)
		}
		if conn.(*publisherConn).ctx != r.Context() {
			t.Fatal("hijack replaced the observation context")
		}
		_, _ = buffered.WriteString("upgrade headers")
		_, _ = conn.Read(make([]byte, 3))
		_, _ = conn.Write(make([]byte, 4))
		if len(publisherBytePoints(t, owner)) != 0 {
			t.Fatal("publisher-owned bytes counted before forwarding")
		}
		PublisherHTTPForward(r.Context())
		_, _ = conn.Read(make([]byte, 5))
		_, _ = conn.Write(make([]byte, 6))
		PublisherHTTPResponse(r.Context())
		_, _ = conn.Read(make([]byte, 7))
		_, _ = conn.Write(make([]byte, 8))
		PublisherHTTPError(r.Context(), net.ErrClosed)
		_, _ = conn.Read(make([]byte, 9)) // forwarding stays true; origin changes
		_, _ = conn.Write(make([]byte, 10))
		PublisherHTTPResponse(r.Context())
		_, _ = conn.Write(make([]byte, 11))
	})).ServeHTTP(writer, request)
	for direction, want := range map[string]float64{"visitor_to_target": 21, "target_to_visitor": 19} {
		if got := dataMetric(t, owner, "tnl_publisher_forwarded_bytes_total", map[string]string{"tnl_direction": direction}); got != want {
			t.Fatalf("%s bytes=%v want=%v", direction, got, want)
		}
	}
}

func TestPublisherConnBytesRecoveryRemainsLiveAndRunLocal(t *testing.T) {
	owner := New("publisher")
	defer owner.Shutdown(context.Background())
	ctx := WithPublisherRecovery(publisherByteContext(WithMetrics(t.Context(), owner)))
	conn, finish := PublisherStream(ctx, &publisherByteConn{})
	defer finish(nil)
	other, finishOther := PublisherStream(WithPublisherRecovery(ctx), &publisherByteConn{})
	defer finishOther(nil)
	for episode := range 2 {
		// the connection already exists when a new loss starts this episode.
		lost := PublisherConnectionLifetime(ctx, "quic", 0)
		lost(net.ErrClosed, false)
		_, _ = other.Read(make([]byte, 3))
		_, _ = conn.Write(make([]byte, 5))
		_, _ = conn.Read(nil)
		if got := dataMetric(t, owner, "tnl_publisher_recovery_duration_seconds", nil); got != float64(episode) {
			t.Fatal("another run, visitor bytes, or an empty read closed recovery", got)
		}
		_, _ = conn.Read(make([]byte, 7))
		_, _ = conn.Read(make([]byte, 11))
		if got := dataMetric(t, owner, "tnl_publisher_recovery_duration_seconds", nil); got != float64(episode+1) {
			t.Fatal("target progress did not close exactly one recovery episode", got)
		}
	}
}

func TestPublisherConnBytesConcurrentDuplex(t *testing.T) {
	owner := New("publisher")
	defer owner.Shutdown(context.Background())
	ctx := publisherByteContext(WithMetrics(t.Context(), owner))
	ctx = context.WithValue(ctx, httpObservationKey{}, &httpObservation{origin: "local_service", forwarding: true})
	conn, finish := PublisherStream(ctx, &publisherByteConn{})
	defer finish(nil)
	var workers sync.WaitGroup
	for _, transfer := range []func([]byte) (int, error){conn.Read, conn.Write} {
		workers.Go(func() {
			chunk := make([]byte, 32)
			for range 1000 {
				if n, err := transfer(chunk); n != len(chunk) || err != nil {
					t.Errorf("duplex transfer: n=%d err=%v", n, err)
					return
				}
			}
		})
	}
	workers.Wait()
	for _, direction := range []string{"visitor_to_target", "target_to_visitor"} {
		if got := dataMetric(t, owner, "tnl_publisher_forwarded_bytes_total", map[string]string{"tnl_direction": direction}); got != 32_000 {
			t.Fatalf("duplex %s bytes=%v", direction, got)
		}
	}
}

func TestPublisherConnBytesDisabledAndNoOwnerDoNotAllocate(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-owner", true: "disabled"}[disabled], func(t *testing.T) {
			ctx := publisherByteContext(t.Context())
			if disabled {
				owner, err := newOwner("publisher", Config{Disabled: true})
				if err != nil {
					t.Fatal(err)
				}
				defer owner.Shutdown(context.Background())
				ctx = WithMetrics(ctx, owner)
				defer func() {
					if len(publisherBytePoints(t, owner)) != 0 {
						t.Fatal("disabled owner recorded bytes")
					}
				}()
			}
			conn, finish := PublisherStream(ctx, &publisherByteConn{})
			defer finish(nil)
			chunk := make([]byte, 32)
			if got := testing.AllocsPerRun(100, func() { _, _ = conn.Read(chunk); _, _ = conn.Write(chunk) }); got != 0 {
				t.Fatalf("per-chunk allocations=%v", got)
			}
		})
	}
}

func TestPublisherConnBytesRetainExemplarContext(t *testing.T) {
	owner := New("publisher")
	defer owner.Shutdown(context.Background())
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled})
	ctx, cancel := context.WithCancel(trace.ContextWithSpanContext(publisherByteContext(WithMetrics(t.Context(), owner)), sc))
	conn := newPublisherConn(ctx, &publisherByteConn{}, "target_to_visitor", "visitor_to_target")
	cancel()
	_, _ = conn.Read(make([]byte, 3))
	points := publisherBytePoints(t, owner)
	if conn.ctx != ctx || conn.ctx.Err() != context.Canceled || len(points) != 1 {
		t.Fatal("byte recording lost the original context or canceled-context bytes")
	}
	exemplar := points[0].GetCounter().GetExemplar()
	labels := map[string]string{}
	for _, label := range exemplar.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}
	if labels["trace_id"] != sc.TraceID().String() || labels["span_id"] != sc.SpanID().String() {
		t.Fatalf("counter exemplar lost original correlation: %v", labels)
	}
}

func publisherBytePoints(t *testing.T, owner *Metrics) []*dto.Metric {
	t.Helper()
	families, err := owner.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_publisher_forwarded_bytes_total" {
			return family.Metric
		}
	}
	return nil
}

func BenchmarkPublisherConnBytes(b *testing.B) {
	for _, mode := range []string{"metrics", "disabled", "no-owner"} {
		for _, operation := range []string{"read", "write"} {
			b.Run(mode+"/"+operation, func(b *testing.B) {
				ctx := publisherByteContext(b.Context())
				var owner *Metrics
				switch mode {
				case "metrics":
					owner = New("publisher")
				case "disabled":
					var err error
					owner, err = newOwner("publisher", Config{Disabled: true})
					if err != nil {
						b.Fatal(err)
					}
				}
				if owner != nil {
					defer owner.Shutdown(context.Background())
					ctx = WithMetrics(ctx, owner)
				}
				conn, finish := PublisherStream(ctx, &publisherByteConn{})
				defer finish(nil)
				transfer := conn.Read
				if operation == "write" {
					transfer = conn.Write
				}
				chunk := make([]byte, 32)
				if _, err := transfer(chunk); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if n, err := transfer(chunk); n != len(chunk) || err != nil {
						b.Fatalf("transfer: n=%d err=%v", n, err)
					}
				}
				b.StopTimer()
				if mode == "metrics" {
					families, err := owner.Gather()
					if err != nil {
						b.Fatal(err)
					}
					var total float64
					for _, family := range families {
						if family.GetName() == "tnl_publisher_forwarded_bytes_total" {
							for _, point := range family.Metric {
								total += point.GetCounter().GetValue()
							}
						}
					}
					if want := float64(b.N+1) * float64(len(chunk)); total != want {
						b.Fatalf("counter=%v want=%v", total, want)
					}
				}
			})
		}
	}
}
