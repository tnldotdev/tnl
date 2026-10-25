package observability

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/region"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// publisherData instruments describe application boundaries, not SQL queries or
// customer payloads. they share the process SDK's attribute filter and budget.
type publisherData struct {
	relayProbes                   metric.Float64Histogram
	recovery                      metric.Float64Histogram
	candidates                    metric.Float64Histogram
	httpDuration, httpHeaders     metric.Float64Histogram
	httpActive, streamsActive     metric.Int64UpDownCounter
	bytes, streams, authorization metric.Int64Counter
	tls                           metric.Int64Counter
	connections                   metric.Int64UpDownCounter
	connectionEvents              metric.Int64Counter
}

func (m *Metrics) initPublisherData() {
	keys := []MetricKey{Component, ServiceProtocol, AccessPath, Exposure}
	m.publisherData.relayProbes = newHistogram(m.meter, "tnl_publisher_relay_probe_duration_seconds", "Bounded TLS nonce round trip to an eligible relay; includes connection setup and response, not visitor latency.", DurationBucketsSeconds(), append(append([]MetricKey{}, keys...), RelayRegion, OutcomeKey)...).instrument
	m.publisherData.candidates = newHistogram(m.meter, "tnl_publisher_transport_candidate_duration_seconds", "Publisher transport candidate connection and authentication duration; count includes both raced candidates, not only the winner.", DurationBucketsSeconds(), append(append([]MetricKey{}, keys...), Transport, OutcomeKey)...).instrument
	m.publisherData.recovery = newHistogram(m.meter, "tnl_publisher_recovery_duration_seconds", "Publisher-local time from unexpected connection loss until an observed target response (HTTP headers or stream bytes); includes waiting for traffic, not visitor delivery or outage duration.", DurationBucketsSeconds(), keys...).instrument
	httpKeys := append(append([]MetricKey{}, keys...), HTTPMethod, HTTPStatus, ResponseOrigin, OutcomeKey)
	m.publisherData.httpDuration = newHistogram(m.meter, "tnl_publisher_http_request_duration_seconds", "HTTP handler lifetime including streaming and upgrades; no request paths or query parsing.", DurationBucketsSeconds(), httpKeys...).instrument
	m.publisherData.httpHeaders = newHistogram(m.meter, "tnl_publisher_http_response_headers_duration_seconds", "Time until final response headers, excluding informational responses.", DurationBucketsSeconds(), httpKeys...).instrument
	declare := func(name, description string, dimensions ...MetricKey) metric.Int64Counter {
		describe(m.meter, name, description, KindCounter, nil, dimensions...)
		instrument, _ := m.meter.Int64Counter(name, metric.WithDescription(description))
		return instrument
	}
	describe(m.meter, "tnl_publisher_http_requests_active", "HTTP handlers currently executing, including streaming and upgrades.", KindGauge, nil, keys...)
	m.publisherData.httpActive, _ = m.meter.Int64UpDownCounter("tnl_publisher_http_requests_active")
	describe(m.meter, "tnl_publisher_visitor_streams_active", "Publisher application streams currently forwarding.", KindGauge, nil, keys...)
	m.publisherData.streamsActive, _ = m.meter.Int64UpDownCounter("tnl_publisher_visitor_streams_active")
	m.publisherData.bytes = declare("tnl_publisher_forwarded_bytes_total", "HTTP body bytes read for target forwarding or written from accepted target responses, and opaque application copies, observed incrementally; excludes tnl-authored responses, HTTP headers, native authentication and TLS framing.", append(append([]MetricKey{}, keys...), Direction)...)
	m.publisherData.streams = declare("tnl_publisher_visitor_stream_completions_total", "Application stream copies completed by outcome.", append(append([]MetricKey{}, keys...), OutcomeKey)...)
	m.publisherData.authorization = declare("tnl_publisher_authorization_decisions_total", "Authorization checks distinguish denial, allowed pending admission, admission and infrastructure failure.", append(append([]MetricKey{}, keys...), OutcomeKey, State)...)
	m.publisherData.tls = declare("tnl_publisher_tls_handshakes_total", "Completed TLS handshakes; negotiated version and resumption only on success.", append(append([]MetricKey{}, keys...), TLSLeg, TLSVersion, TLSResumed, OutcomeKey)...)
	connectionKeys := append(append([]MetricKey{}, keys...), Transport, ConnectionSlot)
	describe(m.meter, "tnl_publisher_connections_active", "Authenticated publisher connections held by this process; sum slots for local redundancy, not control readiness.", KindGauge, nil, connectionKeys...)
	m.publisherData.connections, _ = m.meter.Int64UpDownCounter("tnl_publisher_connections_active")
	m.publisherData.connectionEvents = declare("tnl_publisher_connection_events_total", "Authenticated publisher connection establishment and expected or unexpected close events.", append(connectionKeys, Event, OutcomeKey)...)
}

// PublisherRelayProbe records one bounded connection attempt, including timeouts.
func PublisherRelayProbe(ctx context.Context, value string, elapsed time.Duration, err error) {
	code, valid := region.Parse(value)
	if !valid || string(code) != value || elapsed < 0 {
		return
	}
	if m := FromContext(ctx); m != nil {
		attrs := append(publisherDataAttributes(ctx), RelayRegion.String(value), OutcomeKey.Value(ErrorOutcome(err)))
		m.publisherData.relayProbes.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attrs...))
	}
}

// PublisherTransportCandidate records each bounded candidate independently of
// the race winner. connector/client owners retain spans but not publisher metrics.
func PublisherTransportCandidate(ctx context.Context, transport string, elapsed time.Duration, err error) {
	if transport != "quic" && transport != "tls-tcp" || elapsed < 0 {
		return
	}
	if m := FromContext(ctx); m != nil {
		parsed, _ := ParseTransport(transport)
		attrs := append(publisherDataAttributes(ctx), Transport.Value(parsed), OutcomeKey.Value(ErrorOutcome(err)))
		m.publisherData.candidates.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attrs...))
	}
}

// PublisherConnectionLifetime observes authenticated connections, including
// replacements. a shutdown close remains expected even if the transport errs.
func PublisherConnectionLifetime(ctx context.Context, transport string, slot int) func(error, bool) {
	m := FromContext(ctx)
	if m == nil || (transport != "quic" && transport != "tls-tcp") || slot < 0 || slot > 1 {
		return func(error, bool) {}
	}
	parsed, _ := ParseTransport(transport)
	attrs := append(publisherDataAttributes(ctx), Transport.Value(parsed), ConnectionSlot.Int(slot))
	m.publisherData.connections.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.publisherData.connectionEvents.Add(ctx, 1, metric.WithAttributes(append(attrs, Event.Value(EventConnected), OutcomeKey.Value(Success))...))
	var once sync.Once
	return func(err error, expected bool) {
		once.Do(func() {
			m.publisherData.connections.Add(ctx, -1, metric.WithAttributes(attrs...))
			event := EventUnexpectedClose
			if expected {
				event = EventExpectedClose
				err = nil
			} else if recovery, ok := ctx.Value(publisherRecoveryKey{}).(*publisherRecovery); ok && recovery != nil {
				recovery.mu.Lock()
				if recovery.lost.IsZero() {
					recovery.lost = time.Now()
				}
				recovery.mu.Unlock()
			}
			m.publisherData.connectionEvents.Add(ctx, 1, metric.WithAttributes(append(attrs, Event.Value(event), OutcomeKey.Value(ErrorOutcome(err)))...))
		})
	}
}

type publisherRecoveryKey struct{}
type publisherRecovery struct {
	mu   sync.Mutex
	lost time.Time
}

// WithPublisherRecovery creates one service/run-local recovery observer. share
// the resulting context with its connection slots and visitor handlers only.
func WithPublisherRecovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, publisherRecoveryKey{}, &publisherRecovery{})
}

// WithPublisherRecoveryFrom shares only the run-local recovery observer. it
// preserves the receiving context's cancellation, identity, fields and spans.
// a source without an observer clears any previous run's recovery scope.
func WithPublisherRecoveryFrom(ctx, owner context.Context) context.Context {
	recovery, _ := owner.Value(publisherRecoveryKey{}).(*publisherRecovery)
	return context.WithValue(ctx, publisherRecoveryKey{}, recovery)
}

func publisherDataAttributes(ctx context.Context) []attribute.KeyValue {
	return append(identityAttributes(ctx), Attributes(ctx, Component, ServiceProtocol, AccessPath, Exposure)...)
}

// PublisherAuthorization records each authority result, including allowed checks
// still waiting for admission. errors retain their owned classification.
func PublisherAuthorization(ctx context.Context, allowed, admitted bool, err error) {
	if m := FromContext(ctx); m != nil {
		state, outcome := StateDenied, Denied
		switch {
		case err != nil && ErrorOutcome(err) == Denied:
			state, outcome = StateDenied, Denied
		case err != nil:
			state, outcome = StateFailed, ErrorOutcome(err)
		case allowed && admitted:
			state, outcome = StateAdmitted, Success
		case allowed:
			state, outcome = StatePending, Success
		}
		attrs := append(publisherDataAttributes(ctx), State.Value(state), OutcomeKey.Value(outcome))
		m.publisherData.authorization.Add(ctx, 1, metric.WithAttributes(attrs...))
		_, span := m.tracer().Start(ctx, "publisher.authorization", trace.WithAttributes(attrs...))
		span.SetAttributes(Operation.Value("publisher.authorization"))
		if err != nil {
			finishError(span, err)
		} else {
			finishSpan(span, outcome.String())
		}
		span.End()
	}
}

// PublisherTLS records negotiated facts without peer names or certificates.
func PublisherTLS(ctx context.Context, leg string, state tls.ConnectionState, err error) {
	if leg != "visitor" && leg != "target" {
		return
	}
	if leg == "target" {
		err = publisherTargetTLSError(err)
	}
	attrs := append(publisherDataAttributes(ctx), TLSLeg.String(leg), OutcomeKey.Value(ErrorOutcome(err)))
	trace.SpanFromContext(ctx).SetAttributes(TLSLeg.String(leg))
	if err == nil {
		attrs = append(attrs, TLSAttributes(state)...)
		trace.SpanFromContext(ctx).SetAttributes(TLSAttributes(state)...)
	}
	if m := FromContext(ctx); m != nil {
		m.publisherData.tls.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

type httpObservationKey struct{}
type httpObservation struct {
	mu         sync.Mutex
	origin     string
	err        error
	forwarding bool
}

// PublisherHTTPForward marks the proxy's target boundary after request admission.
// publisher-owned handlers do not contribute forwarded application body bytes.
func PublisherHTTPForward(ctx context.Context) {
	if o, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
		o.mu.Lock()
		o.forwarding = true
		o.mu.Unlock()
	}
}

func publisherApplicationBytes(ctx context.Context, direction string) bool {
	o, ok := ctx.Value(httpObservationKey{}).(*httpObservation)
	if !ok {
		return true
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if direction == "visitor_to_target" {
		return o.forwarding
	}
	return o.origin == "local_service"
}

// PublisherHTTPResponse is called only after the proxy accepts a target response.
func PublisherHTTPResponse(ctx context.Context) {
	if o, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
		o.mu.Lock()
		o.origin = "local_service"
		o.mu.Unlock()
	}
	publisherResponseObserved(ctx)
}

// PublisherHTTPUpgrade observes backend copy failures without hiding the
// ReadWriteCloser required by ReverseProxy or its optional write-half close.
// bytes are counted at the visitor socket, exactly once.
func PublisherHTTPUpgrade(response *http.Response) {
	if response.StatusCode == http.StatusSwitchingProtocols {
		if body, ok := response.Body.(io.ReadWriteCloser); ok {
			response.Body = &publisherUpgrade{ReadWriteCloser: body, ctx: response.Request.Context()}
		}
	}
}

type publisherUpgrade struct {
	io.ReadWriteCloser
	ctx context.Context
}

func (b *publisherUpgrade) Read(p []byte) (int, error) {
	n, err := b.ReadWriteCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		PublisherHTTPWriteError(b.ctx, err)
	}
	return n, err
}

func (b *publisherUpgrade) Write(p []byte) (int, error) {
	n, err := b.ReadWriteCloser.Write(p)
	PublisherHTTPWriteError(b.ctx, err)
	return n, err
}

func (b *publisherUpgrade) CloseWrite() error {
	if closer, ok := b.ReadWriteCloser.(interface{ CloseWrite() error }); ok {
		err := closer.CloseWrite()
		PublisherHTTPWriteError(b.ctx, err)
		return err
	}
	return errors.ErrUnsupported
}

func PublisherHTTPError(ctx context.Context, err error) {
	if o, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
		o.mu.Lock()
		o.err = err
		o.origin = "tnl"
		o.mu.Unlock()
	}
}

// PublisherHTTP observes the whole handler independently of inspection settings.
// no propagation headers are injected into customer requests.
func PublisherHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields, _ := r.Context().Value(fieldsKey{}).(Fields)
		if fields.ServiceProtocol != ProtocolKubernetes {
			r = r.WithContext(WithPublisherProtocol(r.Context(), "http"))
		}
		ctx, span := FromContext(r.Context()).tracer().Start(r.Context(), "publisher.http", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(publisherDataAttributes(r.Context())...))
		span.SetAttributes(Operation.Value("publisher.http"), HTTPMethod.String(httpMethod(r.Method)))
		if id, ok := ctx.Value(visitorKey{}).(string); ok {
			Visitor(ctx, id)
		}
		o := &httpObservation{origin: "tnl"}
		ctx = context.WithValue(ctx, httpObservationKey{}, o)
		r = r.WithContext(ctx)
		m := FromContext(ctx)
		attrs := publisherDataAttributes(ctx)
		if m != nil {
			m.publisherData.httpActive.Add(ctx, 1, metric.WithAttributes(attrs...))
			defer m.publisherData.httpActive.Add(ctx, -1, metric.WithAttributes(attrs...))
		}
		started := time.Now()
		writer := &publisherHTTPWriter{ResponseWriter: w, ctx: ctx}
		if r.Body != nil {
			r.Body = &publisherBody{ReadCloser: r.Body, ctx: ctx, direction: "visitor_to_target"}
		}
		defer func() {
			interrupted := recover()
			o.mu.Lock()
			origin, err := o.origin, o.err
			o.mu.Unlock()
			if ctx.Err() != nil {
				err = context.Cause(ctx)
			}
			if err == nil && interrupted != nil {
				if cause, ok := interrupted.(error); ok && origin == "local_service" && errors.Is(cause, http.ErrAbortHandler) {
					err = diagnostic.Wrap(diagnostic.TargetUnavailable, cause)
				} else {
					err = errors.New("HTTP handler interrupted")
				}
			}
			status := writer.status
			if status == 0 {
				status = http.StatusOK
			}
			outcome := ErrorOutcome(err)
			if err == nil && status >= 500 {
				outcome = Error
			} else if err == nil && status >= 400 {
				outcome = Rejected
			}
			final := append(attrs, HTTPMethod.String(httpMethod(r.Method)), ResponseOrigin.String(origin), OutcomeKey.Value(outcome))
			if status >= 100 && status <= 599 {
				final = append(final, HTTPStatus.Int(status))
			}
			finishError(span, err)
			span.SetAttributes(final...)
			if outcome != Success && outcome != Canceled {
				span.SetStatus(codes.Error, outcome.String())
			}
			span.End()
			if m != nil {
				m.publisherData.httpDuration.Record(ctx, time.Since(started).Seconds(), metric.WithAttributes(final...))
				if !writer.headers.IsZero() {
					m.publisherData.httpHeaders.Record(ctx, writer.headers.Sub(started).Seconds(), metric.WithAttributes(final...))
				}
			}
			if interrupted != nil {
				panic(interrupted)
			}
		}()
		next.ServeHTTP(writer, r)
	})
}

func publisherBytes(ctx context.Context, direction string, n int) {
	if m := FromContext(ctx); m != nil && n > 0 && publisherApplicationBytes(ctx, direction) {
		attrs := append(publisherDataAttributes(ctx), Direction.String(direction))
		m.publisherData.bytes.Add(ctx, int64(n), metric.WithAttributes(attrs...))
		if direction == "target_to_visitor" {
			publisherResponseObserved(ctx)
		}
	}
}

func publisherResponseObserved(ctx context.Context) {
	m := FromContext(ctx)
	if m == nil || !publisherApplicationBytes(ctx, "target_to_visitor") {
		return
	}
	if recovery, ok := ctx.Value(publisherRecoveryKey{}).(*publisherRecovery); ok && recovery != nil {
		recovery.mu.Lock()
		lost := recovery.lost
		recovery.lost = time.Time{}
		recovery.mu.Unlock()
		if !lost.IsZero() {
			m.publisherData.recovery.Record(ctx, time.Since(lost).Seconds(), metric.WithAttributes(publisherDataAttributes(ctx)...))
		}
	}
}

type publisherBody struct {
	io.ReadCloser
	ctx       context.Context
	direction string
}

func (b *publisherBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	publisherBytes(b.ctx, b.direction, n)
	return n, err
}

type publisherHTTPWriter struct {
	http.ResponseWriter
	ctx     context.Context
	headers time.Time
	status  int
}

func (w *publisherHTTPWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *publisherHTTPWriter) WriteHeader(status int) {
	if w.status == 0 && (status >= 200 || status == 101) {
		w.status, w.headers = status, time.Now()
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *publisherHTTPWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	publisherBytes(w.ctx, "target_to_visitor", n)
	PublisherHTTPWriteError(w.ctx, err)
	return n, err
}
func PublisherHTTPWriteError(ctx context.Context, err error) {
	if err != nil {
		if o, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok {
			o.mu.Lock()
			o.err = err
			o.mu.Unlock()
		}
	}
}
func (w *publisherHTTPWriter) Flush() {
	_ = w.FlushError()
}
func (w *publisherHTTPWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	PublisherHTTPWriteError(w.ctx, err)
	return err
}
func (w *publisherHTTPWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		PublisherHTTPError(w.ctx, err)
		return c, rw, err
	}
	// the proxy writes the upgrade response itself after hijacking.
	if w.status == 0 {
		w.status, w.headers = 101, time.Now()
	}
	return &publisherConn{Conn: c, ctx: w.ctx, readDirection: "visitor_to_target", writeDirection: "target_to_visitor"}, rw, nil
}

type publisherConn struct {
	net.Conn
	ctx                           context.Context
	readDirection, writeDirection string
}

func (c *publisherConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	publisherBytes(c.ctx, c.readDirection, n)
	if e != nil && !errors.Is(e, io.EOF) {
		PublisherHTTPWriteError(c.ctx, e)
	}
	return n, e
}
func (c *publisherConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	publisherBytes(c.ctx, c.writeDirection, n)
	PublisherHTTPWriteError(c.ctx, e)
	return n, e
}
func (c *publisherConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		err := closer.CloseWrite()
		PublisherHTTPWriteError(c.ctx, err)
		return err
	}
	return errors.ErrUnsupported
}

// PublisherStream wraps only application copy after native authentication. reads
// on the target are target-to-visitor and writes are visitor-to-target.
func PublisherStream(ctx context.Context, target net.Conn) (net.Conn, func(error)) {
	ctx, end := Start(ctx, "publisher.stream")
	m := FromContext(ctx)
	attrs := publisherDataAttributes(ctx)
	if m != nil {
		m.publisherData.streamsActive.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	var once sync.Once
	return &publisherConn{Conn: target, ctx: ctx, readDirection: "target_to_visitor", writeDirection: "visitor_to_target"}, func(err error) {
		once.Do(func() {
			if ctx.Err() != nil {
				err = context.Cause(ctx)
			}
			end(err)
			if m != nil {
				m.publisherData.streamsActive.Add(ctx, -1, metric.WithAttributes(attrs...))
				m.publisherData.streams.Add(ctx, 1, metric.WithAttributes(append(attrs, OutcomeKey.Value(ErrorOutcome(err)))...))
			}
		})
	}
}
