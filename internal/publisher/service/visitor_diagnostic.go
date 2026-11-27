package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type publicVisitorDiagnosticKey struct{}

type publicVisitorDiagnostic struct {
	header     tunnelv1.ServiceForwardingHeader
	transport  tunnel.Transport
	step       string
	started    time.Time
	tls, setup time.Duration
	cause      error
}

// a persistent outage must not turn every browser console or native publisher
// log into a copy of the visitor request stream. ordinary successes are silent.
var publicVisitorLogBudget = operatorlog.NewBudget(1, 8)
var publicHTTPLogBudget = operatorlog.NewBudget(1, 8)

// markPublicVisitor records a completed owner transition on this stream's goroutine.
func markPublicVisitor(ctx context.Context, step string) {
	if d, _ := ctx.Value(publicVisitorDiagnosticKey{}).(*publicVisitorDiagnostic); d != nil {
		d.step = step
	}
}

func (d *publicVisitorDiagnostic) finish(ctx context.Context, err error) {
	if (err == nil && d.setup < time.Second) || failure.Only(err, context.Canceled) {
		return
	}
	suppressed, allowed := publicVisitorLogBudget.Take(ctx, observability.PublisherVisitorClose)
	if !allowed {
		return
	}
	ctx = observability.ExtractWireTrace(ctx, d.header.TraceContext)
	if d.cause != nil {
		err = d.cause
	}
	fields := []slog.Attr{
		slog.String("visitor_connection_id", d.header.VisitorConnectionID),
		slog.String("service_run_id", d.header.ServiceRunID),
		slog.String("publisher_connection_id", d.header.PublisherConnectionID),
		slog.String("relay_run_id", d.header.RelayRunID),
		slog.String("ingress_run_id", d.header.PublicService.IngressRunID),
		slog.Int("connection_slot", int(d.header.ConnectionSlot)),
		slog.Uint64("connection_assignment_revision", d.header.ConnectionAssignmentRevision),
		slog.String("transport", string(d.transport)),
		slog.String("step", d.step), slog.String("result", operatorlog.CauseClass(err)),
		slog.Int64("elapsed_ms", time.Since(d.started).Milliseconds()),
		slog.Int64("suppressed", suppressed),
	}
	if d.tls != 0 {
		fields = append(fields, slog.Int64("tls_done_ms", d.tls.Milliseconds()))
	}
	if d.setup != 0 {
		fields = append(fields, slog.Int64("setup_done_ms", d.setup.Milliseconds()))
	}
	var denied *tunnel.ProtocolError
	if errors.As(err, &denied) {
		fields = append(fields, slog.String("protocol_code", string(denied.Code)))
	}
	operatorlog.Line(ctx, "publisher visitor", fields...)
}

func (d *publicVisitorDiagnostic) observeHTTP(ctx context.Context, result observability.PublisherHTTPCompletion) {
	slowHeaders := result.HeadersAfter >= time.Second || !result.HeadersStarted && result.Elapsed >= time.Second
	if !slowHeaders && result.Err == nil && result.Status < 500 {
		return
	}
	suppressed, allowed := publicHTTPLogBudget.Take(ctx, observability.PublisherHTTPAbort)
	if !allowed {
		return
	}
	progress := "request_received"
	if result.ApplicationEntered {
		progress = "application_entered"
	}
	if result.HeadersStarted {
		progress = "response_headers_started"
	}
	var ending string
	switch {
	case result.Err != nil && ctx.Err() != nil:
		ending = "request_context_ended"
	case result.Err != nil:
		ending = "request_error"
	default:
		ending = "handler_returned"
	}
	fields := []slog.Attr{slog.String("visitor_connection_id", d.header.VisitorConnectionID), slog.String("service_run_id", d.header.ServiceRunID),
		slog.String("publisher_connection_id", d.header.PublisherConnectionID), slog.Uint64("request_number", result.RequestNumber),
		slog.String("last_progress", progress), slog.String("close_trigger", ending), slog.String("result", operatorlog.CauseClass(result.Err)),
		slog.Int64("elapsed_ms", result.Elapsed.Milliseconds()), slog.Int64("suppressed", suppressed)}
	if result.HeadersStarted {
		fields = append(fields, slog.Int("status", result.Status), slog.Int64("headers_ms", result.HeadersAfter.Milliseconds()))
	}
	operatorlog.Line(ctx, "publisher http request", fields...)
}
