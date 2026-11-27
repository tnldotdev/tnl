package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"go.opentelemetry.io/otel/trace"
)

// only log validated ids and facts from the forwarding owners. never format a
// header, IP address, PROXY proof, TLS record or underlying error as text.
func forwardingLogFields(ctx context.Context, cause error) (context.Context, []slog.Attr) {
	var fields []slog.Attr
	addID := func(key, value, prefix string) {
		if opaqueid.Valid(value, prefix) {
			fields = append(fields, slog.String(key, value))
		}
	}
	addRelay := func(prefix, name, run, publisher string) {
		addID(prefix+"relay_run_id", run, opaqueid.RelayRunPrefix)
		addID(prefix+"publisher_connection_id", publisher, opaqueid.PublisherConnectionPrefix)
		if safeRelayName(name) {
			fields = append(fields, slog.String(prefix+"relay_id", name))
		}
	}
	addCause := func(prefix string, err error) {
		var stream *quic.StreamError
		if errors.As(err, &stream) {
			fields = append(fields, slog.Uint64(prefix+"quic_stream_code", uint64(stream.ErrorCode)), slog.Bool(prefix+"quic_stream_remote", stream.Remote))
		}
		var rejected *tunnel.ProtocolError
		if errors.As(err, &rejected) {
			fields = append(fields, slog.String(prefix+"protocol_code", string(rejected.Code)))
		}
	}
	var service, run, visitor, phase string
	var number uint64
	var span trace.SpanContext
	var operation, cleanup error
	var lastProgress, trigger string
	var v *ingress.VisitorError
	var r *relay.ForwardingError
	switch {
	case errors.As(cause, &v):
		service, run, visitor, number = v.ForwardingScope()
		phase, operation, cleanup, span = v.ForwardingPhase(), v.ForwardingOperation(), v.ForwardingCleanup(), v.SpanContext()
		lastProgress, trigger = v.CloseProgress()
		addID("ingress_run_id", v.IngressRunID(), opaqueid.IngressRunPrefix)
		sent, returned := v.Forwarded()
		fields = append(fields, slog.Int64("visitor_bytes_to_relay", sent), slog.Int64("bytes_to_visitor", returned))
		if id := v.ClientHelloID(); id != [16]byte{} {
			fields = append(fields, slog.String("client_hello_id", hex.EncodeToString(id[:])))
		}
		attempts := v.RelayAttempts()
		fields = append(fields, slog.Int("relay_attempts", len(attempts)))
		for i, a := range attempts {
			// the last attempted relay has the same field names as its own log.
			prefix := ""
			if i+1 < len(attempts) {
				prefix = "attempt_" + strconv.Itoa(i+1) + "_"
			}
			addRelay(prefix, a.RelayID, a.RelayRunID, a.PublisherConnectionID)
			fields = append(fields, slog.Int(prefix+"connection_slot", a.Slot), slog.String(prefix+"step", a.Step),
				slog.Int64(prefix+"connection_assignment_revision", a.AssignmentRevision),
				slog.String(prefix+"attempt_result", operatorlog.CauseClass(a.Err)), slog.Int64(prefix+"attempt_ms", a.Elapsed.Milliseconds()),
				slog.Int64(prefix+"budget_ms", a.Budget.Milliseconds()), slog.Bool(prefix+"visitor_committed", a.Committed))
			addCause(prefix, a.Err)
		}
	case errors.As(cause, &r):
		service, run, visitor, number = r.ForwardingScope()
		phase, operation, cleanup, span = r.ForwardingPhase(), r.ForwardingOperation(), r.ForwardingCleanup(), r.SpanContext()
		lastProgress, trigger = r.CloseProgress()
		name, relayRun, publisher := r.RelayScope()
		addRelay("", name, relayRun, publisher)
		addID("ingress_run_id", r.IngressRunID(), opaqueid.IngressRunPrefix)
		step, elapsed := r.ForwardingStep()
		slot, revision := r.Assignment()
		sent, returned := r.Forwarded()
		fields = append(fields, slog.String("step", step), slog.Int64("elapsed_ms", elapsed.Milliseconds()),
			slog.Int("connection_slot", int(slot)), slog.Uint64("connection_assignment_revision", revision),
			slog.Int64("bytes_to_publisher", sent), slog.Int64("bytes_to_ingress", returned))
		if ack := r.AcceptedAt(); ack > 0 {
			fields = append(fields, slog.Int64("ack_ingress_ms", ack.Milliseconds()))
		}
		addCause("", operation)
		var opening *tunnel.OpeningError
		if errors.As(operation, &opening) {
			fields = append(fields, slog.String("stream_step", opening.Step))
		}
		var copyStep interface {
			ForwardingCopyOperation() (string, string, string)
		}
		if errors.As(r.ForwardingCopyResult(), &copyStep) {
			op, end, dir := copyStep.ForwardingCopyOperation()
			if validCopyOperationLabels(op, end, dir) {
				fields = append(fields, slog.String("copy_op", op), slog.String("copy_endpoint", end), slog.String("copy_direction", dir))
			}
		}
	default:
		return ctx, nil
	}
	if span.IsValid() {
		ctx = trace.ContextWithSpanContext(ctx, span)
	}
	addID("service_id", service, opaqueid.ServicePrefix)
	addID("service_run_id", run, opaqueid.ServiceRunPrefix)
	addID("visitor_connection_id", visitor, opaqueid.VisitorConnectionPrefix)
	if number != 0 {
		fields = append(fields, slog.Uint64("service_run_number", number))
	}
	fields = append(fields, slog.String("phase", phase), slog.String("operation_result", operatorlog.CauseClass(operation)), slog.String("cleanup_result", operatorlog.CauseClass(cleanup)))
	if lastProgress != "" {
		fields = append(fields, slog.String("last_progress", lastProgress), slog.String("close_trigger", trigger))
	}
	return ctx, fields
}

func logForwardingClose(ctx context.Context, kind observability.DiagnosticKind, budget *operatorlog.Budget, diagnostic error) {
	suppressed, allowed := budget.Take(ctx, kind)
	if !allowed {
		return
	}
	ctx, fields := forwardingLogFields(ctx, diagnostic)
	operatorlog.Line(ctx, string(kind), append(fields, slog.Int64("suppressed", suppressed))...)
}

func safeRelayName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
