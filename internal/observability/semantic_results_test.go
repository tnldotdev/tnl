package observability

import (
	"context"
	"reflect"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestSemanticResultsKeepOutcomeAndDomainReasonSeparate(t *testing.T) {
	for _, test := range []struct {
		name    string
		result  semanticResult
		outcome Outcome
		reason  string
	}{
		{"visitor forwarded", VisitorForwarded.result(), Success, "forwarded"},
		{"visitor policy", VisitorPolicyDenied.result(), Denied, "policy_denied"},
		{"visitor capacity", VisitorCapacityDenied.result(), Rejected, "capacity_denied"},
		{"visitor draining", VisitorDraining.result(), Rejected, "draining"},
		{"visitor projection", VisitorInvalidProjection.result(), Rejected, "invalid_projection"},
		{"visitor missing", VisitorLookupMissing.result(), Error, "lookup_missing"},
		{"visitor unavailable", VisitorLookupUnavailable.result(), Error, "lookup_unavailable"},
		{"visitor open", VisitorOpenFailed.result(), Error, "open_failed"},
		{"visitor committed failure", VisitorCommittedFailed.result(), Error, "committed_failed"},
		{"visitor unknown", VisitorOutcome("secret").result(), Error, "other"},
		{"relay committed", RelayAttemptCommitted.result(), Success, "committed"},
		{"relay open", RelayAttemptOpenFailed.result(), Error, "open_failed"},
		{"relay setup", RelayAttemptSetupFailed.result(), Error, "setup_failed"},
		{"relay committed failure", RelayAttemptCommittedFailed.result(), Error, "committed_failed"},
		{"relay unknown", RelayAttemptOutcome("secret").result(), Error, "other"},
		{"recovery success", RecoveryAttemptSuccess.result(), Success, ""},
		{"recovery canceled", RecoveryAttemptCanceled.result(), Canceled, ""},
		{"recovery stale", RecoveryAttemptStale.result(), Rejected, "stale"},
		{"recovery retry", RecoveryAttemptRetry.result(), Error, "retry"},
		{"placement success", PlacementPlaced.result(), Success, "placed"},
		{"placement services", PlacementInsufficientServices.result(), Rejected, "insufficient_services"},
		{"placement capacity", PlacementCapacity.result(), Rejected, "capacity"},
		{"placement unavailable", PlacementUnavailable.result(), Error, "unavailable"},
		{"placement stale", PlacementStale.result(), Rejected, "stale"},
		{"placement error", PlacementError.result(), Error, ""},
		{"DNS success", DNSWorkSuccess.result(), Success, ""},
		{"DNS pending", DNSWorkPending.result(), Success, "pending"},
		{"DNS error", DNSWorkError.result(), Error, ""},
		{"certificate claimed", CertificateClaimed.result(), Success, "claimed"},
		{"certificate empty", CertificateEmpty.result(), Success, "empty"},
		{"certificate claim error", CertificateError.result(), Error, ""},
		{"certificate progress", CertificateProgress.result(), Success, "progress"},
		{"certificate retry", CertificateRetry.result(), Error, "retry"},
		{"certificate terminal", CertificateTerminal.result(), Error, "terminal"},
		{"certificate save", CertificateSaveFailed.result(), Error, "save_failed"},
		{"API success", APIRequestSuccess.result(), Success, ""},
		{"API timeout", APIRequestDeadlineExceeded.result(), Timeout, ""},
		{"API canceled", APIRequestCanceled.result(), Canceled, ""},
		{"API denied", APIRequestDenied.result(), Denied, ""},
		{"API server", APIRequestServerError.result(), Error, "server_error"},
		{"API client", APIRequestClientError.result(), Rejected, "client_error"},
		{"API admission", APIRequestNotAdmitted.result(), Rejected, "not_admitted"},
		{"API draining", APIRequestDraining.result(), Rejected, "draining"},
		{"API unknown", APIRequestOutcome("secret").result(), Error, "other"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.result.outcome != test.outcome || test.result.reason.String() != test.reason {
				t.Fatalf("result=%s/%s want=%s/%s", test.result.outcome, test.result.reason, test.outcome, test.reason)
			}
			exporter := tracetest.NewInMemoryExporter()
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			defer provider.Shutdown(t.Context())
			_, span := provider.Tracer("fixture").Start(t.Context(), "result")
			finishSpan(span, test.result)
			span.End()
			got := exporter.GetSpans()[0]
			if !containsAttribute(got.Attributes, string(OutcomeKey.Key()), test.outcome.String()) {
				t.Fatal("span lost outcome", got)
			}
			if test.reason != "" && !containsAttribute(got.Attributes, string(Reason.Key()), test.reason) {
				t.Fatal("span lost domain reason", got)
			}
			status := codes.Error
			if test.outcome == Success || test.outcome == Canceled {
				status = codes.Unset
			}
			if got.Status.Code != status {
				t.Fatal("span status changed", got.Status)
			}
		})
	}
}

func TestDomainReasonVocabularyRemainsExact(t *testing.T) {
	want := []string{"bandwidth", "busy", "capacity", "capacity_denied", "claimed", "client_error", "committed", "committed_failed", "draining", "empty", "expired", "forwarded", "http_error", "insufficient_services", "invalid", "invalid_projection", "invalid_response", "lookup_missing", "lookup_unavailable", "not_admitted", "not_modified", "open_failed", "other", "pending", "placed", "policy_denied", "progress", "retry", "save_failed", "served", "server_error", "setup_failed", "stale", "terminal", "transport_error", "unavailable"}
	if got := domainReasons(); !reflect.DeepEqual(got, want) {
		t.Fatalf("reasons=%v", got)
	}
	if DomainReason(255).String() != "" || DomainReason(0).String() != "" {
		t.Fatal("unknown domain reason exported")
	}
}

func TestServerOperationObserversRetainCallerContext(t *testing.T) {
	m := New("standalone")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	ctx, parent := Start(WithMetrics(t.Context(), m), "parent")
	child, finish := ControlOperation(ctx, OpCreatePublishRun)
	m.ObserveOperationContext(child, OpIngressBackendAttempt, nil, time.Millisecond)
	finish(nil)
	finish(context.Canceled)
	parent(nil)
	spans := exporter.GetSpans()
	if len(spans) != 3 || spans[0].Name != "IngressBackendAttempt" || spans[1].Name != "CreatePublishRun" || spans[0].Parent.SpanID() != spans[1].SpanContext.SpanID() || spans[1].Parent.SpanID() != spans[2].SpanContext.SpanID() {
		t.Fatal("operation context or single completion lost", spans)
	}
	for _, invalid := range []ServerOperation{0, 255} {
		_, finish := ControlOperation(ctx, invalid)
		finish(nil)
		m.ObserveOperationContext(ctx, invalid, nil, time.Second)
	}
	if got := exporter.GetSpans(); len(got) != len(spans) {
		t.Fatal("unknown operation exported", got)
	}
}
