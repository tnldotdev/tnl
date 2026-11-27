package observability

import "slices"

type DiagnosticKind string

const (
	IngressEarlyClose     DiagnosticKind = "ingress_early_close"
	IngressVisitorClose   DiagnosticKind = "ingress_visitor_close"
	RelayVisitorClose     DiagnosticKind = "relay_visitor_close"
	PublisherVisitorClose DiagnosticKind = "publisher_visitor_close"
	PublisherHTTPAbort    DiagnosticKind = "publisher_http_abort"
	WatchUnavailable      DiagnosticKind = "watch_unavailable"
)

func (m *Metrics) ObserveDiagnostic(kind DiagnosticKind, logged bool) {
	if m == nil {
		return
	}
	switch kind {
	case IngressEarlyClose, IngressVisitorClose, RelayVisitorClose, PublisherVisitorClose, PublisherHTTPAbort, WatchUnavailable:
		event := EventDropped
		if logged {
			event = EventDelivered
		}
		m.diagnostics.With(Operation.Dimension(operationName(kind)), Event.Dimension(event)).Inc()
	}
}

var ingressEarlyCloseReasons = []string{"draining", "process_connection_rate", "client_hello_connections", "source_connection_rate", "source_connections",
	"inspection_deadline", "invalid_forwarding_metadata", "unallocated_port", "invalid_hostname", "client_hello_timeout",
	"malformed_client_hello", "incomplete_client_hello", "client_hello_too_large", "too_many_tls_records", "missing_sni",
	"duplicate_sni", "unexpected_tls_record"}

func (m *Metrics) ObserveIngressEarlyClose(reason string) {
	if m == nil {
		return
	}
	if !slices.Contains(ingressEarlyCloseReasons, reason) {
		reason = "other"
	}
	m.ingressEarlyCloses.With(Reason.Dimension(reason)).Inc()
}
