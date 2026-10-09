package observability

import (
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// ObserveWebhookProviderSource counts catalog lookups without URL or identity labels.
func (m *Metrics) ObserveWebhookProviderSource(provider, outcome string) {
	if m == nil {
		return
	}
	if !controlv1.WebhookProvider(provider).Valid() {
		provider = "unknown"
	}
	switch outcome {
	case "served", "not_modified", "unavailable", "unknown":
	default:
		outcome = "unavailable"
	}
	m.webhookProviderSources.WithLabelValues(provider, outcome).Inc()
}

// visitor outcomes describe the last ingress boundary reached, not a completed
// TLS handshake or a successful HTTP request at the local service.
func (m *Metrics) ObserveVisitor(outcome VisitorOutcome) {
	if m == nil {
		return
	}
	switch outcome {
	case VisitorLookupMissing, VisitorLookupUnavailable, VisitorInvalidProjection, VisitorPolicyDenied, VisitorCapacityDenied,
		VisitorOpenFailed, VisitorCommittedFailed, VisitorForwarded, VisitorDraining:
	default:
		outcome = VisitorOther
	}
	m.visitorConnections.WithLabelValues(string(outcome)).Inc()
}

func (m *Metrics) ObserveVisitorOpen(success bool, elapsed time.Duration) {
	if m == nil || elapsed < 0 {
		return
	}
	outcome := "error"
	if success {
		outcome = "success"
	}
	m.visitorOpenDuration.WithLabelValues(outcome).Observe(elapsed.Seconds())
}

func (m *Metrics) SetIngressConnections(class string, count int) {
	if m == nil {
		return
	}
	switch class {
	case "client_hello", "public", "denied", "challenge", "control", "relay_tcp":
		m.ingressConnections.WithLabelValues(class).Set(float64(count))
	}
}

func (m *Metrics) AddRegisteredPublisherConnections(delta int) {
	if m != nil {
		m.registeredConnections.Add(float64(delta))
	}
}

func (m *Metrics) ObservePublisherExit(unexpected bool) {
	if m == nil {
		return
	}
	reason := "expected"
	if unexpected {
		reason = "unexpected"
	}
	m.publisherExits.WithLabelValues(reason).Inc()
}

func (m *Metrics) ObserveRelayStreamRejection(reason string) {
	if m == nil {
		return
	}
	switch reason {
	case "stale_assignment", "publisher_unavailable":
	default:
		reason = "other"
	}
	m.relayStreamRejections.WithLabelValues(reason).Inc()
}

func (m *Metrics) ObserveRecoveryDuration(duration time.Duration) {
	if m != nil && duration >= 0 {
		m.recoveryDuration.Observe(duration.Seconds())
	}
}

func (m *Metrics) AddRecoveryPending(delta int) {
	if m != nil {
		m.recoveryPending.Add(float64(delta))
	}
}

func (m *Metrics) ObserveRecoveryAttempt(outcome RecoveryAttemptOutcome) {
	if m == nil {
		return
	}
	switch outcome {
	case RecoveryAttemptSuccess, RecoveryAttemptStale, RecoveryAttemptRetry, RecoveryAttemptCanceled:
	default:
		return
	}
	m.recoveryAttempts.WithLabelValues(string(outcome)).Inc()
}

func (m *Metrics) ObserveCertificateClaim(kind string, outcome CertificateClaimOutcome) {
	if m == nil || kind != "relay" && kind != "public_url" {
		return
	}
	if outcome != CertificateClaimed && outcome != CertificateEmpty && outcome != CertificateError {
		return
	}
	m.certificateClaims.WithLabelValues(kind, string(outcome)).Inc()
}

func (m *Metrics) ObserveCertificateOrder(domainKind, plan string) {
	if m == nil || domainKind != "managed" && domainKind != "custom" || plan != "exact" && plan != "wildcard" {
		return
	}
	m.certificateOrders.WithLabelValues(domainKind, plan).Inc()
}

func (m *Metrics) ObserveCertificateTransition(kind, state string) {
	if m == nil || kind != "relay" && kind != "public_url" {
		return
	}
	switch state {
	case "available", "installed", "cleanup_complete", "failed":
	default:
		return
	}
	m.certificateTransitions.WithLabelValues(kind, state).Inc()
}

func (m *Metrics) ObserveDNSWork(kind, phase string, outcome DNSWorkOutcome, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch kind {
	case "authority", "public_url", "public_url_challenge", "relay_challenge":
	default:
		return
	}
	switch phase {
	case "claim", "advance", "provider", "verify", "save", "cleanup":
	default:
		return
	}
	switch outcome {
	case DNSWorkSuccess, DNSWorkPending, DNSWorkError:
	default:
		return
	}
	m.dnsWork.WithLabelValues(kind, phase, string(outcome)).Observe(elapsed.Seconds())
}

func (m *Metrics) ObserveDNSTransition(kind, state string) {
	if m == nil || kind != "authority" && kind != "public_url" {
		return
	}
	switch state {
	case "published", "removed", "ready", "released", "failed":
	default:
		return
	}
	m.dnsTransitions.WithLabelValues(kind, state).Inc()
}

func (m *Metrics) ObserveUsageWork(phase string, outcome UsageWorkOutcome) {
	if m == nil {
		return
	}
	switch phase {
	case "incomplete_runs", "finalize", "claim", "deliver", "complete", "retry", "reject":
	default:
		return
	}
	switch outcome {
	case UsageWorkSuccess, UsageWorkEmpty, UsageWorkError:
	default:
		return
	}
	m.usageWork.WithLabelValues(phase, string(outcome)).Inc()
	if phase == "finalize" && outcome == UsageWorkSuccess {
		m.usageLastSuccess.WithLabelValues("finalize").SetToCurrentTime()
	}
}

func (m *Metrics) AddUsageItems(result string, count int) {
	if m == nil || count <= 0 {
		return
	}
	switch result {
	case "incomplete", "finalized", "accepted", "retried", "rejected":
	default:
		return
	}
	m.usageItems.WithLabelValues(result).Add(float64(count))
	if result == "accepted" {
		m.usageLastSuccess.WithLabelValues("deliver").SetToCurrentTime()
	}
}

func (m *Metrics) ObserveUsageReceiver(outcome UsageReceiverOutcome, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch outcome {
	case UsageReceiverSuccess, UsageReceiverHTTPError, UsageReceiverTransportError, UsageReceiverInvalidResponse:
	default:
		return
	}
	m.usageReceiverDuration.WithLabelValues(string(outcome)).Observe(elapsed.Seconds())
}

func (m *Metrics) SetUsageRetained(count int) {
	if m != nil {
		m.usageRetained.Set(float64(count))
	}
}

func (m *Metrics) ObserveCleanup(kind string, count int, busy bool, err error) {
	if m == nil {
		return
	}
	switch kind {
	case "expired_publish_runs", "ephemeral_public_urls", "routing_floor", "routing_prune":
	default:
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "error"
	} else if busy {
		outcome = "busy"
	}
	m.cleanupRuns.WithLabelValues(kind, outcome).Inc()
	if outcome == "success" {
		m.cleanupLastSuccess.WithLabelValues(kind).SetToCurrentTime()
		if count > 0 {
			m.cleanupItems.WithLabelValues(kind).Add(float64(count))
		}
	}
}

func (m *Metrics) ObservePlacement(action string, outcome PlacementOutcome) {
	if m == nil {
		return
	}
	if action != "create" && action != "replenish" {
		return
	}
	switch outcome {
	case PlacementPlaced, PlacementInsufficientServices, PlacementCapacity, PlacementUnavailable, PlacementStale, PlacementError:
	default:
		return
	}
	m.placementDecisions.WithLabelValues(action, string(outcome)).Inc()
}

func (m *Metrics) AddAssignmentReplacements(reason string, count int) {
	if m == nil || count <= 0 {
		return
	}
	switch reason {
	case "failed_ready", "expired", "unavailable":
	default:
		return
	}
	m.assignmentReplacements.WithLabelValues(reason).Add(float64(count))
}
