package observability

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InstrumentDefinition is generated from the actual instrument declarations.
// dimensions are an allowlist, not labels automatically attached to every point.
type InstrumentDefinition struct {
	Name           string    `json:"name"`
	Semantics      string    `json:"semantics"`
	Kind           string    `json:"kind"`
	Dimensions     []Key     `json:"dimensions"`
	ExplicitBounds []float64 `json:"explicit_bounds,omitempty"`
}

type contractMeter struct {
	metric.Meter
	mu    sync.RWMutex
	specs map[string]InstrumentDefinition
}

func (m *contractMeter) describe(name, semantics, kind string, bounds []float64, keys ...string) {
	var dimensions []Key
	for _, key := range keys {
		k := dimensionKey(name, key)
		dimensions = append(dimensions, k)
		if k == OutcomeKey {
			dimensions = append(dimensions, Reason)
		}
	}
	// the SDK creates overflow points after applying the instrument view. this
	// exception is boolean true only, never a caller-supplied dimension.
	dimensions = append(dimensions, MetricOverflow)
	if strings.HasPrefix(name, "tnl_publisher_") {
		dimensions = append(dimensions, TeamID, DeploymentID, ReplicaKey, PublisherGroupID, PublisherIdentityID, ServiceID, PublicURLID, ServiceKindKey)
	}
	slices.Sort(dimensions)
	dimensions = slices.Compact(dimensions)
	if dimensions == nil {
		dimensions = []Key{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specs[name] = InstrumentDefinition{name, semantics, kind, dimensions, slices.Clone(bounds)}
}

func (m *contractMeter) definition(name string) (InstrumentDefinition, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	spec, ok := m.specs[name]
	return spec, ok
}

func describe(m metric.Meter, name, semantics, kind string, bounds []float64, keys ...string) {
	if c, ok := m.(*contractMeter); ok {
		c.describe(name, semantics, kind, bounds, keys...)
	}
}

// InstrumentDefinitions returns a detached, sorted snapshot for documentation.
func (m *Metrics) InstrumentDefinitions() []InstrumentDefinition {
	c := m.meter.(*contractMeter)
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]InstrumentDefinition, 0, len(c.specs))
	for _, spec := range c.specs {
		spec.Dimensions = slices.Clone(spec.Dimensions)
		spec.ExplicitBounds = slices.Clone(spec.ExplicitBounds)
		out = append(out, spec)
	}
	slices.SortFunc(out, func(a, b InstrumentDefinition) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Vocabulary is the deterministic shared contract consumed by tnl.dev.
type Vocabulary struct {
	Version          int                    `json:"version"`
	Authority        string                 `json:"authority"`
	CardinalityLimit int                    `json:"cardinality_limit"`
	Attributes       []AttributeDefinition  `json:"attributes"`
	Instruments      []InstrumentDefinition `json:"instruments"`
}

// SharedVocabulary is offline. callbacks expose only local snapshots; no
// environment, process instance, runtime counts, or I/O is included.
func SharedVocabulary() Vocabulary {
	m := New("standalone")
	defer m.Shutdown(context.Background())
	m.RegisterDatabase(func(time.Time) DatabaseSnapshot { return DatabaseSnapshot{} })
	m.RegisterIngressRouting(func() IngressRoutingSnapshot { return IngressRoutingSnapshot{} })
	m.RegisterIngressLease(func() time.Time { return time.Time{} })
	m.RegisterControlCertificate(func() time.Time { return time.Time{} })
	instruments := append(m.InstrumentDefinitions(), RuntimeInstrumentDefinitions()...)
	slices.SortFunc(instruments, func(a, b InstrumentDefinition) int { return strings.Compare(a.Name, b.Name) })
	return Vocabulary{1, "internal/observability: vocabulary.go and instrument declarations", 2000, VocabularyAttributes(), instruments}
}

func dimensionKey(name, key string) Key {
	if strings.Contains(key, ".") {
		return Key(key)
	}
	switch key {
	case "role":
		return RoleKey
	case "resource":
		return CapacityResource
	case "class":
		return "tnl.connection_class"
	case "surface":
		return Component
	case "pool":
		return "tnl.ingress_pool"
	case "purpose":
		if strings.HasPrefix(name, "tnl_database_") {
			return "tnl.database_purpose"
		}
		return "tnl.public_url_purpose"
	case "plan":
		return "tnl.certificate_plan"
	case "kind":
		switch {
		case strings.Contains(name, "certificate"):
			return CertificateKind
		case strings.Contains(name, "dns"):
			return DNSKind
		case strings.Contains(name, "cleanup"):
			return CleanupKind
		default:
			return ServiceKindKey
		}
	case "result":
		if name == "tnl_service_audit_events_total" || name == "tnl_control_public_url_usage_items_total" {
			return Event
		}
		return OutcomeKey
	case "outcome":
		if strings.Contains(name, "readiness_") {
			return State
		}
		return OutcomeKey
	case "stage":
		if strings.Contains(name, "guest_trials") {
			return Event
		}
		return Operation
	case "phase", "action":
		return Operation
	case "milestone":
		return Event
	default:
		return Key("tnl." + key)
	}
}

// classifyResult separates the small result vocabulary from closed domain detail.
// no fallback ever uses the supplied value as a reason.
func classifyResult(value string) (Outcome, string) {
	switch value {
	case "success", "allowed", "accepted":
		return Success, ""
	case "denied":
		return Denied, ""
	case "rejected":
		return Rejected, ""
	case "timeout", "deadline_exceeded":
		return Timeout, ""
	case "canceled":
		return Canceled, ""
	case "error":
		return Error, ""
	default:
		if outcome, ok := domainOutcomes[value]; ok {
			return outcome, value
		}
		return Error, "other"
	}
}

var domainOutcomes = map[string]Outcome{
	"forwarded": Success, "committed": Success, "placed": Success, "served": Success, "not_modified": Success, "claimed": Success, "empty": Success, "progress": Success, "pending": Success, "busy": Success,
	"policy_denied":   Denied,
	"not_admitted":    Rejected,
	"capacity_denied": Rejected, "capacity": Rejected, "bandwidth": Rejected, "draining": Rejected, "invalid": Rejected, "invalid_projection": Rejected, "insufficient_services": Rejected, "client_error": Rejected, "stale": Rejected,
	"lookup_missing": Error, "lookup_unavailable": Error, "open_failed": Error, "setup_failed": Error, "committed_failed": Error, "unavailable": Error, "retry": Error, "terminal": Error, "save_failed": Error, "http_error": Error, "server_error": Error, "transport_error": Error, "invalid_response": Error, "other": Error, "expired": Error,
}

func domainReasons() []string {
	out := make([]string, 0, len(domainOutcomes))
	for reason := range domainOutcomes {
		out = append(out, reason)
	}
	slices.Sort(out)
	return out
}

func metricLabelSet(name string, keys, values []string) attribute.Set {
	if len(keys) != len(values) {
		panic("instrument attribute count mismatch")
	}
	var attrs []attribute.KeyValue
	for i, key := range keys {
		k, v := dimensionKey(name, key), values[i]
		if k == ConnectionSlot && v != "0" && v != "1" {
			continue
		}
		if k == OutcomeKey {
			outcome, reason := classifyResult(v)
			attrs = append(attrs, k.String(string(outcome)))
			if reason != "" {
				attrs = append(attrs, Reason.String(reason))
			}
			continue
		}
		attrs = append(attrs, k.String(v))
	}
	return attribute.NewSet(attrs...)
}
