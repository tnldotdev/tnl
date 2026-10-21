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
	Name           string         `json:"name"`
	Semantics      string         `json:"semantics"`
	Kind           InstrumentKind `json:"kind"`
	Dimensions     []Key          `json:"dimensions"`
	ExplicitBounds []float64      `json:"explicit_bounds,omitempty"`
}

type contractMeter struct {
	metric.Meter
	mu    sync.RWMutex
	specs map[string]InstrumentDefinition
}

func (m *contractMeter) describe(name, semantics string, kind InstrumentKind, bounds []float64, keys ...MetricKey) {
	if kind.String() == "" {
		panic("instrument kind is unspecified")
	}
	var dimensions []Key
	for _, key := range keys {
		k := key.key()
		if k == "" {
			panic("instrument dimension has no declared key")
		}
		dimensions = append(dimensions, k)
		if k == OutcomeKey.key() {
			dimensions = append(dimensions, Reason.key())
		}
	}
	// the SDK creates overflow points after applying the instrument view. this
	// exception is boolean true only, never a caller-supplied dimension.
	dimensions = append(dimensions, MetricOverflow.key())
	if strings.HasPrefix(name, "tnl_publisher_") {
		for _, k := range []MetricKey{TeamID, DeploymentID, ReplicaKey, PublisherGroupID, PublisherIdentityID, ServiceID, PublicURLID, ServiceKindKey} {
			dimensions = append(dimensions, k.key())
		}
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

func describe(m metric.Meter, name, semantics string, kind InstrumentKind, bounds []float64, keys ...MetricKey) {
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

func metricDimensions(keys []MetricKey, values ...Dimension) attribute.Set {
	var attrs []attribute.KeyValue
	seen := make(map[Key]bool)
	for _, value := range values {
		for _, a := range value.attrs {
			k := Key(a.Key)
			allowed := slices.ContainsFunc(keys, func(key MetricKey) bool { return key.key() == k || key.key() == OutcomeKey.key() && k == Reason.key() })
			if !allowed || seen[k] {
				panic("instrument dimension is undeclared or duplicated")
			}
			seen[k] = true
			if validMetricValue(a) {
				attrs = append(attrs, a)
			}
		}
	}
	return attribute.NewSet(attrs...)
}

// resultDimension is the legacy semantic-result boundary: supplied domain values
// are classified before narrowing, and unknown values never become labels.
func resultDimension(value string) Dimension {
	outcome, reason := classifyResult(value)
	d := OutcomeKey.Dimension(outcome)
	if reason != "" {
		d.attrs = append(d.attrs, Reason.String(reason))
	}
	return d
}

func stateDimension(value string) Dimension {
	state, _ := ParseState(value)
	return State.Dimension(state)
}

func eventDimension(value string) Dimension {
	event, _ := ParseEvent(value)
	return Event.Dimension(event)
}
