package observability

//go:generate go run ./cmd/vocabulary ../../api/observability/v1/vocabulary.json

import "errors"

// DimensionPolicy describes where a declared attribute may be exported.
type DimensionPolicy uint8

const (
	PolicyResource DimensionPolicy = iota + 1
	PolicyScoped
	PolicyBounded
	PolicyTraceLog
	PolicySDK
)

func (v DimensionPolicy) String() string {
	return enumString([]string{"", "resource", "scoped", "bounded", "trace_log", "sdk"}, int(v))
}

func (v DimensionPolicy) MarshalJSON() ([]byte, error) {
	if v.String() == "" {
		return nil, errors.New("invalid observability dimension policy")
	}
	return []byte(`"` + v.String() + `"`), nil
}

// InstrumentKind preserves the wire spelling while separating instrument kinds
// from descriptions, dimension policies, and arbitrary strings.
type InstrumentKind uint8

const (
	KindCounter InstrumentKind = iota + 1
	KindGauge
	KindHistogram
	KindSummary
)

func (v InstrumentKind) String() string {
	return enumString([]string{"", "counter", "gauge", "histogram", "summary"}, int(v))
}

func (v InstrumentKind) MarshalJSON() ([]byte, error) {
	if v.String() == "" {
		return nil, errors.New("invalid observability instrument kind")
	}
	return []byte(`"` + v.String() + `"`), nil
}
