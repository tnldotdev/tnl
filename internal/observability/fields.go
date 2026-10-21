package observability

import (
	"context"
	"crypto/tls"
	"slices"
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

// Fields replaces protocol/component scope. protocol and transport must be
// parsed at external boundaries; unspecified or invalid values are omitted.
type Fields struct {
	Component           string
	ServiceProtocol     Protocol
	Transport           TransportValue
	TransportPreference TransportValue
	AccessPath          string
	Exposure            string
	TLSLeg              string
	Direction           string
	ConnectionSlot      *int
	ResponseOrigin      string
}
type fieldsKey struct{}

func WithFields(ctx context.Context, fields Fields) context.Context {
	return context.WithValue(ctx, fieldsKey{}, fields)
}

func fieldAttributes(ctx context.Context) []attribute.KeyValue {
	f, _ := ctx.Value(fieldsKey{}).(Fields)
	var out []attribute.KeyValue
	for _, item := range []struct {
		k metricStringKey
		v string
	}{
		{Component, f.Component}, {AccessPath, f.AccessPath}, {Exposure, f.Exposure},
		{TLSLeg, f.TLSLeg}, {Direction, f.Direction}, {ResponseOrigin, f.ResponseOrigin},
	} {
		if slices.Contains(attributeValues[item.k.key()], item.v) {
			out = append(out, item.k.String(item.v))
		}
	}
	for _, a := range []attribute.KeyValue{ServiceProtocol.Value(f.ServiceProtocol), Transport.Value(f.Transport), TransportPreference.Value(f.TransportPreference)} {
		if a.Value.AsString() != "" {
			out = append(out, a)
		}
	}
	if f.ConnectionSlot != nil && (*f.ConnectionSlot == 0 || *f.ConnectionSlot == 1) {
		out = append(out, ConnectionSlot.Int(*f.ConnectionSlot))
	}
	return out
}

// Attributes selects only metric-eligible scope fields for an explicit allowlist.
func Attributes(ctx context.Context, allowed ...MetricKey) []attribute.KeyValue {
	var out []attribute.KeyValue
	for _, a := range append(identityAttributes(ctx), fieldAttributes(ctx)...) {
		for _, k := range allowed {
			if k.key() == Key(a.Key) {
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// TLSAttributes accepts negotiated state, never certificate subjects or peers.
func TLSAttributes(state tls.ConnectionState) []attribute.KeyValue {
	version := ""
	switch state.Version {
	case tls.VersionTLS12:
		version = "1.2"
	case tls.VersionTLS13:
		version = "1.3"
	}
	if version == "" {
		return nil
	}
	return []attribute.KeyValue{TLSVersion.String(version), TLSResumed.Bool(state.DidResume)}
}

func validMetricValue(kv attribute.KeyValue) bool {
	k := Key(kv.Key)
	switch k {
	case HTTPStatus.key():
		return kv.Value.Type() == attribute.INT64 && kv.Value.AsInt64() >= 100 && kv.Value.AsInt64() <= 599
	case ConnectionSlot.key():
		// connection slots are integers at both typed and SDK recording boundaries.
		return kv.Value.Type() == attribute.INT64 && (kv.Value.AsInt64() == 0 || kv.Value.AsInt64() == 1)
	case TLSResumed.key():
		return kv.Value.Type() == attribute.BOOL
	case State.key():
		_, ok := ParseState(kv.Value.AsString())
		return kv.Value.Type() == attribute.STRING && ok
	case Event.key():
		_, ok := ParseEvent(kv.Value.AsString())
		return kv.Value.Type() == attribute.STRING && ok
	}
	if kv.Value.Type() != attribute.STRING {
		return false
	}
	if values := attributeValues[k]; len(values) > 0 {
		return slices.Contains(values, kv.Value.AsString())
	}
	value := kv.Value.AsString()
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}
