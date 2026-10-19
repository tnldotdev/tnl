package observability

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// these small bindings keep the existing semantic observer API independent of
// the exporter. all measurements enter the OTel SDK once. only absolute gauges
// need local state, to translate Set and Add into an additive OTel instrument.
type counter struct {
	instrument metric.Float64Counter
	keys       []string
}
type counterValue struct {
	instrument metric.Float64Counter
	attrs      attribute.Set
}

func newCounter(m metric.Meter, name, description string, keys ...string) *counter {
	instrument, err := m.Float64Counter(name, metric.WithDescription(description))
	if err != nil {
		panic(err)
	} // names are compiled constants.
	return &counter{instrument: instrument, keys: keys}
}
func (c *counter) WithLabelValues(values ...string) counterValue {
	return counterValue{c.instrument, labelSet(c.keys, values)}
}
func (c *counter) Inc()              { c.WithLabelValues().Inc() }
func (c *counter) Add(value float64) { c.WithLabelValues().Add(value) }
func (c counterValue) Inc()          { c.Add(1) }
func (c counterValue) Add(value float64) {
	c.instrument.Add(context.Background(), value, metric.WithAttributeSet(c.attrs))
}

type gauge struct {
	instrument metric.Float64UpDownCounter
	keys       []string
	mu         sync.Mutex
	values     map[attribute.Set]float64
}
type gaugeValue struct {
	gauge *gauge
	attrs attribute.Set
}

func newGauge(m metric.Meter, name, description string, keys ...string) *gauge {
	instrument, err := m.Float64UpDownCounter(name, metric.WithDescription(description))
	if err != nil {
		panic(err)
	}
	return &gauge{instrument: instrument, keys: keys, values: make(map[attribute.Set]float64)}
}
func (g *gauge) WithLabelValues(values ...string) gaugeValue {
	return gaugeValue{g, labelSet(g.keys, values)}
}
func (g *gauge) Set(value float64) { g.WithLabelValues().Set(value) }
func (g *gauge) Add(value float64) { g.WithLabelValues().Add(value) }
func (g gaugeValue) Set(value float64) {
	g.gauge.mu.Lock()
	defer g.gauge.mu.Unlock()
	g.record(value - g.gauge.values[g.attrs])
}
func (g gaugeValue) Add(value float64) {
	g.gauge.mu.Lock()
	defer g.gauge.mu.Unlock()
	g.record(value)
}
func (g gaugeValue) record(delta float64) {
	g.gauge.values[g.attrs] += delta
	g.gauge.instrument.Add(context.Background(), delta, metric.WithAttributeSet(g.attrs))
}
func (g gaugeValue) Inc()              { g.Add(1) }
func (g gaugeValue) Dec()              { g.Add(-1) }
func (g gaugeValue) SetToCurrentTime() { g.Set(routingTimestamp(time.Now())) }

type histogram struct {
	instrument metric.Float64Histogram
	keys       []string
}
type histogramValue struct {
	instrument metric.Float64Histogram
	attrs      attribute.Set
}

func newHistogram(m metric.Meter, name, description string, bounds []float64, keys ...string) *histogram {
	instrument, err := m.Float64Histogram(name, metric.WithDescription(description), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(bounds...))
	if err != nil {
		panic(err)
	}
	return &histogram{instrument, keys}
}
func (h *histogram) WithLabelValues(values ...string) histogramValue {
	return histogramValue{h.instrument, labelSet(h.keys, values)}
}
func (h *histogram) Observe(value float64) { h.WithLabelValues().Observe(value) }
func (h histogramValue) Observe(value float64) {
	h.instrument.Record(context.Background(), value, metric.WithAttributeSet(h.attrs))
}

func labelSet(keys, values []string) attribute.Set {
	if len(keys) != len(values) {
		panic("instrument attribute count mismatch")
	}
	attrs := make([]attribute.KeyValue, len(keys))
	for i, key := range keys {
		attrs[i] = attribute.String(key, values[i])
	}
	return attribute.NewSet(attrs...)
}

func (m *Metrics) gaugeFunc(name, description string, source func() float64) {
	_, err := m.meter.Float64ObservableGauge(name, metric.WithDescription(description), metric.WithFloat64Callback(func(_ context.Context, observer metric.Float64Observer) error {
		observer.Observe(source())
		return nil
	}))
	if err != nil {
		panic(err)
	}
}
