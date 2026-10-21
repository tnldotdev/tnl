package observability

import (
	"context"
	"slices"
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
	keys       []MetricKey
}
type counterValue struct {
	instrument metric.Float64Counter
	attrs      attribute.Set
}

func newCounter(m metric.Meter, name, description string, keys ...MetricKey) *counter {
	describe(m, name, description, KindCounter, nil, keys...)
	instrument, err := m.Float64Counter(name, metric.WithDescription(description))
	if err != nil {
		panic(err)
	} // names are compiled constants.
	return &counter{instrument: instrument, keys: slices.Clone(keys)}
}
func (c *counter) With(values ...Dimension) counterValue {
	return counterValue{c.instrument, metricDimensions(c.keys, values...)}
}
func (c *counter) Inc()              { c.With().Inc() }
func (c *counter) Add(value float64) { c.With().Add(value) }
func (c counterValue) Inc()          { c.Add(1) }
func (c counterValue) Add(value float64) {
	c.instrument.Add(context.Background(), value, metric.WithAttributeSet(c.attrs))
}

type gauge struct {
	instrument metric.Float64UpDownCounter
	keys       []MetricKey
	mu         sync.Mutex
	values     map[attribute.Set]float64
}
type gaugeValue struct {
	gauge *gauge
	attrs attribute.Set
}

func newGauge(m metric.Meter, name, description string, keys ...MetricKey) *gauge {
	describe(m, name, description, KindGauge, nil, keys...)
	instrument, err := m.Float64UpDownCounter(name, metric.WithDescription(description))
	if err != nil {
		panic(err)
	}
	return &gauge{instrument: instrument, keys: slices.Clone(keys), values: make(map[attribute.Set]float64)}
}
func (g *gauge) With(values ...Dimension) gaugeValue {
	return gaugeValue{g, metricDimensions(g.keys, values...)}
}
func (g *gauge) Set(value float64) { g.With().Set(value) }
func (g *gauge) Add(value float64) { g.With().Add(value) }
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
	if _, exists := g.gauge.values[g.attrs]; !exists && len(g.gauge.values) >= 2000 {
		return
	}
	g.gauge.values[g.attrs] += delta
	g.gauge.instrument.Add(context.Background(), delta, metric.WithAttributeSet(g.attrs))
}
func (g gaugeValue) Inc()              { g.Add(1) }
func (g gaugeValue) Dec()              { g.Add(-1) }
func (g gaugeValue) SetToCurrentTime() { g.Set(routingTimestamp(time.Now())) }

type histogram struct {
	instrument metric.Float64Histogram
	keys       []MetricKey
}
type histogramValue struct {
	instrument metric.Float64Histogram
	attrs      attribute.Set
}

func newHistogram(m metric.Meter, name, description string, bounds []float64, keys ...MetricKey) *histogram {
	describe(m, name, description, KindHistogram, bounds, keys...)
	instrument, err := m.Float64Histogram(name, metric.WithDescription(description), metric.WithUnit("s"), metric.WithExplicitBucketBoundaries(bounds...))
	if err != nil {
		panic(err)
	}
	return &histogram{instrument, slices.Clone(keys)}
}
func (h *histogram) With(values ...Dimension) histogramValue {
	return histogramValue{h.instrument, metricDimensions(h.keys, values...)}
}
func (h *histogram) Observe(value float64) { h.With().Observe(value) }
func (h histogramValue) Observe(value float64) {
	h.ObserveContext(context.Background(), value)
}
func (h histogramValue) ObserveContext(ctx context.Context, value float64) {
	h.instrument.Record(ctx, value, metric.WithAttributeSet(h.attrs))
}

func (m *Metrics) gaugeFunc(name, description string, source func() float64) {
	describe(m.meter, name, description, KindGauge, nil)
	_, err := m.meter.Float64ObservableGauge(name, metric.WithDescription(description), metric.WithFloat64Callback(func(_ context.Context, observer metric.Float64Observer) error {
		observer.Observe(source())
		return nil
	}))
	if err != nil {
		panic(err)
	}
}
