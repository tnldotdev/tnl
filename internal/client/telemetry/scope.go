package telemetry

import (
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// each publication owns its scope and joins it after its transport workers.
// only fixed-size counters are touched by transport and recovery callbacks.
type Scope struct {
	collector *Collector
	role      api.TransportReportRole
	mu        sync.Mutex
	epoch     int64
	counts    [4][3][3][4]int64
	stop      chan struct{}
	done      chan struct{}
	once      sync.Once
	closed    bool
}

func (c *Collector) BeginScope(role api.TransportReportRole, disabled bool) *Scope {
	if c == nil || c.closed.Load() || disabled || !role.Valid() {
		return nil
	}
	s := &Scope{collector: c, role: role, epoch: c.preference.Load().Epoch, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-s.stop:
				s.flush()
				return
			case <-ticker.C:
				s.flush()
			}
		}
	}()
	return s
}

var operations = [...]api.Operation{api.RelayConnect, api.DirectConnect, api.Fallback, api.Recovery}
var paths = [...]api.Path{api.Quic, api.TlsTcp, api.DirectUdp}
var outcomes = [...]api.Outcome{api.Succeeded, api.Failed, api.Canceled}
var durations = [...]api.Duration{api.Lt1s, api.Lt10s, api.Lt1m, api.Longer}

func index[T comparable](values []T, value T) int {
	for i, candidate := range values {
		if candidate == value {
			return i
		}
	}
	return -1
}

func (s *Scope) Record(operation api.Operation, path api.Path, outcome api.Outcome, elapsed time.Duration) {
	if s == nil || elapsed < 0 {
		return
	}
	i, j, k := index(operations[:], operation), index(paths[:], path), index(outcomes[:], outcome)
	if i < 0 || j < 0 || k < 0 {
		return
	}
	bucket := 3
	switch {
	case elapsed < time.Second:
		bucket = 0
	case elapsed < 10*time.Second:
		bucket = 1
	case elapsed < time.Minute:
		bucket = 2
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.collector.preference.Load()
	if p.Epoch != s.epoch {
		s.counts = [4][3][3][4]int64{}
		s.epoch = p.Epoch
	}
	if s.closed || !p.Enabled || s.collector.closed.Load() {
		return
	}
	count := &s.counts[i][j][k][bucket]
	if *count < 1_000_000_000 {
		*count++
	}
}

func (s *Scope) flush() {
	s.mu.Lock()
	p := s.collector.preference.Load()
	report := api.TransportReport{Role: s.role}
	if p.Enabled && p.Epoch == s.epoch {
		for i, op := range operations {
			for j, path := range paths {
				for k, outcome := range outcomes {
					for l, duration := range durations {
						if count := s.counts[i][j][k][l]; count != 0 {
							measurement := api.Measurement{Operation: op, Path: path, Outcome: outcome, Duration: duration, Count: count}
							if op == api.Fallback {
								measurement.Duration = ""
							}
							report.Measurements = append(report.Measurements, measurement)
						}
					}
				}
			}
		}
	}
	s.counts = [4][3][3][4]int64{}
	epoch := s.epoch
	s.mu.Unlock()
	if len(report.Measurements) == 0 {
		return
	}
	id, _ := opaqueid.New(opaqueid.TelemetryEventPrefix)
	var event api.Event
	_ = event.FromTransportEvent(api.TransportEvent{EventId: id, EventVersion: 1, Name: "transport.report", Payload: report})
	// retain the measurement epoch; Report would capture a potentially newer one.
	data, err := event.MarshalJSON()
	if err == nil {
		select {
		case s.collector.queue <- queuedEvent{data, epoch}:
		default:
		}
	}
	s.collector.Flush()
}

func (s *Scope) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() { s.mu.Lock(); s.closed = true; s.mu.Unlock(); close(s.stop); <-s.done })
}
