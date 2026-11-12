package telemetry

import (
	"sync"
	"time"

	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// each publication owns its scope and closes it after its transport workers.
// only fixed-size counters are touched by transport and recovery callbacks.
type Scope struct {
	collector    *Collector
	role         api.TransportReportRole
	mu           sync.Mutex
	epoch        int64
	counts       [4][3][3][4]int64
	closed       bool
	once         sync.Once
	ready        *api.PublicationReady
	demo         bool
	seenReady    bool
	seenDemo     bool
	integrations [4]struct {
		seen, pending bool
		payload       api.IntegrationOutcome
	}
}

func (c *Collector) BeginScope(role api.TransportReportRole) *Scope {
	if c == nil || !role.Valid() {
		return nil
	}
	c.scopesMu.Lock()
	defer c.scopesMu.Unlock()
	if c.closed.Load() {
		return nil
	}
	s := &Scope{collector: c, role: role, epoch: c.preference.Load().Epoch}
	c.scopes[s] = struct{}{}
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
	if !s.enabled() {
		return
	}
	count := &s.counts[i][j][k][bucket]
	if *count < 1_000_000_000 {
		*count++
	}
}

// enabled is called with mu held; an epoch change drops every pending fact.
func (s *Scope) enabled() bool {
	p := s.collector.preference.Load()
	if p.Epoch != s.epoch {
		s.counts = [4][3][3][4]int64{}
		s.ready, s.demo, s.seenReady, s.seenDemo = nil, false, false, false
		clear(s.integrations[:])
		s.epoch = p.Epoch
	}
	return !s.closed && p.Enabled && !s.collector.closed.Load()
}

func (s *Scope) Ready(payload api.PublicationReady) {
	if s == nil {
		return
	}
	if payload.Framework != nil {
		framework := *payload.Framework
		payload.Framework = &framework
	}
	s.mu.Lock()
	if s.enabled() && !s.seenReady {
		s.ready, s.seenReady = &payload, true
	}
	s.mu.Unlock()
	s.collector.Flush()
}

// request callbacks only retain bounded facts; the collector encodes them.
func (s *Scope) Demo() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled() && !s.seenDemo {
		s.demo, s.seenDemo = true, true
	}
}

func (s *Scope) Integration(payload api.IntegrationOutcome) {
	if s == nil {
		return
	}
	index := 0
	switch {
	case payload.Kind == "oauth" && payload.Outcome == api.Ready:
	case payload.Kind == "oauth" && payload.Outcome == api.Redirected:
		index = 1
	case payload.Kind == "webhook" && payload.Outcome == api.Ready:
		index = 2
	case payload.Kind == "webhook" && payload.Outcome == api.ReachedReceiver:
		index = 3
	default:
		return
	}
	if payload.Delivery != nil {
		delivery := *payload.Delivery
		payload.Delivery = &delivery
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled() && !s.integrations[index].seen {
		s.integrations[index].seen, s.integrations[index].pending, s.integrations[index].payload = true, true, payload
	}
}

func (s *Scope) flush() {
	s.flushTo(s.collector.enqueue)
}

func (s *Scope) flushTo(emit func(api.Event, int64)) {
	s.mu.Lock()
	var events []api.Event
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
	if p.Enabled && p.Epoch == s.epoch {
		if s.ready != nil {
			events = append(events, Ready(*s.ready))
		}
		if s.demo {
			events = append(events, Demo())
		}
		for _, observation := range s.integrations {
			if observation.pending {
				events = append(events, Integration(observation.payload))
			}
		}
		if len(report.Measurements) != 0 {
			var event api.Event
			id := eventID()
			_ = event.FromTransportEvent(api.TransportEvent{EventId: id, EventVersion: 1, Name: "transport.report", Payload: report})
			events = append(events, event)
		}
	}
	s.ready, s.demo = nil, false
	for i := range s.integrations {
		s.integrations[i].pending = false
	}
	epoch := s.epoch
	s.mu.Unlock()
	for _, event := range events {
		emit(event, epoch)
	}
}

func (s *Scope) Close() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.collector.scopesMu.Lock()
		delete(s.collector.scopes, s)
		s.collector.scopesMu.Unlock()
		s.flush()
		s.collector.Flush()
	})
}
