package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type startupTimingOptions struct {
	StartupTimings bool `name:"startup-timings" help:"Report startup phase timings once the route is ready."`

	startup *startupTimings
}

type startupMilestone struct {
	label   string
	elapsed time.Duration
	delta   time.Duration
}

type startupTimings struct {
	mu         sync.Mutex
	started    time.Time
	previous   time.Time
	now        func() time.Time
	milestones []startupMilestone
	seen       map[string]struct{}
	reported   bool
}

func newStartupTimings(enabled bool, started time.Time) *startupTimings {
	if !enabled {
		return nil
	}
	return &startupTimings{
		started: started, previous: started, now: time.Now, seen: make(map[string]struct{}),
	}
}

func (s *startupTimings) mark(label string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.seen[label]; found || s.reported {
		return
	}
	now := s.now()
	s.milestones = append(s.milestones, startupMilestone{
		label: label, elapsed: now.Sub(s.started), delta: now.Sub(s.previous),
	})
	s.previous = now
	s.seen[label] = struct{}{}
}

func (s *startupTimings) configurePublisher(
	config *publisher.Config,
	output *publishOutput,
	observe func(publisher.Event) error,
) {
	if s == nil {
		config.Observe = observe
		return
	}
	config.ObserveStartup = func(phase publisher.StartupPhase) {
		s.mark(string(phase))
	}
	config.Observe = func(event publisher.Event) error {
		switch event.Type {
		case publisher.EventRouteAssigned:
			s.mark("route assigned")
		case publisher.EventProvisioning:
			s.mark("route session")
		case publisher.EventReady:
			s.mark("control ready")
		}
		if observe != nil {
			if err := observe(event); err != nil {
				return err
			}
		}
		if event.Type == publisher.EventReady {
			return s.report(output)
		}
		return nil
	}
}

func (s *startupTimings) report(output *publishOutput) error {
	s.mu.Lock()
	if s.reported {
		s.mu.Unlock()
		return nil
	}
	s.reported = true
	fields := make([]clioutput.Field, 0, len(s.milestones))
	for _, milestone := range s.milestones {
		fields = append(fields, clioutput.Field{
			Label: milestone.label,
			Value: fmt.Sprintf("%s / +%s", formatStartupDuration(milestone.elapsed), formatStartupDuration(milestone.delta)),
		})
	}
	s.mu.Unlock()
	return output.startupTimings(fields)
}

func formatStartupDuration(value time.Duration) string {
	if value < time.Millisecond {
		return "<1ms"
	}
	return value.Round(time.Millisecond).String()
}
