package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestStartupTimingsFlag(t *testing.T) {
	for _, command := range []string{"publish", "dev"} {
		t.Run(command, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse([]string{command, "--startup-timings"}); err != nil {
				t.Fatal(err)
			}
			if command == "publish" && !flags.Publish.StartupTimings {
				t.Fatal("publish startup timings flag was not set")
			}
			if command == "dev" && !flags.Dev.StartupTimings {
				t.Fatal("dev startup timings flag was not set")
			}
		})
	}
}

func TestStartupTimingsReportMilestonesOnce(t *testing.T) {
	started := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	now := started
	timings := newStartupTimings(true, started)
	timings.now = func() time.Time { return now }
	advance := func(label string, duration time.Duration) {
		now = now.Add(duration)
		timings.mark(label)
	}
	advance("configuration", 10*time.Millisecond)

	var stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	observed := 0
	config := publisher.Config{Observe: func(publisher.Event) error {
		observed++
		return nil
	}}
	timings.configurePublisher(&config, output, config.Observe)

	now = now.Add(20 * time.Millisecond)
	if err := config.Observe(publisher.Event{Type: publisher.EventRouteAssigned}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Millisecond)
	config.ObserveStartup(publisher.StartupFirstConnection)
	now = now.Add(40 * time.Millisecond)
	if err := config.Observe(publisher.Event{Type: publisher.EventReady}); err != nil {
		t.Fatal(err)
	}
	if err := config.Observe(publisher.Event{Type: publisher.EventReady}); err != nil {
		t.Fatal(err)
	}

	got := stderr.String()
	for _, want := range []string{
		"]-- startup timings ",
		"configuration     10ms / +10ms",
		"route assigned    30ms / +20ms",
		"first connection  60ms / +30ms",
		"control ready     100ms / +40ms",
		"elapsed / since previous milestone",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("startup timing output missing %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "]-- startup timings ") != 1 || observed != 3 {
		t.Fatalf("startup timing reports = %d, observed events = %d", strings.Count(got, "]-- startup timings "), observed)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 72 {
			t.Fatalf("line exceeds 72 columns: %q", line)
		}
	}
}

func TestStartupTimingsDisabled(t *testing.T) {
	if timings := newStartupTimings(false, time.Now()); timings != nil {
		t.Fatalf("disabled startup timings = %#v", timings)
	}
}
