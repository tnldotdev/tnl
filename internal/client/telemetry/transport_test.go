package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestTelemetryTransportAdaptersKeepBoundedFactsAndExistingObservers(t *testing.T) {
	c := collectorForTest(t, Config{})
	s := c.BeginScope("connector", false)
	defer s.Close()
	attempts, fallbacks := 0, 0
	options := s.Connectivity(peer.ConnectivityOptions{ObserveAttempt: func(peer.ConnectivityAttempt) { attempts++ }, ObserveFallback: func() { fallbacks++ }})
	options.ObserveAttempt(peer.ConnectivityAttempt{Outcome: "succeeded", Duration: 2 * time.Second})
	options.ObserveAttempt(peer.ConnectivityAttempt{Outcome: "failed", Duration: 10 * time.Second})
	options.ObserveFallback()
	s.RelayAttempt(t.Context(), tunnel.TransportQUIC, time.Second, errors.New("private relay address"))
	s.RelayAttempt(t.Context(), tunnel.TransportTLSTCP, time.Second, nil)
	canceled, stop := context.WithCancel(t.Context())
	stop()
	s.RelayAttempt(canceled, tunnel.TransportQUIC, time.Second, context.Canceled)
	s.Close()
	flushForTest(t, c)
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 1 || attempts != 2 || fallbacks != 1 {
		t.Fatalf("rows=%d attempts=%d fallbacks=%d err=%v", len(rows), attempts, fallbacks, err)
	}
	var event api.Event
	_ = json.Unmarshal(rows[0].JSON, &event)
	report, _ := event.AsTransportEvent()
	if len(report.Payload.Measurements) != 6 {
		t.Fatalf("measurements=%+v", report.Payload.Measurements)
	}
	for _, measurement := range report.Payload.Measurements {
		if measurement.Operation == api.Fallback && measurement.Duration != "" {
			t.Fatal("invented a fallback duration")
		}
	}
	if api.ValidateEvent(rows[0].JSON) != nil {
		t.Fatalf("invalid report: %s", rows[0].JSON)
	}
}
