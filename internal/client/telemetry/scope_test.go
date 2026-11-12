package telemetry

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestTelemetryScopeKeepsPublicationFactsOnceAndImmutable(t *testing.T) {
	c := collectorForTest(t, Config{})
	s := c.BeginScope("publisher")
	defer s.Close()
	framework := api.PublicationReadyFrameworkVite
	s.Ready(api.PublicationReady{ServerKind: api.Hosted, PublishMode: api.Demo, Framework: &framework})
	framework = api.PublicationReadyFrameworkNext
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 20 {
				s.Demo()
				s.Integration(api.IntegrationOutcome{Kind: "oauth", Outcome: api.Ready})
				s.Integration(api.IntegrationOutcome{Kind: "oauth", Outcome: api.Redirected})
				delivery := api.Selected
				s.Integration(api.IntegrationOutcome{Kind: "webhook", Outcome: api.Ready, Delivery: &delivery})
				s.Integration(api.IntegrationOutcome{Kind: "webhook", Outcome: api.ReachedReceiver, Delivery: &delivery})
				delivery = api.Fanout
			}
		})
	}
	workers.Wait()
	s.Close()
	flushForTest(t, c)
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 6 {
		t.Fatalf("facts=%d err=%v", len(rows), err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if api.ValidateCollectedEvent(row.JSON) != nil {
			t.Fatalf("invalid event: %s", row.JSON)
		}
		var collected api.CollectedEvent
		if err := json.Unmarshal(row.JSON, &collected); err != nil {
			t.Fatal(err)
		}
		name, _ := collected.Event.Discriminator()
		key := name
		switch name {
		case "tunnel.ready":
			ready, _ := collected.Event.AsReadyEvent()
			if ready.Payload.Framework == nil || *ready.Payload.Framework != api.PublicationReadyFrameworkVite || ready.Payload.PublishMode != api.Demo {
				t.Fatalf("ready=%+v", ready)
			}
		case "integration.outcome":
			integration, _ := collected.Event.AsIntegrationEvent()
			key += "/" + string(integration.Payload.Kind) + "/" + string(integration.Payload.Outcome)
			if integration.Payload.Kind == "oauth" && integration.Payload.Delivery != nil {
				t.Fatal("OAuth carried delivery context")
			}
			if integration.Payload.Kind == "webhook" && (integration.Payload.Delivery == nil || *integration.Payload.Delivery != api.Selected) {
				t.Fatal("caller mutated a collected delivery")
			}
		}
		if seen[key] {
			t.Fatalf("duplicate %s", key)
		}
		seen[key] = true
	}
	c.scopesMu.Lock()
	defer c.scopesMu.Unlock()
	if len(c.scopes) != 0 {
		t.Fatal("closed scope remains registered")
	}
}

func TestTelemetryCollectorDrainsMoreScopesThanQueueCapacity(t *testing.T) {
	delivered := 0
	c := collectorForTest(t, Config{Client: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		var batch api.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		delivered += len(batch.Events)
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}})
	for range 80 {
		s := c.BeginScope("connector")
		defer s.Close()
		s.Record(api.RelayConnect, api.Quic, api.Succeeded, time.Second)
	}
	for range 4 {
		flushForTest(t, c)
	}
	if delivered != 80 {
		t.Fatalf("collector dropped scope reports: %d", delivered)
	}
}

func TestTelemetryRepeatedEnableKeepsScopeCountersAndPendingRetry(t *testing.T) {
	c := collectorForTest(t, Config{})
	c.Report(Demo())
	flushForTest(t, c)
	s := c.BeginScope("publisher")
	s.Record(api.RelayConnect, api.Quic, api.Succeeded, time.Second)
	before, err := c.state.TelemetryPreference(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.state.SetTelemetryEnabled(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	c.refreshPreference()
	if after := *c.preference.Load(); after != before {
		t.Fatalf("idempotent enable changed preference: %+v -> %+v", before, after)
	}
	s.Close()
	flushForTest(t, c)
	rows, err := c.state.PendingTelemetryEvents(t.Context(), 25)
	if err != nil || len(rows) != 2 {
		t.Fatalf("lost pending event/counters: %d %v", len(rows), err)
	}
}

func TestTelemetryScopeCloseRacesCollectionAndCollectorDrain(t *testing.T) {
	c := collectorForTest(t, Config{})
	s := c.BeginScope("publisher")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				s.Record(api.RelayConnect, api.Quic, api.Succeeded, time.Second)
				s.Integration(api.IntegrationOutcome{Kind: "oauth", Outcome: api.Ready})
			}
		})
	}
	workers.Go(func() {
		for range 20 {
			c.flushScopes()
		}
	})
	workers.Go(s.Close)
	workers.Go(s.Close)
	workers.Wait()
	flushForTest(t, c)
}
