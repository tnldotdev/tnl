package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestScopesKeepPublicAndNativeReportsSeparate(t *testing.T) {
	c := &Collector{scopes: make(map[*Scope]struct{})}
	c.preference.Store(&clientstate.TelemetryPreference{Enabled: true, Epoch: 1})
	public := c.BeginScope(Public, false)
	native := c.BeginScope(Native, false)
	if public == nil || native == nil || c.BeginScope(Native, true) != nil {
		t.Fatal("scopes failed independent opt-out")
	}
	public.Observe(PublicUDP, 256, 512, time.Second, 0)
	public.Observe(NativeDirect, 8192, 8192, time.Second, time.Second) // wrong kind is ignored
	public.DirectAttempt(true, time.Second)                            // public never collects ICE
	native.Observe(NativeRelayTCP, 0, 64, time.Second, 7*time.Millisecond)
	native.DirectAttempt(true, 12*time.Millisecond)
	native.Fallback(api.UdpBlocked)
	for _, scope := range []*Scope{public, native} {
		wire := scope.snapshot(time.Now())
		if wire == nil {
			t.Fatal("measured scope did not produce a report")
		}
		event, err := wire("tev_0123456789abcdefghijkl")
		encoded, encodeErr := json.Marshal(event)
		if err != nil || encodeErr != nil || api.ValidateEvent(encoded) != nil {
			t.Fatalf("report violates contract: %s %v %v", encoded, err, encodeErr)
		}
		publisher, err := event.AsPublisherEvent()
		if err != nil {
			t.Fatal(err)
		}
		if scope == public {
			report, err := publisher.Payload.AsPublicReport()
			if err != nil || len(report.Paths) != 1 || report.Paths[0].Path != api.PublicUdp || report.Paths[0].Rtt != nil {
				t.Fatalf("public reported unmeasured RTT or native data: %+v %v", report, err)
			}
		} else {
			report, err := publisher.Payload.AsNativeReport()
			if err != nil || len(report.Paths) != 1 || report.Paths[0].Path != api.NativeRelayTcp || report.DirectSetupAttempts == nil || *report.DirectSetupAttempts != 1 || report.DirectEstablishment == nil || len(*report.DirectEstablishment) != 12 {
				t.Fatalf("native report lost measured fields: %+v %v", report, err)
			}
		}
	}
}

func TestScopeFinalCloseCapturesMeasuredReportOnceAndKeepsEpochPrivacy(t *testing.T) {
	for _, closeScope := range []bool{false, true} {
		for _, reset := range []bool{false, true} {
			t.Run(fmt.Sprintf("scope_close=%t/reset=%t", closeScope, reset), func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "state")
				var batches []api.Batch
				c, err := New(t.Context(), Config{Root: root, Protection: clientstate.ProtectionFile, FlushInterval: time.Hour,
					Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
						body, err := io.ReadAll(request.Body)
						if err != nil {
							return nil, err
						}
						if err := api.ValidateBatch(body); err != nil {
							t.Error("final scope batch violates privacy contract", err)
						}
						var batch api.Batch
						if err := json.Unmarshal(body, &batch); err != nil {
							return nil, err
						}
						batches = append(batches, batch)
						return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody}, nil
					})}})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close(context.Background())
				database, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
				if err != nil {
					t.Fatal(err)
				}
				defer database.Close()
				s := c.BeginScope(Public, false)
				s.Observe(PublicTCP, 256, 512, time.Second, 7*time.Millisecond)
				if reset {
					for _, enabled := range []bool{false, true} {
						if err := database.SetTelemetryEnabled(t.Context(), enabled); err != nil {
							t.Fatal(err)
						}
					}
				}
				if closeScope {
					s.Close()
					s.Observe(PublicTCP, 1<<30, 1<<30, time.Hour, time.Hour)
				}
				c.Close(context.Background())
				s.Close()
				c.Close(context.Background())
				if len(c.scopes) != 0 {
					t.Fatal("final close retained a retired scope")
				}
				items, err := database.PendingTelemetryEvents(t.Context(), 25)
				if reset {
					if err != nil || len(items) != 0 || len(batches) != 0 {
						t.Fatalf("final close revived old epoch measurements: %+v %v", items, err)
					}
					return
				}
				if err != nil || len(items) != 1 {
					t.Fatalf("final measured report was lost or duplicated: %+v %v", items, err)
				}
				if len(batches) == 0 {
					t.Fatal("final outbox report was not delivered to the batch sender")
				}
				for _, batch := range batches {
					if len(batch.Events) != 1 {
						t.Fatalf("final scope batch duplicated reports: %+v", batch.Events)
					}
					publisher, err := batch.Events[0].AsPublisherEvent()
					if err != nil || publisher.EventId != items[0].ID {
						t.Fatalf("final scope retry created a second report: %+v %v", publisher, err)
					}
				}
				if err := api.ValidateEvent(items[0].JSON); err != nil {
					t.Fatal(err)
				}
				var event api.Event
				if err := json.Unmarshal(items[0].JSON, &event); err != nil {
					t.Fatal(err)
				}
				publisher, err := event.AsPublisherEvent()
				if err != nil {
					t.Fatal(err)
				}
				report, err := publisher.Payload.AsPublicReport()
				if err != nil || len(report.Paths) != 1 {
					t.Fatalf("lost measured public path: %+v %v", report, err)
				}
				path := report.Paths[0]
				if path.Path != api.PublicTcp || path.Sent == nil || *path.Sent != api.VolumeBucketLt64kib || path.Received == nil || *path.Received != api.VolumeBucketLt64kib || path.Rtt == nil {
					t.Fatalf("final report changed captured measurements: %+v", path)
				}
				total := int64(0)
				for _, count := range *path.Rtt {
					total += count
				}
				if total != 1 {
					t.Fatalf("RTT sample count = %d, want 1", total)
				}
			})
		}
	}
}

func TestScopeCollectorCloseCancelsFinalDeliveryAndJoins(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	entered := make(chan struct{})
	c, err := New(t.Context(), Config{Root: root, Protection: clientstate.ProtectionFile, FlushInterval: time.Hour,
		Client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			close(entered)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	s := c.BeginScope(Public, false)
	s.Observe(PublicUDP, 1, 2, time.Second, 0)
	flush, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { c.Close(flush); close(done) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("collector close did not capture and send its final scope")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector did not join canceled final delivery")
	}
	select {
	case <-c.done:
	default:
		t.Fatal("close returned before collector workers joined")
	}
	database, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if items, err := database.PendingTelemetryEvents(t.Context(), 25); err != nil || len(items) != 1 {
		t.Fatalf("canceled delivery lost its final outbox report: %+v %v", items, err)
	}
}

func TestScopePreferenceResetDiscardsOldWindow(t *testing.T) {
	c := &Collector{scopes: make(map[*Scope]struct{})}
	c.preference.Store(&clientstate.TelemetryPreference{Enabled: true, Epoch: 1})
	s := c.BeginScope(Public, false)
	s.Observe(PublicTCP, 100, 200, time.Second, 0)
	off := clientstate.TelemetryPreference{Enabled: false, Epoch: 2}
	c.preference.Store(&off)
	c.resetScopes(off)
	s.Observe(PublicTCP, 200, 300, time.Second, 0)
	on := clientstate.TelemetryPreference{Enabled: true, Epoch: 3}
	c.preference.Store(&on)
	c.resetScopes(on)
	if s.snapshot(time.Now()) != nil {
		t.Fatal("old or disabled-period measurement survived opt-out")
	}
	s.Observe(PublicTCP, 1, 2, time.Second, 0)
	if s.snapshot(time.Now()) == nil {
		t.Fatal("new window did not collect after opt-in")
	}
	for range maximumScopes - 1 {
		if c.BeginScope(Public, false) == nil {
			t.Fatal("scope capacity exhausted too early")
		}
	}
	if c.BeginScope(Public, false) != nil {
		t.Fatal("unbounded number of active scopes")
	}
	s.Close()
	// a closed scope is retired by capture even if it had no new observations.
	c.resetScopes(on)
	if c.BeginScope(Public, false) == nil {
		t.Fatal("closed scope retained capacity")
	}
}
