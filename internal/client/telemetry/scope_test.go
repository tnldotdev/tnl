package telemetry

import (
	"encoding/json"
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
