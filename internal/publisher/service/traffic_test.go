package service

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func serviceTrafficFixture() controlv1.TrafficLimits {
	return controlv1.TrafficLimits{
		Connections: 32, Rate: 20, RatePerNs: int64(time.Second), Burst: 40,
		UploadBytes: 8 << 20, DownloadBytes: 16 << 20,
	}
}

func TestServiceTrafficApprovalRejectsMissingOrInvalidLimits(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.TrafficLimits)
	}{
		{"missing", func(l *controlv1.TrafficLimits) { *l = controlv1.TrafficLimits{} }},
		{"connections", func(l *controlv1.TrafficLimits) { l.Connections = 0 }},
		{"connections-overflow", func(l *controlv1.TrafficLimits) { l.Connections = 1<<20 + 1 }},
		{"rate", func(l *controlv1.TrafficLimits) { l.Rate = 0 }},
		{"rate-overflow", func(l *controlv1.TrafficLimits) { l.Rate = 1<<31 + 1 }},
		{"period-omitted", func(l *controlv1.TrafficLimits) { l.RatePerNs = 0 }},
		{"period-small", func(l *controlv1.TrafficLimits) { l.RatePerNs = int64(time.Millisecond) - 1 }},
		{"period-large", func(l *controlv1.TrafficLimits) { l.RatePerNs = int64(24*time.Hour) + 1 }},
		{"burst", func(l *controlv1.TrafficLimits) { l.Burst = 0 }},
		{"burst-overflow", func(l *controlv1.TrafficLimits) { l.Burst = 1<<31 + 1 }},
		{"upload", func(l *controlv1.TrafficLimits) { l.UploadBytes = 64<<10 - 1 }},
		{"upload-overflow", func(l *controlv1.TrafficLimits) { l.UploadBytes = 1<<40 + 1 }},
		{"download", func(l *controlv1.TrafficLimits) { l.DownloadBytes = 64<<10 - 1 }},
		{"download-overflow", func(l *controlv1.TrafficLimits) { l.DownloadBytes = 1<<40 + 1 }},
		{"zero-connection-total", func(l *controlv1.TrafficLimits) { l.TotalConnections = new(int64(0)) }},
		{"negative-connection-total", func(l *controlv1.TrafficLimits) { l.TotalConnections = new(int64(-1)) }},
		{"zero-upload-total", func(l *controlv1.TrafficLimits) { l.TotalUploadBytes = new(int64(0)) }},
		{"negative-upload-total", func(l *controlv1.TrafficLimits) { l.TotalUploadBytes = new(int64(-1)) }},
		{"zero-download-total", func(l *controlv1.TrafficLimits) { l.TotalDownloadBytes = new(int64(0)) }},
		{"negative-download-total", func(l *controlv1.TrafficLimits) { l.TotalDownloadBytes = new(int64(-1)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			approved := serviceTrafficFixture()
			test.change(&approved)
			if _, err := serviceTraffic(approved); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("invalid control approval accepted or defaulted", err)
			}
		})
	}
}

func TestServiceTrafficApprovalDoesNotApplyLocalDefaultsOrCeilings(t *testing.T) {
	approved := serviceTrafficFixture()
	approved.Connections, approved.Rate, approved.RatePerNs, approved.Burst = 256, 200, int64(2*time.Second), 400
	approved.UploadBytes, approved.DownloadBytes = 128<<20, 256<<20
	approved.TotalConnections, approved.TotalUploadBytes, approved.TotalDownloadBytes = new(int64(7)), new(int64(8)), new(int64(9))
	want := trafficlimits.Limits{Connections: 256, Rate: 200, RatePer: 2 * time.Second, Burst: 400,
		UploadBytes: 128 << 20, DownloadBytes: 256 << 20, TotalConnections: 7, TotalUploadBytes: 8, TotalDownloadBytes: 9}
	if got, err := serviceTraffic(approved); err != nil || got != want {
		t.Fatal("publisher re-resolved a valid control approval", got, err)
	}
}

func TestServiceTrafficApprovalSurvivesEndpointAndSlotChanges(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	preparation := control.prep
	preparation.Traffic.TotalConnections = new(int64(3))
	preparation.Traffic.TotalUploadBytes = new(int64(4))
	preparation.Traffic.TotalDownloadBytes = new(int64(5))
	want, err := serviceTraffic(preparation.Traffic)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []controlv1.ServiceEndpoint{
		{Hostname: preparation.Hostname, Port: 25443, Public: true},
		{Hostname: preparation.Hostname, Port: 25443},
		{Hostname: preparation.Hostname, Port: 0},
		{Hostname: preparation.Hostname, Port: 25444, Public: true},
	} {
		approved.Endpoint = &endpoint
		approved.EndpointRevision++
		prepared, err := newManagedPrepared(preparation, approved, cfg)
		if err != nil {
			t.Fatal("endpoint change rejected retained traffic approval", err)
		}
		bound, err := prepared.Activate(control.setup)
		if err != nil {
			t.Fatal(err)
		}
		original := bound.prepared.connectionRef(bound.connections[0])
		replacement := bound.connections[0]
		replacement.PublisherConnectionId, err = opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			t.Fatal(err)
		}
		replacement.ConnectionAssignmentRevision++
		replacement.RelayServiceId, replacement.RelayAddress, replacement.TlsServerName = "replacement", "replacement.example:443", "replacement.example"
		state := controlv1.ServiceRunState{ServiceId: preparation.ServiceId, ServiceRunId: preparation.ServiceRunId,
			RunNumber: preparation.RunNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute),
			PublisherConnections: []controlv1.ConnectionAssignment{replacement, bound.connections[1]}}
		if err := bound.ApplyHeartbeat(state); err != nil {
			t.Fatal(err)
		}
		retained, err := serviceTraffic(bound.prepared.Preparation.Traffic)
		if err != nil || retained != want || bound.prepared.traffic != want || bound.current(original) {
			t.Fatal("endpoint or slot replacement changed run traffic approval", retained, err)
		}
	}
	prepared, err := newManagedPrepared(preparation, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	*preparation.Traffic.TotalConnections, *preparation.Traffic.TotalUploadBytes, *preparation.Traffic.TotalDownloadBytes = -1, -1, -1
	if _, err := prepared.Activate(control.setup); err != nil || prepared.traffic != want {
		t.Fatal("control response pointers changed retained approval", err)
	}
}

func TestServiceActivationRejectsMissingOrChangedTrafficApproval(t *testing.T) {
	for _, change := range []string{"missing", "changed", "snapshot"} {
		t.Run(change, func(t *testing.T) {
			prepared, bound, _, _ := privateFixture(t, "127.0.0.1:1")
			setup := controlv1.ServiceRunSetup{ServiceId: prepared.Preparation.ServiceId, ServiceRunId: prepared.Preparation.ServiceRunId,
				RunNumber: prepared.Preparation.RunNumber, RunToken: "run-token",
				PublisherConnections: []controlv1.ConnectionAssignment{bound.connections[0], bound.connections[1]}}
			switch change {
			case "missing":
				prepared.Preparation.Traffic = controlv1.TrafficLimits{}
			case "changed":
				prepared.Preparation.Traffic.Connections++
			case "snapshot":
				prepared.traffic = trafficlimits.Limits{}
			}
			if _, err := prepared.Activate(setup); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("activation accepted missing or replaced run approval", err)
			}
		})
	}
}

func TestServiceTrafficApprovalDoesNotReplacePhysicalCapacity(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	control.prep.Traffic.Connections = 1
	control.prep.Traffic.TotalConnections = new(int64(1))
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := prepared.Activate(control.setup)
	if err != nil {
		t.Fatal(err)
	}
	bound.streamCapacity = 2
	ref := prepared.connectionRef(bound.connections[0])
	for range 2 {
		first, ok := bound.reserveStream(ref)
		if !ok {
			t.Fatal("traffic total replaced physical capacity")
		}
		second, ok := bound.reserveStream(ref)
		if !ok {
			t.Fatal("per-ingress traffic concurrency changed shared publisher capacity")
		}
		if release, ok := bound.reserveStream(ref); ok {
			release()
			t.Fatal("physical capacity was bypassed")
		}
		first()
		second()
	}
	if bound.reservedStreams != 0 {
		t.Fatal("physical capacity was not released")
	}
}
