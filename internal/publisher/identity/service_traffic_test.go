package identity

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestNativeServiceTrafficSelectionsDoNotSharePointers(t *testing.T) {
	for _, worker := range []bool{false, true} {
		name := "declaration"
		if worker {
			name = "worker"
		}
		t.Run(name, func(t *testing.T) {
			native, control := privateScopeFixture(t)
			selection := &trafficlimits.Selection{
				Connections: new(48), Rate: new(3), RatePer: new("1m"), Burst: new(4),
				UploadBytes: new(int64(1 << 20)), DownloadBytes: new(int64(2 << 20)),
				TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(7)), TotalDownloadBytes: new(int64(8)),
			}
			want := &controlv1.TrafficSelection{
				Connections: new(48), Rate: new(3), RatePer: new("1m"), Burst: new(4),
				UploadBytes: new(int64(1 << 20)), DownloadBytes: new(int64(2 << 20)),
				TotalConnections: new(int64(0)), TotalUploadBytes: new(int64(7)), TotalDownloadBytes: new(int64(8)),
			}
			declaration := ServiceDeclaration(control.service)
			regions := []string{"us-east-1"}
			declaration.PreferredRegions = &regions
			if worker {
				var err error
				native, err = native.WithTraffic(selection)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				declaration.Traffic = &controlv1.TrafficSelection{
					Connections: selection.Connections, Rate: selection.Rate, RatePer: selection.RatePer, Burst: selection.Burst,
					UploadBytes: selection.UploadBytes, DownloadBytes: selection.DownloadBytes,
					TotalConnections: selection.TotalConnections, TotalUploadBytes: selection.TotalUploadBytes, TotalDownloadBytes: selection.TotalDownloadBytes,
				}
			}
			for range 2 {
				if _, err := native.PrepareServiceRun(t.Context(), control.service.Id, "retry", "access", declaration); err != nil {
					t.Fatal(err)
				}
				got := control.declarations[len(control.declarations)-1]
				if !reflect.DeepEqual(got.Traffic, want) || !reflect.DeepEqual(got.PreferredRegions, declaration.PreferredRegions) ||
					!sameServiceDeclaration(got, ServiceDeclaration(control.service)) {
					t.Fatal("service preparation lost explicit traffic, placement, or saved trust")
				}
				*got.Traffic.Connections, *got.Traffic.Rate, *got.Traffic.RatePer, *got.Traffic.Burst = 1, 1, "1s", 1
				*got.Traffic.UploadBytes, *got.Traffic.DownloadBytes = 1, 1
				*got.Traffic.TotalConnections, *got.Traffic.TotalUploadBytes, *got.Traffic.TotalDownloadBytes = 1, 1, 1
			}
			if *selection.Connections != 48 || *selection.RatePer != "1m" || *selection.TotalConnections != 0 {
				t.Fatal("control changed caller-owned traffic choices")
			}
		})
	}
}

func TestNativeServiceTrafficUsesOneExplicitSelectionWithoutDefaults(t *testing.T) {
	for _, test := range []struct {
		name      string
		worker    *trafficlimits.Selection
		requested *controlv1.TrafficSelection
		want      *controlv1.TrafficSelection
	}{
		{name: "omitted"},
		{name: "empty", requested: &controlv1.TrafficSelection{}, want: &controlv1.TrafficSelection{}},
		{
			name:      "matching-without-period",
			worker:    &trafficlimits.Selection{Connections: new(48)},
			requested: &controlv1.TrafficSelection{Connections: new(48)},
			want:      &controlv1.TrafficSelection{Connections: new(48)},
		},
		{
			name:      "matching",
			worker:    &trafficlimits.Selection{Connections: new(48), RatePer: new("1s")},
			requested: &controlv1.TrafficSelection{Connections: new(48), RatePer: new("1000ms")},
			want:      &controlv1.TrafficSelection{Connections: new(48), RatePer: new("1s")},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			native, control := privateScopeFixture(t)
			native, err := native.WithTraffic(test.worker)
			if err != nil {
				t.Fatal(err)
			}
			declaration := ServiceDeclaration(control.service)
			declaration.Traffic = test.requested
			if _, err := native.PrepareServiceRun(t.Context(), control.service.Id, "retry", "access", declaration); err != nil {
				t.Fatal(err)
			}
			if len(control.declarations) != 1 || !reflect.DeepEqual(control.declarations[0].Traffic, test.want) {
				t.Fatal("service preparation resolved defaults or discarded an explicit choice", control.declarations)
			}
			if test.requested != nil && test.requested.RatePer != nil && *test.requested.RatePer != "1000ms" {
				t.Fatal("comparison normalized the caller-owned duration")
			}
		})
	}
}

func TestNativeServiceTrafficRejectsConflictsAndInvalidChoices(t *testing.T) {
	for _, test := range []struct {
		name      string
		worker    *trafficlimits.Selection
		requested controlv1.TrafficSelection
		conflict  bool
	}{
		{"connections", &trafficlimits.Selection{Connections: new(48)}, controlv1.TrafficSelection{Connections: new(24)}, true},
		{"rate", &trafficlimits.Selection{Rate: new(3)}, controlv1.TrafficSelection{Rate: new(4)}, true},
		{"period", &trafficlimits.Selection{RatePer: new("1s")}, controlv1.TrafficSelection{RatePer: new("2s")}, true},
		{"burst", &trafficlimits.Selection{Burst: new(4)}, controlv1.TrafficSelection{Burst: new(5)}, true},
		{"upload", &trafficlimits.Selection{UploadBytes: new(int64(1 << 20))}, controlv1.TrafficSelection{UploadBytes: new(int64(2 << 20))}, true},
		{"download", &trafficlimits.Selection{DownloadBytes: new(int64(1 << 20))}, controlv1.TrafficSelection{DownloadBytes: new(int64(2 << 20))}, true},
		{"connection-total", &trafficlimits.Selection{TotalConnections: new(int64(1))}, controlv1.TrafficSelection{TotalConnections: new(int64(0))}, true},
		{"upload-total", &trafficlimits.Selection{TotalUploadBytes: new(int64(1))}, controlv1.TrafficSelection{TotalUploadBytes: new(int64(2))}, true},
		{"download-total", &trafficlimits.Selection{TotalDownloadBytes: new(int64(1))}, controlv1.TrafficSelection{TotalDownloadBytes: new(int64(2))}, true},
		{"disjoint", &trafficlimits.Selection{Connections: new(48)}, controlv1.TrafficSelection{TotalConnections: new(int64(0))}, true},
		{"omitted-connection", &trafficlimits.Selection{}, controlv1.TrafficSelection{Connections: new(32)}, true},
		{"explicit-connection", &trafficlimits.Selection{Connections: new(32)}, controlv1.TrafficSelection{}, true},
		{"omitted-period", &trafficlimits.Selection{}, controlv1.TrafficSelection{RatePer: new("1s")}, true},
		{"explicit-period", &trafficlimits.Selection{RatePer: new("1s")}, controlv1.TrafficSelection{}, true},
		{"omitted-total", &trafficlimits.Selection{}, controlv1.TrafficSelection{TotalConnections: new(int64(0))}, true},
		{"explicit-total", &trafficlimits.Selection{TotalConnections: new(int64(0))}, controlv1.TrafficSelection{}, true},
		{"invalid-connections", nil, controlv1.TrafficSelection{Connections: new(0)}, false},
		{"invalid-period", nil, controlv1.TrafficSelection{RatePer: new("0s")}, false},
		{"invalid-total", nil, controlv1.TrafficSelection{TotalConnections: new(int64(-1))}, false},
		{"invalid-declaration-with-worker", &trafficlimits.Selection{Connections: new(48)}, controlv1.TrafficSelection{RatePer: new("invalid")}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			native, control := privateScopeFixture(t)
			native, err := native.WithTraffic(test.worker)
			if err != nil {
				t.Fatal(err)
			}
			declaration := ServiceDeclaration(control.service)
			declaration.Traffic = &test.requested
			_, err = native.PrepareServiceRun(t.Context(), control.service.Id, "retry", "access", declaration)
			if err == nil || test.conflict && !errors.Is(err, ErrScope) || len(control.declarations) != 0 {
				t.Fatal("conflicting or invalid traffic reached service preparation", err, control.declarations)
			}
		})
	}
}
