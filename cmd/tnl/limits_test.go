package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestLimitsShowUsesServerDefaultsWithProjectOverrides(t *testing.T) {
	var command cli
	parser, err := kong.New(&command)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := parser.Parse([]string{"limits", "show", "web", "--output=json"})
	if err != nil || selected.Command() != "limits show <service>" || command.Limits.Show.Service != "web" {
		t.Fatalf("limits command = %v, %+v", err, command.Limits.Show)
	}
	connections, count := 16, 10
	period := config.Duration(time.Second)
	upload := config.ByteRate("4MiB/s")
	concurrency := 24
	effective := config.TNL{Tunnel: &config.Tunnel{Limits: &config.Limits{
		Traffic: &config.TrafficLimits{Connections: &connections, Rate: &config.Rate{Count: &count, Per: &period},
			Bandwidth: &config.Bandwidth{Upload: &upload}},
		HTTP: &config.WorkLimits{Concurrency: &concurrency},
	}}}
	server := controlv1.ControlDiscovery{
		TrafficDefaults: &controlv1.PublishRunTrafficLimits{Connections: 32, Rate: 20, RatePerNs: int64(time.Second),
			Burst: 40, UploadBytes: 8 << 20, DownloadBytes: 16 << 20},
		TrafficCeilings: &controlv1.PublishRunTrafficLimits{Connections: 128, Rate: 100, RatePerNs: int64(time.Second),
			Burst: 200, UploadBytes: 64 << 20, DownloadBytes: 128 << 20},
	}
	flags := limitsShowCommand{Service: "web", Output: statusOutputJSON}
	var output bytes.Buffer
	if err := showLimitsForDiscovery(flags, effective, server, &output); err != nil {
		t.Fatal(err)
	}
	var shown limitsShowResult
	if err := json.Unmarshal(output.Bytes(), &shown); err != nil || shown.Version != 1 || shown.Service != "web" ||
		shown.Protocol != "http" || shown.Traffic.Effective.Connections != 16 ||
		shown.Traffic.Effective.Rate != 10 || shown.Traffic.Effective.Burst != 40 ||
		shown.Traffic.Effective.UploadBytes != 4<<20 || shown.Traffic.Effective.DownloadBytes != 16<<20 ||
		shown.Publisher.Concurrency != 24 || shown.Publisher.Rate != 60 {
		t.Fatalf("shown limits = %+v, %v", shown, err)
	}
	flags.Output = statusOutputHuman
	output.Reset()
	if err := showLimitsForDiscovery(flags, effective, server, &output); err != nil || output.Len() == 0 {
		t.Fatalf("human limits = %q, %v", output.String(), err)
	}
}
