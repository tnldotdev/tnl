package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type limitsCommand struct {
	Show limitsShowCommand `cmd:"" help:"Show the limits selected for a service's next publish run."`
}

type limitsShowCommand struct {
	remoteFlags `embed:""`
	Service     string           `arg:"" name:"service" help:"Configured project service."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type limitsShowResult struct {
	Version  int    `json:"version"`
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
	Traffic  struct {
		Selected  trafficlimits.Selection `json:"selected"`
		Effective trafficlimits.Limits    `json:"effective"`
		Default   trafficlimits.Limits    `json:"default"`
		Ceiling   trafficlimits.Limits    `json:"ceiling"`
	} `json:"traffic"`
	Publisher publisherLimitSummary `json:"publisher"`
}

type publisherLimitSummary struct {
	Unit        string `json:"unit"`
	Total       *int   `json:"total,omitempty"`
	Concurrency int    `json:"concurrency"`
	Rate        int    `json:"rate"`
	RatePer     string `json:"rate_per"`
	Burst       int    `json:"burst"`
}

func runLimitsShow(ctx context.Context, flags limitsShowCommand, project projectConfiguration, output io.Writer) error {
	if !project.Found() || len(project.Config.Services) == 0 {
		return failure.Wrap("show publication limits", failure.ProjectConfigMissing, errors.New("a configured project service is required"))
	}
	if _, found := project.Config.Services[flags.Service]; !found {
		return failure.Wrap("show publication limits", failure.ServiceNotConfigured, fmt.Errorf("service %q is not configured", flags.Service))
	}
	effective, err := project.EffectiveService(flags.Service)
	if err != nil {
		return err
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	server := flags.ServerURL
	if server == "" && effective.Server != nil {
		server = *effective.Server
	}
	server, err = clientserver.Select(ctx, state, server)
	if err != nil {
		return err
	}
	client, err := controlclient.New(server, nil, "")
	if err != nil {
		return err
	}
	discovery, err := client.Discovery(ctx)
	if err != nil {
		return err
	}
	return showLimitsForDiscovery(flags, effective, discovery, output)
}

func showLimitsForDiscovery(flags limitsShowCommand, effective config.TNL, discovery controlv1.ControlDiscovery, output io.Writer) error {
	if discovery.TrafficDefaults == nil || discovery.TrafficCeilings == nil {
		return failure.Wrap("read traffic policy", failure.ServerResponseInvalid, errors.New("server did not provide traffic defaults and ceilings"))
	}
	protocol := config.ServiceProtocol(effective.Publish)
	local := tunnelFlags{}
	if effective.Tunnel != nil {
		applyTunnelLimits(&local, effective.Tunnel.Limits, protocol)
	}
	selected, err := local.traffic()
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	defaults, ceiling := trafficFromAPI(*discovery.TrafficDefaults), trafficFromAPI(*discovery.TrafficCeilings)
	traffic, err := selected.Resolve(defaults, ceiling)
	if err != nil {
		return failure.Wrap("validate traffic limits", failure.InvalidTunnelFlags, err)
	}
	limits := local.limits()
	unit, concurrency, rate, burst := "requests", 64, 60, 60
	if protocol != "http" {
		unit, concurrency, rate, burst = "sessions", 24, 10, 20
	}
	if limits.Concurrency != 0 {
		concurrency = limits.Concurrency
	}
	period := time.Second
	if limits.RateRequests != 0 {
		rate, period, burst = limits.RateRequests, limits.RatePer, limits.RateRequests
		if limits.RateBurst != 0 {
			burst = limits.RateBurst
		}
	}
	result := limitsShowResult{Version: 1, Service: flags.Service, Protocol: protocol,
		Publisher: publisherLimitSummary{Unit: unit, Concurrency: concurrency, Rate: rate, RatePer: period.String(), Burst: burst}}
	if limits.Requests != 0 {
		result.Publisher.Total = &limits.Requests
	}
	result.Traffic.Selected, result.Traffic.Effective, result.Traffic.Default, result.Traffic.Ceiling = selected, traffic, defaults, ceiling
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	total := "unlimited"
	if result.Publisher.Total != nil {
		total = strconv.Itoa(*result.Publisher.Total)
	}
	return clioutput.Write(output, clioutput.Frame{Command: "tnl limits show", State: "next publish run", Blocks: []clioutput.Block{
		clioutput.Fields(
			clioutput.Field{Label: "service", Value: flags.Service + " (" + protocol + ")"},
			clioutput.Field{Label: "visitor connections", Value: strconv.Itoa(traffic.Connections) + " per ingress process"},
			clioutput.Field{Label: "new connections", Value: fmt.Sprintf("%d/%s (burst %d)", traffic.Rate, time.Duration(traffic.RatePer), traffic.Burst)},
			clioutput.Field{Label: "upload", Value: displayByteRate(traffic.UploadBytes)},
			clioutput.Field{Label: "download", Value: displayByteRate(traffic.DownloadBytes)},
			clioutput.Field{Label: "server max connections", Value: strconv.Itoa(ceiling.Connections)},
			clioutput.Field{Label: "server max new", Value: fmt.Sprintf("%d/%s (burst %d)", ceiling.Rate, time.Duration(ceiling.RatePer), ceiling.Burst)},
			clioutput.Field{Label: "server max upload", Value: displayByteRate(ceiling.UploadBytes)},
			clioutput.Field{Label: "server max download", Value: displayByteRate(ceiling.DownloadBytes)},
			clioutput.Field{Label: "tnl concurrency", Value: strconv.Itoa(concurrency) + " " + unit},
			clioutput.Field{Label: "tnl rate", Value: fmt.Sprintf("%d/%s (burst %d)", rate, period, burst)},
			clioutput.Field{Label: "tnl total", Value: total},
		),
		clioutput.Text("server ceilings still apply; ingress replicas do not share rate tokens."),
	}})
}

func trafficFromAPI(wire controlv1.PublishRunTrafficLimits) trafficlimits.Limits {
	return trafficlimits.Limits{Connections: wire.Connections, Rate: wire.Rate, RatePer: time.Duration(wire.RatePerNs),
		Burst: wire.Burst, UploadBytes: wire.UploadBytes, DownloadBytes: wire.DownloadBytes}
}

func displayByteRate(bytes int64) string {
	for _, unit := range []struct {
		name  string
		bytes int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if bytes >= unit.bytes && bytes%unit.bytes == 0 {
			return fmt.Sprintf("%d%s/s", bytes/unit.bytes, unit.name)
		}
	}
	return fmt.Sprintf("%dB/s", bytes)
}
