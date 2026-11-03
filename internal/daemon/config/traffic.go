package config

import (
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func (c Config) TrafficDefaults() trafficlimits.Limits {
	l := trafficlimits.Limits{Connections: c.TrafficDefaultConnections, Rate: c.TrafficDefaultRate,
		RatePer: c.TrafficDefaultRatePer, Burst: c.TrafficDefaultBurst,
		UploadBytes: c.TrafficDefaultUploadBytes, DownloadBytes: c.TrafficDefaultDownloadBytes,
		TotalConnections: c.TrafficDefaultTotalConnections, TotalUploadBytes: c.TrafficDefaultTotalUploadBytes,
		TotalDownloadBytes: c.TrafficDefaultTotalDownloadBytes}
	if l == (trafficlimits.Limits{}) {
		return trafficlimits.Default()
	}
	return l
}

func (c Config) TrafficCeiling() trafficlimits.Limits {
	l := trafficlimits.Limits{Connections: c.TrafficMaxConnections, Rate: c.TrafficMaxRate,
		RatePer: c.TrafficMaxRatePer, Burst: c.TrafficMaxBurst,
		UploadBytes: c.TrafficMaxUploadBytes, DownloadBytes: c.TrafficMaxDownloadBytes,
		TotalConnections: c.TrafficMaxTotalConnections, TotalUploadBytes: c.TrafficMaxTotalUploadBytes,
		TotalDownloadBytes: c.TrafficMaxTotalDownloadBytes}
	if l == (trafficlimits.Limits{}) {
		return trafficlimits.Ceiling()
	}
	return l
}

func (c Config) IngressTraffic() trafficlimits.IngressConfig {
	return trafficlimits.IngressConfig{Default: c.TrafficDefaults(), Ceiling: c.TrafficCeiling(),
		SourceConnections: c.TrafficSourceConnections, SourceRate: c.TrafficSourceRate, SourceBurst: c.TrafficSourceBurst,
		ProcessRate: c.TrafficProcessRate, ProcessBurst: c.TrafficProcessBurst,
		ProcessUpload: c.TrafficProcessUploadBytes, ProcessDownload: c.TrafficProcessDownloadBytes}
}

func (c Config) IngressPending() trafficlimits.PendingConfig {
	return trafficlimits.PendingConfig{Connections: c.PendingConnectionLimit, PublicURLConnections: c.PendingURLConnectionLimit,
		SourceConnections: c.PendingSourceConnectionLimit, Timeout: c.PendingTimeout,
		UploadBytes: c.PendingUploadBytes, DownloadBytes: c.PendingDownloadBytes,
		PublicURLRate: c.PendingURLRate, PublicURLBurst: c.PendingURLBurst,
		SourceRate: c.PendingSourceRate, SourceBurst: c.PendingSourceBurst}
}

// ValidateIngressTraffic resolves zero-valued local settings to bounded defaults.
// root configuration parsing belongs to Config, not to the traffic data plane.
func ValidateIngressTraffic(traffic trafficlimits.IngressConfig, pending trafficlimits.PendingConfig) (trafficlimits.IngressConfig, trafficlimits.PendingConfig, error) {
	t, err := traffic.Resolve()
	if err != nil {
		return t, pending, err
	}
	p, err := pending.Resolve()
	return t, p, err
}
