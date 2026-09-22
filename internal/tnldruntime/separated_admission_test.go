package tnldruntime

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

// Only admission settings belong in this evidence; never serialize the full
// process configuration, which includes credentials and database URLs.
type separatedAdmissionLimits struct {
	ClientHelloConnectionLimit       int     `json:"client_hello_connection_limit"`
	ChallengeConnectionLimit         int     `json:"challenge_connection_limit"`
	ChallengeHostnameConnectionLimit int     `json:"challenge_hostname_connection_limit"`
	SourceConnectionRate             float64 `json:"source_connection_rate"`
	SourceConnectionBurst            int     `json:"source_connection_burst"`
	VisitorConnectionLimit           int64   `json:"visitor_connection_limit"`
	RouteConnectionLimit             int64   `json:"route_connection_limit"`
	PublisherConnectionLimit         int64   `json:"publisher_connection_limit"`
	RelayStreamCapacity              int64   `json:"relay_stream_capacity"`
	QUICMaxIncomingStreams           int64   `json:"quic_max_incoming_streams"`
}

type separatedIngressAdmissionLimits struct {
	ClientHelloConnectionLimit       int     `json:"client_hello_connection_limit"`
	ChallengeConnectionLimit         int     `json:"challenge_connection_limit"`
	ChallengeHostnameConnectionLimit int     `json:"challenge_hostname_connection_limit"`
	SourceConnectionRate             float64 `json:"source_connection_rate"`
	SourceConnectionBurst            int     `json:"source_connection_burst"`
	VisitorConnectionLimit           int64   `json:"visitor_connection_limit"`
	RouteConnectionLimit             int64   `json:"route_connection_limit"`
}

type separatedRelayAdmissionLimits struct {
	PublisherConnectionLimit int64 `json:"publisher_connection_limit"`
	RelayStreamCapacity      int64 `json:"relay_stream_capacity"`
	QUICMaxIncomingStreams   int64 `json:"quic_max_incoming_streams"`
}

var runtimeLoadAdmission separatedAdmissionLimits

func init() {
	flag.IntVar(&runtimeLoadAdmission.ClientHelloConnectionLimit, "tnl-runtime-load-client-hello-connection-limit", ingress.DefaultClientHelloConnectionLimit, "maximum simultaneous ClientHello inspections")
	flag.IntVar(&runtimeLoadAdmission.ChallengeConnectionLimit, "tnl-runtime-load-challenge-connection-limit", ingress.DefaultChallengeConnectionLimit, "maximum concurrent route certificate checks")
	flag.IntVar(&runtimeLoadAdmission.ChallengeHostnameConnectionLimit, "tnl-runtime-load-challenge-hostname-connection-limit", ingress.DefaultChallengeHostnameConnectionLimit, "maximum concurrent certificate checks per hostname")
	flag.Float64Var(&runtimeLoadAdmission.SourceConnectionRate, "tnl-runtime-load-source-connection-rate", sourcelimiter.DefaultRate, "new connections/second per source on each ingress process")
	flag.IntVar(&runtimeLoadAdmission.SourceConnectionBurst, "tnl-runtime-load-source-connection-burst", sourcelimiter.DefaultBurst, "new connection burst per source on each ingress process")
	flag.Int64Var(&runtimeLoadAdmission.VisitorConnectionLimit, "tnl-runtime-load-visitor-connection-limit", 20000, "maximum visitor connections per ingress process")
	flag.Int64Var(&runtimeLoadAdmission.RouteConnectionLimit, "tnl-runtime-load-route-connection-limit", 500, "maximum visitor connections per route on each ingress process")
	flag.Int64Var(&runtimeLoadAdmission.PublisherConnectionLimit, "tnl-runtime-load-publisher-connection-limit", 1000, "maximum publisher connections per relay process")
	flag.Int64Var(&runtimeLoadAdmission.RelayStreamCapacity, "tnl-runtime-load-relay-stream-capacity", 4096, "maximum visitor streams per relay process")
	flag.Int64Var(&runtimeLoadAdmission.QUICMaxIncomingStreams, "tnl-runtime-load-quic-max-incoming-streams", 4096, "maximum incoming QUIC streams per publisher connection")
}

func (limits separatedAdmissionLimits) apply(cfg *tnldconfig.Config) {
	cfg.ClientHelloConnectionLimit = limits.ClientHelloConnectionLimit
	cfg.ChallengeConnectionLimit, cfg.ChallengeHostnameConnectionLimit = limits.ChallengeConnectionLimit, limits.ChallengeHostnameConnectionLimit
	cfg.SourceConnectionRate, cfg.SourceConnectionBurst = limits.SourceConnectionRate, limits.SourceConnectionBurst
	cfg.VisitorConnectionLimit, cfg.RouteConnectionLimit = limits.VisitorConnectionLimit, limits.RouteConnectionLimit
	cfg.PublisherConnectionLimit, cfg.RelayStreamCapacity = limits.PublisherConnectionLimit, limits.RelayStreamCapacity
	cfg.QUICMaxIncomingStreams = limits.QUICMaxIncomingStreams
}

func separatedAdmissionFrom(cfg tnldconfig.Config) separatedAdmissionLimits {
	return separatedAdmissionLimits{
		ClientHelloConnectionLimit: cfg.ClientHelloConnectionLimit,
		ChallengeConnectionLimit:   cfg.ChallengeConnectionLimit, ChallengeHostnameConnectionLimit: cfg.ChallengeHostnameConnectionLimit,
		SourceConnectionRate: cfg.SourceConnectionRate, SourceConnectionBurst: cfg.SourceConnectionBurst,
		VisitorConnectionLimit: cfg.VisitorConnectionLimit, RouteConnectionLimit: cfg.RouteConnectionLimit,
		PublisherConnectionLimit: cfg.PublisherConnectionLimit, RelayStreamCapacity: cfg.RelayStreamCapacity,
		QUICMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
	}
}

func (limits separatedAdmissionLimits) ingress() separatedIngressAdmissionLimits {
	return separatedIngressAdmissionLimits{
		ClientHelloConnectionLimit: limits.ClientHelloConnectionLimit,
		ChallengeConnectionLimit:   limits.ChallengeConnectionLimit, ChallengeHostnameConnectionLimit: limits.ChallengeHostnameConnectionLimit,
		SourceConnectionRate: limits.SourceConnectionRate, SourceConnectionBurst: limits.SourceConnectionBurst,
		VisitorConnectionLimit: limits.VisitorConnectionLimit, RouteConnectionLimit: limits.RouteConnectionLimit,
	}
}

func (limits separatedAdmissionLimits) relay() separatedRelayAdmissionLimits {
	return separatedRelayAdmissionLimits{
		PublisherConnectionLimit: limits.PublisherConnectionLimit, RelayStreamCapacity: limits.RelayStreamCapacity,
		QUICMaxIncomingStreams: limits.QUICMaxIncomingStreams,
	}
}

func recordSeparatedAdmission(t *testing.T, components map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(struct {
		Requested  separatedAdmissionLimits `json:"requested"`
		Components map[string]any           `json:"component_configuration"`
	}{runtimeLoadAdmission, components}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("/results", "admission-limits.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func verifySeparatedAdmission(t *testing.T) {
	t.Helper()
	components := make(map[string]any)
	for _, component := range []string{"ingress", "relay-a", "relay-b"} {
		var applied separatedAdmissionLimits
		separatedWait(t, component+".admission-limits", 15*time.Second, &applied)
		var matches bool
		if component == "ingress" {
			components[component] = applied.ingress()
			matches = applied.ingress() == runtimeLoadAdmission.ingress()
		} else {
			components[component] = applied.relay()
			matches = applied.relay() == runtimeLoadAdmission.relay()
		}
		recordSeparatedAdmission(t, components)
		if !matches {
			t.Fatalf("%s admission configuration = %+v; requested %+v", component, components[component], runtimeLoadAdmission)
		}
		t.Logf("separated_admission component=%s configuration=%+v", component, components[component])
	}
}
