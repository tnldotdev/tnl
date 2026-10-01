package tnldruntime

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

// only admission settings belong in this evidence; never serialize the full
// process configuration, which includes credentials and database URLs.
type separatedAdmissionLimits struct {
	ClientHelloConnectionLimit       int   `json:"client_hello_connection_limit"`
	ChallengeConnectionLimit         int   `json:"challenge_connection_limit"`
	ChallengeHostnameConnectionLimit int   `json:"challenge_hostname_connection_limit"`
	VisitorConnectionLimit           int64 `json:"visitor_connection_limit"`
	PublisherConnectionLimit         int64 `json:"publisher_connection_limit"`
	RelayStreamCapacity              int64 `json:"relay_stream_capacity"`
	QUICMaxIncomingStreams           int64 `json:"quic_max_incoming_streams"`
	PublisherRequestLimit            int   `json:"publisher_request_limit"`
}

type separatedIngressAdmissionLimits struct {
	ClientHelloConnectionLimit       int   `json:"client_hello_connection_limit"`
	ChallengeConnectionLimit         int   `json:"challenge_connection_limit"`
	ChallengeHostnameConnectionLimit int   `json:"challenge_hostname_connection_limit"`
	VisitorConnectionLimit           int64 `json:"visitor_connection_limit"`
}

type separatedRelayAdmissionLimits struct {
	PublisherConnectionLimit int64 `json:"publisher_connection_limit"`
	RelayStreamCapacity      int64 `json:"relay_stream_capacity"`
	QUICMaxIncomingStreams   int64 `json:"quic_max_incoming_streams"`
}

var runtimeLoadAdmission separatedAdmissionLimits

func init() {
	flag.IntVar(&runtimeLoadAdmission.ClientHelloConnectionLimit, "tnl-runtime-load-client-hello-connection-limit", -1, "maximum simultaneous ClientHello inspections (-1: automatic)")
	flag.IntVar(&runtimeLoadAdmission.ChallengeConnectionLimit, "tnl-runtime-load-challenge-connection-limit", -1, "maximum concurrent public URL certificate checks (-1: automatic)")
	flag.IntVar(&runtimeLoadAdmission.ChallengeHostnameConnectionLimit, "tnl-runtime-load-challenge-hostname-connection-limit", ingress.DefaultChallengeHostnameConnectionLimit, "maximum concurrent certificate checks per hostname")
	flag.Int64Var(&runtimeLoadAdmission.VisitorConnectionLimit, "tnl-runtime-load-visitor-connection-limit", -1, "maximum visitor connections per ingress process (-1: automatic)")
	flag.Int64Var(&runtimeLoadAdmission.PublisherConnectionLimit, "tnl-runtime-load-publisher-connection-limit", -1, "maximum publisher connections per relay process (-1: automatic)")
	flag.Int64Var(&runtimeLoadAdmission.RelayStreamCapacity, "tnl-runtime-load-relay-stream-capacity", -1, "maximum visitor streams per relay process (-1: automatic)")
	flag.Int64Var(&runtimeLoadAdmission.QUICMaxIncomingStreams, "tnl-runtime-load-quic-max-incoming-streams", -1, "maximum incoming QUIC streams per publisher connection (-1: automatic)")
	flag.IntVar(&runtimeLoadAdmission.PublisherRequestLimit, "tnl-runtime-load-publisher-request-limit", 500, "maximum concurrent requests handled by each publisher route")
}

func (limits separatedAdmissionLimits) apply(cfg *tnldconfig.Config) {
	cfg.ClientHelloConnectionLimit = limits.ClientHelloConnectionLimit
	cfg.ChallengeConnectionLimit, cfg.ChallengeHostnameConnectionLimit = limits.ChallengeConnectionLimit, limits.ChallengeHostnameConnectionLimit
	cfg.VisitorConnectionLimit = limits.VisitorConnectionLimit
	cfg.PublisherConnectionLimit, cfg.RelayStreamCapacity = limits.PublisherConnectionLimit, limits.RelayStreamCapacity
	cfg.QUICMaxIncomingStreams = limits.QUICMaxIncomingStreams
}

func separatedAdmissionFrom(cfg tnldconfig.Config) separatedAdmissionLimits {
	return separatedAdmissionLimits{
		ClientHelloConnectionLimit: cfg.ClientHelloConnectionLimit,
		ChallengeConnectionLimit:   cfg.ChallengeConnectionLimit, ChallengeHostnameConnectionLimit: cfg.ChallengeHostnameConnectionLimit,
		VisitorConnectionLimit:   cfg.VisitorConnectionLimit,
		PublisherConnectionLimit: cfg.PublisherConnectionLimit, RelayStreamCapacity: cfg.RelayStreamCapacity,
		QUICMaxIncomingStreams: cfg.QUICMaxIncomingStreams,
	}
}

func (limits separatedAdmissionLimits) ingress() separatedIngressAdmissionLimits {
	return separatedIngressAdmissionLimits{
		ClientHelloConnectionLimit: limits.ClientHelloConnectionLimit,
		ChallengeConnectionLimit:   limits.ChallengeConnectionLimit, ChallengeHostnameConnectionLimit: limits.ChallengeHostnameConnectionLimit,
		VisitorConnectionLimit: limits.VisitorConnectionLimit,
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
	for shard, component := range separatedPublisherComponents() {
		var publisherLimit int
		separatedWait(t, separatedPublisherShardKey(shard, "request-limit"), 15*time.Second, &publisherLimit)
		if publisherLimit != runtimeLoadAdmission.PublisherRequestLimit {
			t.Fatalf("%s request limit = %d, want %d", component, publisherLimit, runtimeLoadAdmission.PublisherRequestLimit)
		}
		components[component] = map[string]int{"request_limit": publisherLimit}
	}
	for _, component := range append(separatedIngresses(), "relay-a", "relay-b") {
		var applied separatedAdmissionLimits
		separatedWait(t, component+".admission-limits", 15*time.Second, &applied)
		var matches bool
		if component == "ingress-a" || component == "ingress-b" {
			components[component] = applied.ingress()
			matches = (runtimeLoadAdmission.ClientHelloConnectionLimit == -1 || applied.ClientHelloConnectionLimit == runtimeLoadAdmission.ClientHelloConnectionLimit) &&
				(runtimeLoadAdmission.ChallengeConnectionLimit == -1 || applied.ChallengeConnectionLimit == runtimeLoadAdmission.ChallengeConnectionLimit) &&
				applied.ChallengeHostnameConnectionLimit == runtimeLoadAdmission.ChallengeHostnameConnectionLimit &&
				(runtimeLoadAdmission.VisitorConnectionLimit == -1 || applied.VisitorConnectionLimit == runtimeLoadAdmission.VisitorConnectionLimit) &&
				applied.VisitorConnectionLimit > 0 && applied.ClientHelloConnectionLimit > 0 && applied.ChallengeConnectionLimit > 0
		} else {
			components[component] = applied.relay()
			matches = (runtimeLoadAdmission.PublisherConnectionLimit == -1 || applied.PublisherConnectionLimit == runtimeLoadAdmission.PublisherConnectionLimit) &&
				(runtimeLoadAdmission.RelayStreamCapacity == -1 || applied.RelayStreamCapacity == runtimeLoadAdmission.RelayStreamCapacity) &&
				(runtimeLoadAdmission.QUICMaxIncomingStreams == -1 || applied.QUICMaxIncomingStreams == runtimeLoadAdmission.QUICMaxIncomingStreams) &&
				applied.PublisherConnectionLimit > 0 && applied.RelayStreamCapacity > 0 && applied.QUICMaxIncomingStreams > 0
		}
		recordSeparatedAdmission(t, components)
		if !matches {
			t.Fatalf("%s admission configuration = %+v; requested %+v", component, components[component], runtimeLoadAdmission)
		}
		t.Logf("separated_admission component=%s configuration=%+v", component, components[component])
	}
}
