package tnldconfig

import (
	"strconv"
	"testing"
)

func TestIndependentAdmissionLimits(t *testing.T) {
	base := []string{"--role", "ingress", "--control-hostname", "control.example.test",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1"}
	for _, test := range []struct {
		flag  string
		value func(Config) int
	}{
		{"client-hello-connection-limit", func(c Config) int { return c.ClientHelloConnectionLimit }},
		{"challenge-connection-limit", func(c Config) int { return c.ChallengeConnectionLimit }},
		{"challenge-hostname-connection-limit", func(c Config) int { return c.ChallengeHostnameConnectionLimit }},
		{"standalone-control-connection-limit", func(c Config) int { return c.StandaloneControlConnectionLimit }},
		{"standalone-relay-connection-limit", func(c Config) int { return c.StandaloneRelayConnectionLimit }},
	} {
		t.Run(test.flag, func(t *testing.T) {
			cfg, err := Parse(base)
			if err != nil || test.value(cfg) <= 0 {
				t.Fatalf("default=%d error=%v", test.value(cfg), err)
			}
			for _, value := range []int{-2, 0, 7} {
				cfg, err := Parse(append(append([]string{}, base...), "--"+test.flag+"="+strconv.Itoa(value)))
				if value <= 0 && err == nil || value > 0 && (err != nil || test.value(cfg) != value) {
					t.Fatalf("input=%d parsed=%d error=%v", value, test.value(cfg), err)
				}
			}
		})
	}
}

func TestAutomaticAndExplicitConnectionCapacities(t *testing.T) {
	base := []string{"--role", "ingress", "--control-hostname", "control.example.test",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1"}
	for _, test := range []struct {
		flag  string
		value func(Config) int64
	}{
		{"visitor-connection-limit", func(c Config) int64 { return c.VisitorConnectionLimit }},
		{"publisher-connection-limit", func(c Config) int64 { return c.PublisherConnectionLimit }},
		{"relay-stream-capacity", func(c Config) int64 { return c.RelayStreamCapacity }},
		{"quic-max-incoming-streams", func(c Config) int64 { return c.QUICMaxIncomingStreams }},
	} {
		t.Run(test.flag, func(t *testing.T) {
			automatic, err := Parse(base)
			if err != nil || test.value(automatic) <= 0 {
				t.Fatalf("automatic limit = %d; error = %v", test.value(automatic), err)
			}
			for _, value := range []int{-2, 0, 7} {
				cfg, err := Parse(append(append([]string{}, base...), "--"+test.flag+"="+strconv.Itoa(value)))
				if value <= 0 && err == nil || value > 0 && (err != nil || test.value(cfg) != int64(value)) {
					t.Fatalf("input=%d parsed=%d error=%v", value, test.value(cfg), err)
				}
			}
		})
	}
	t.Setenv("TNLD_PUBLISHER_CONNECTION_LIMIT", "91")
	fromEnvironment, err := Parse(base)
	if err != nil || fromEnvironment.PublisherConnectionLimit != 91 {
		t.Fatalf("environment override = %d, err = %v", fromEnvironment.PublisherConnectionLimit, err)
	}
	fromFlag, err := Parse(append(append([]string{}, base...), "--publisher-connection-limit=17"))
	if err != nil || fromFlag.PublisherConnectionLimit != 17 {
		t.Fatalf("flag override = %d, err = %v", fromFlag.PublisherConnectionLimit, err)
	}
}

func TestTrafficDefaultsAndOperatorCeilings(t *testing.T) {
	base := []string{"--role", "ingress", "--control-hostname", "control.example.test",
		"--cluster-secret", testClusterSecret, "--ingress-id", "ingress-1"}
	cfg, err := Parse(base)
	if err != nil || cfg.TrafficDefaultConnections != 32 || cfg.TrafficMaxConnections != 128 ||
		cfg.TrafficDefaultRate != 20 || cfg.TrafficDefaultBurst != 40 ||
		cfg.TrafficDefaultUploadBytes != 8<<20 || cfg.TrafficDefaultDownloadBytes != 16<<20 {
		t.Fatalf("default traffic = %+v, %v", cfg, err)
	}
	for _, setting := range []string{
		"--traffic-default-connections=0", "--traffic-default-rate=0",
		"--traffic-default-upload-bytes=1", "--traffic-source-rate=0",
		"--traffic-max-rate=10", "--traffic-max-download-bytes=1",
	} {
		if _, err := Parse(append(append([]string{}, base...), setting)); err == nil {
			t.Fatalf("invalid traffic setting %s was accepted", setting)
		}
	}
	cfg, err = Parse(append(append([]string{}, base...), "--traffic-default-rate=30", "--traffic-max-rate=31"))
	if err != nil || cfg.TrafficDefaultRate != 30 || cfg.TrafficMaxRate != 31 {
		t.Fatalf("explicit traffic rate = %+v, %v", cfg, err)
	}
}
