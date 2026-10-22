package discovery_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
)

func TestCloudSelectorBoundaryParity(t *testing.T) {
	for _, test := range []struct {
		name, kind, protocol, cluster, instance, endpoint string
		valid                                             bool
	}{
		{"eks", "eks", "kubernetes", "Production_1", "", "", true},
		{"eks numeric initial", "eks", "kubernetes", "1cluster", "", "", false},
		{"eks wrong protocol", "eks", "http", "demo", "", "", false},
		{"eks endpoint", "eks", "kubernetes", "demo", "", "writer", false},
		{"eks instance", "eks", "kubernetes", "demo", "demo", "", false},
		{"instance default", "rds", "postgres", "", "orders", "", true},
		{"instance writer", "rds", "mysql", "", "orders", "writer", true},
		{"cluster default", "rds", "mysql", "orders", "", "", true},
		{"cluster reader", "rds", "postgres", "orders", "", "reader", true},
		{"instance reader", "rds", "postgres", "", "orders", "reader", false},
		{"rds both", "rds", "postgres", "orders", "orders", "", false},
		{"rds neither", "rds", "postgres", "", "", "", false},
		{"rds wrong protocol", "rds", "tcp", "orders", "", "", false},
		{"rds uppercase", "rds", "postgres", "Orders", "", "", false},
		{"rds underscore", "rds", "postgres", "orders_db", "", "", false},
		{"rds trailing hyphen", "rds", "postgres", "orders-", "", "", false},
		{"rds repeated hyphen", "rds", "postgres", "orders--db", "", "", false},
		{"rds 63", "rds", "postgres", strings.Repeat("a", 63), "", "", true},
		{"rds 64", "rds", "postgres", strings.Repeat("a", 64), "", "", false},
		{"endpoint case", "rds", "postgres", "orders", "", "Writer", false},
		{"unknown type", "other", "postgres", "orders", "", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			optional := func(value string) *string {
				if value == "" {
					return nil
				}
				return &value
			}
			source := config.ServiceTarget{Type: test.kind, Region: new("us-east-1"), Cluster: optional(test.cluster), Instance: optional(test.instance), Endpoint: optional(test.endpoint)}
			descriptor := controlstate.ProjectTargetDiscovery{Type: source.Type, Region: *source.Region, Cluster: source.Cluster, Instance: source.Instance, Endpoint: source.Endpoint}
			before, _ := json.Marshal(descriptor)
			request := publisherdiscovery.Request{Type: test.kind, Region: "us-east-1", Cluster: test.cluster, Instance: test.instance, Endpoint: test.endpoint, Protocol: test.protocol}
			normalized, discoveryErr := request.Normalize()
			adapted, adapterErr := publisherdiscovery.FromServiceTarget(source, config.ProtocolName(test.protocol))
			for boundary, err := range map[string]error{"source": config.ValidateCloudTarget(test.protocol, source), "control": descriptor.Validate(test.protocol), "discovery": discoveryErr, "source adapter": adapterErr} {
				if (err == nil) != test.valid {
					t.Errorf("%s valid=%t: %v", boundary, test.valid, err)
				}
			}
			after, _ := json.Marshal(descriptor)
			if !bytes.Equal(before, after) {
				t.Fatal("validation mutated the descriptor")
			}
			if test.valid {
				if adapted != normalized {
					t.Fatal("normalization differs", adapted, normalized)
				}
				result, err := descriptor.Normalize(test.protocol)
				if err != nil {
					t.Fatal(err)
				}
				if test.kind == "rds" && (result.Endpoint == nil || string(config.RDSEndpoint(*result.Endpoint)) != normalized.Endpoint) {
					t.Fatal("endpoint default differs", result)
				}
			}
		})
	}
}

func TestCloudSelectorNormalizedJSONAndHash(t *testing.T) {
	const expected = `{"publisher_groups":{"production":{}},"services":{"db":{"target_discovery":{"type":"rds","region":"us-east-1","instance":"orders","endpoint":"writer"},"publisher_group":"production","name":"db","protocol":"postgres","target":""}},"oauth":false,"webhooks":{}}`
	digest := sha256.Sum256([]byte(expected))
	for _, endpoint := range []*string{nil, new("writer")} {
		descriptor := &controlstate.ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("orders"), Endpoint: endpoint}
		input := controlstate.ProjectConfiguration{PublisherGroups: map[string]controlstate.ProjectPublisherGroup{"production": {}}, Services: map[string]controlstate.ProjectServiceConfiguration{"db": {PublisherGroup: "production", Protocol: "postgres", TargetDiscovery: descriptor}}}
		before, _ := json.Marshal(input)
		normalized, hash, err := controlstate.NormalizeProjectConfiguration(input)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(normalized)
		if err != nil || string(encoded) != expected || hash != hex.EncodeToString(digest[:]) {
			t.Fatalf("normal form changed: %s, %s, %v", encoded, hash, err)
		}
		after, _ := json.Marshal(input)
		if !bytes.Equal(before, after) {
			t.Fatal("normalization mutated its input")
		}
		*normalized.Services["db"].TargetDiscovery.Instance = "other"
		if *descriptor.Instance != "orders" {
			t.Fatal("normalized descriptor aliases its input")
		}
	}
}

func TestCloudSelectorPresenceAndRegion(t *testing.T) {
	for _, mutate := range []func(*config.ServiceTarget){
		func(s *config.ServiceTarget) { s.Region = nil },
		func(s *config.ServiceTarget) { s.Region = new("") },
		func(s *config.ServiceTarget) { s.Region = new("US-east-1") },
		func(s *config.ServiceTarget) { s.Region = new("us-" + strings.Repeat("a", 28) + "-1") },
		func(s *config.ServiceTarget) { s.Cluster = new("") },
		func(s *config.ServiceTarget) { s.Instance = new("") },
		func(s *config.ServiceTarget) { s.Endpoint = new("") },
		func(s *config.ServiceTarget) { s.TLS = &config.TargetTLS{} },
		func(s *config.ServiceTarget) { s.Address = new(config.Target("localhost:5432")) },
	} {
		source := config.ServiceTarget{Type: "rds", Region: new("us-east-1"), Cluster: new("orders")}
		mutate(&source)
		if config.ValidateCloudTarget("postgres", source) == nil {
			t.Fatal("invalid source selector accepted")
		}
		if _, err := publisherdiscovery.FromServiceTarget(source, config.ProtocolPostgres); publisherdiscovery.ErrorKind(err) != publisherdiscovery.Invalid {
			t.Fatal("invalid adapter selector", err)
		}
		if source.Region != nil && source.TLS == nil && source.Address == nil {
			descriptor := controlstate.ProjectTargetDiscovery{Type: source.Type, Region: *source.Region, Cluster: source.Cluster, Instance: source.Instance, Endpoint: source.Endpoint}
			if descriptor.Validate("postgres") == nil {
				t.Fatal("invalid control selector accepted")
			}
		}
	}
	request := publisherdiscovery.Request{Type: "rds", Region: "us-east-1", Instance: "orders", Protocol: "postgres", Account: "*"}
	if _, err := request.Normalize(); publisherdiscovery.ErrorKind(err) != publisherdiscovery.Invalid {
		t.Fatal("provider account check was lost", err)
	}
	request.Account = "123456789012"
	normalized, err := request.Normalize()
	if err != nil || normalized.Account != request.Account || normalized.Endpoint != "writer" || request.Endpoint != "" {
		t.Fatal("request normalization", normalized, err)
	}
}
