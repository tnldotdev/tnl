package state

import (
	"encoding/json"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestAppliedPublicationProjectionSeparatesEndpoints(t *testing.T) {
	original := ProjectServiceConfiguration{
		Name: "api", Protocol: "http", Target: "app.internal:3000",
		Hostname: "api.example.test", DomainID: "original-domain", Public: new(true),
		TargetTLS: &ProjectTargetTLS{Hostname: "target.example.test", Digest: "approved"},
		Access:    &ProjectServiceAccess{Team: true},
		HTTP:      &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}},
		Traffic:   &trafficlimits.Selection{Connections: new(8)},
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"public", "hostname", "domain", "all endpoints"} {
		t.Run(field, func(t *testing.T) {
			next := original
			switch field {
			case "public":
				next.Public = new(false)
			case "hostname":
				next.Hostname = "renamed.example.test"
			case "domain":
				next.DomainID = "another-domain"
			case "all endpoints":
				next.Public, next.Hostname, next.DomainID = nil, "", ""
			}
			if !sameAppliedPublication(original, next) || !sameAppliedPublication(next, original) {
				t.Fatal("endpoint settings changed the serving definition")
			}
			projected := appliedPublicationConfiguration(next)
			if projected.Public != nil || projected.Hostname != "" || projected.DomainID != "" {
				t.Fatal("endpoint settings remained in the worker definition")
			}
		})
	}
	for _, field := range []string{"name", "protocol", "target", "discovery", "target hostname", "target roots", "target digest", "team access", "http access", "traffic", "ephemeral", "visitor tls"} {
		t.Run(field, func(t *testing.T) {
			next := original
			switch field {
			case "name":
				next.Name = "replacement"
			case "protocol":
				next.Protocol = "tcp"
			case "target":
				next.Target = "replacement.internal:3000"
			case "discovery":
				next.TargetDiscovery = &ProjectTargetDiscovery{Type: "aws.rds", Region: "us-west-2", Instance: new("database")}
			case "target hostname", "target roots", "target digest":
				trust := *original.TargetTLS
				next.TargetTLS = &trust
				switch field {
				case "target hostname":
					trust.Hostname = "replacement.example.test"
				case "target roots":
					trust.CAPEM = "different roots"
				case "target digest":
					trust.Digest = "different digest"
				}
			case "team access":
				next.Access = nil
			case "http access":
				next.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
			case "traffic":
				next.Traffic = &trafficlimits.Selection{Connections: new(16)}
			case "ephemeral":
				next.Ephemeral = true
			case "visitor tls":
				next.RequirePostQuantum = new(true)
			}
			if sameAppliedPublication(original, next) || sameAppliedPublication(next, original) {
				t.Fatal("a serving change was hidden by the endpoint projection")
			}
		})
	}
	after, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("projection or comparison mutated the original declaration")
	}
}
