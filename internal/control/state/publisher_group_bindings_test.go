package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestPublisherGroupTargetBindingValidation(t *testing.T) {
	c := ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{
		"api":   {PublisherGroup: "customer", Protocol: "http", TargetBinding: "group"},
		"fixed": {PublisherGroup: "customer", Protocol: "tcp", Target: "localhost:22"},
	}}
	normalized, _, err := NormalizeProjectConfiguration(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, bindings := range map[string]PublisherGroupBindings{
		"missing":        {},
		"unknown":        {"api": {Target: "localhost:3000"}, "other": {Target: "localhost:3001"}},
		"fixed override": {"api": {Target: "localhost:3000"}, "fixed": {Target: "localhost:23"}},
		"cloud protocol": {"api": {TargetDiscovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("db")}}},
		"deferred":       {"api": {Target: "app"}},
		"bad trust":      {"api": {Target: "localhost:443", TargetTLS: &ProjectTargetTLS{Hostname: "localhost", Digest: "bad"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePublisherGroupBindings(normalized, "customer", bindings); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal(err)
			}
		})
	}
	bindings, err := normalizePublisherGroupBindings(PublisherGroupBindings{"api": {Target: "localhost:3000"}}, publisherGroupBindingProtocols(normalized, "customer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePublisherGroupBindings(normalized, "customer", bindings); err != nil {
		t.Fatal(err)
	}
	s := c.Services["api"]
	s.Target = "localhost:3000"
	c.Services["api"] = s
	if _, _, err := NormalizeProjectConfiguration(c); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("template accepted both target authorities", err)
	}
	s.Target = ""
	c.Services["api"] = s
	c.PublisherGroups["customer"] = ProjectPublisherGroup{}
	if _, _, err := NormalizeProjectConfiguration(c); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("direct group accepted bindings", err)
	}
}

func TestPublisherGroupBindingNormalizationUsesDeclaredProtocol(t *testing.T) {
	for _, test := range []struct {
		name, protocol, target string
		discovery              *ProjectTargetDiscovery
		valid                  bool
	}{
		{name: "HTTP shorthand", protocol: "http", target: "http://db.internal:5432/", valid: true},
		{name: "postgres URL forbidden", protocol: "postgres", target: "http://db.internal:5432/"},
		{name: "mysql URL forbidden", protocol: "mysql", target: "https://db.internal:3306"},
		{name: "plaintext kubernetes forbidden", protocol: "kubernetes", target: "cluster.internal:443"},
		{name: "EKS postgres forbidden", protocol: "postgres", discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("cluster")}},
		{name: "RDS kubernetes forbidden", protocol: "kubernetes", discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("db")}},
		{name: "RDS postgres", protocol: "postgres", discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Cluster: new("db")}, valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := normalizePublisherGroupBindings(PublisherGroupBindings{"db": {Target: test.target, TargetDiscovery: test.discovery}}, map[string]string{"db": test.protocol})
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("accepted incompatible target", result, err)
			}
		})
	}
}

func TestPublisherGroupBindingRequiresSavedProtocolApproval(t *testing.T) {
	service := ProjectServiceConfiguration{PublisherGroup: "customer", Protocol: "tcp", TargetBinding: "group"}
	for _, pin := range []string{"", "http", "postgres"} {
		if _, err := bindPublisherGroupService(service, PublisherGroupTargetBinding{Target: "equipment.internal:5432", protocol: pin}); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatalf("pin %q was reinterpreted as TCP: %v", pin, err)
		}
	}
	bindings, err := normalizePublisherGroupBindings(PublisherGroupBindings{"api": {Target: "equipment.internal:5432", protocol: "http"}}, map[string]string{"api": "tcp"})
	if err != nil || bindings["api"].protocol != "tcp" {
		t.Fatal("explicit binding replacement did not derive its approved protocol", err)
	}
	encoded, err := json.Marshal(bindings)
	if err != nil || bytes.Contains(encoded, []byte("protocol")) {
		t.Fatal("private protocol pin entered the public binding shape", string(encoded), err)
	}
}
