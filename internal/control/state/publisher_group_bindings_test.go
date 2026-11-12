package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestPublisherGroupTargetBindingValidation(t *testing.T) {
	definition, hash, err := NormalizeServiceDefinition(ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "fixed": {Protocol: "tcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, targets := range map[string]EnvironmentTargets{
		"missing":        {},
		"unknown":        {"api": {Address: "localhost:3000"}, "other": {Address: "localhost:3001"}},
		"missing fixed":  {"api": {Address: "localhost:3000"}},
		"cloud protocol": {"api": {Discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Instance: new("db")}}, "fixed": {Address: "localhost:22"}},
		"deferred":       {"api": {Address: "app"}, "fixed": {Address: "localhost:22"}},
		"bad trust":      {"api": {Address: "localhost:443", TLS: &ProjectTargetTLS{Hostname: "localhost", Digest: "bad"}}, "fixed": {Address: "localhost:22"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeEnvironmentTargets(targets, definition); !errors.Is(err, ErrEnvironmentInvalid) && !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal(err)
			}
		})
	}
	bindings, err := normalizeEnvironmentTargets(EnvironmentTargets{"api": {Address: "localhost:3000"}, "fixed": {Address: "localhost:22"}}, definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEnvironmentBindings(bindings, definition); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"target":"localhost:3000"`, `"target_binding":"group"`} {
		data := []byte(`{"services":{"api":{"protocol":"http",` + field + `},"fixed":{"protocol":"tcp"}}}`)
		if _, err := decodeServiceDefinition(data, hash); !errors.Is(err, ErrServiceDefinitionInvalid) {
			t.Fatal("logical definition accepted a second target authority", err)
		}
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
			result, err := normalizeEnvironmentTargets(EnvironmentTargets{"db": {Address: test.target, Discovery: test.discovery}}, ServiceDefinition{Services: map[string]ServiceDefinitionService{"db": {Protocol: test.protocol}}})
			if test.valid && err != nil {
				t.Fatal(err)
			}
			if !test.valid && !errors.Is(err, ErrEnvironmentInvalid) && !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("accepted incompatible target", result, err)
			}
		})
	}
}

func TestPublisherGroupBindingRequiresSavedProtocolApproval(t *testing.T) {
	for _, pin := range []string{"", "http", "postgres"} {
		if _, err := bindEnvironmentService("tcp", environmentTargetBinding{Target: "equipment.internal:5432", protocol: pin}); !errors.Is(err, ErrEnvironmentInvalid) {
			t.Fatalf("pin %q was reinterpreted as TCP: %v", pin, err)
		}
	}
	bindings, err := normalizeEnvironmentTargets(EnvironmentTargets{"api": {Address: "equipment.internal:5432"}}, ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "tcp"}}})
	if err != nil || bindings["api"].protocol != "tcp" {
		t.Fatal("explicit binding replacement did not derive its approved protocol", err)
	}
	encoded, err := json.Marshal(bindings)
	if err != nil || bytes.Contains(encoded, []byte("protocol")) {
		t.Fatal("private protocol pin entered the public binding shape", string(encoded), err)
	}
}
