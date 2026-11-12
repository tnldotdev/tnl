package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestEnvironmentPreparedPublicationRequiresCompleteImmutableFacts(t *testing.T) {
	valid := EnvironmentPublication{EnvironmentID: "env_AAAAAAAAAAAAAAAAAAAAAA", MutationRevision: 3, ConfigurationHash: strings.Repeat("a", 64)}
	for _, test := range []struct {
		name    string
		run     controlstatedb.ControlServiceRun
		want    *EnvironmentPublication
		invalid bool
	}{
		{name: "legacy nil"},
		{name: "complete", run: controlstatedb.ControlServiceRun{EnvironmentID: text(valid.EnvironmentID), EnvironmentMutationRevision: pgtype.Int8{Int64: valid.MutationRevision, Valid: true}, EnvironmentConfigurationHash: text(valid.ConfigurationHash)}, want: &valid},
		{name: "missing revision", run: controlstatedb.ControlServiceRun{EnvironmentID: text(valid.EnvironmentID), EnvironmentConfigurationHash: text(valid.ConfigurationHash)}, invalid: true},
		{name: "missing ID", run: controlstatedb.ControlServiceRun{EnvironmentMutationRevision: pgtype.Int8{Int64: 3, Valid: true}, EnvironmentConfigurationHash: text(valid.ConfigurationHash)}, invalid: true},
		{name: "invalid revision", run: controlstatedb.ControlServiceRun{EnvironmentID: text(valid.EnvironmentID), EnvironmentMutationRevision: pgtype.Int8{Valid: true}, EnvironmentConfigurationHash: text(valid.ConfigurationHash)}, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := preparedEnvironmentPublication(test.run)
			if test.invalid {
				if !errors.Is(err, ErrEnvironmentStale) {
					t.Fatal("incomplete stored fence was accepted", got, err)
				}
			} else if err != nil || !sameEnvironmentPublication(got, test.want) {
				t.Fatal(got, err)
			}
		})
	}
	older := valid
	older.MutationRevision--
	if sameEnvironmentPublication(&valid, &older) || sameEnvironmentPublication(&valid, nil) {
		t.Fatal("publication equality ignored explicit context or revision")
	}
}

func TestServiceDefinitionShapeAndHash(t *testing.T) {
	input := ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}}}
	definition, hash, err := NormalizeServiceDefinition(input)
	if err != nil || len(hash) != 64 || !reflect.DeepEqual(input, definition) {
		t.Fatal(definition, hash, err)
	}
	input.Services["api"] = ServiceDefinitionService{Protocol: "tcp"}
	if definition.Services["api"].Protocol != "http" {
		t.Fatal("normalization retained caller map")
	}
	_, same, err := NormalizeServiceDefinition(ServiceDefinition{Services: map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}, "api": {Protocol: "http"}}})
	if err != nil || hash != same {
		t.Fatal("hash depends on map insertion order", err)
	}
	if _, err := decodeServiceDefinition([]byte(`{"services":{"api":{"protocol":"http","access":{"team":true}},"db":{"protocol":"postgres"}}}`), hash); !errors.Is(err, ErrServiceDefinitionInvalid) {
		t.Fatal("stored definition accepted policy outside its immutable shape", err)
	}
	for name, bad := range map[string]ServiceDefinition{
		"empty":            {},
		"default protocol": {Services: map[string]ServiceDefinitionService{"api": {}}},
		"unknown protocol": {Services: map[string]ServiceDefinitionService{"api": {Protocol: "https"}}},
		"invalid name":     {Services: map[string]ServiceDefinitionService{"bad/name": {Protocol: "http"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := NormalizeServiceDefinition(bad); !errors.Is(err, ErrServiceDefinitionInvalid) {
				t.Fatal(err)
			}
		})
	}
	tooMany := ServiceDefinition{Services: map[string]ServiceDefinitionService{}}
	for i := range 129 {
		tooMany.Services["a"+strings.Repeat("b", i)] = ServiceDefinitionService{Protocol: "tcp"}
	}
	if _, _, err := NormalizeServiceDefinition(tooMany); !errors.Is(err, ErrServiceDefinitionInvalid) {
		t.Fatal("definition size was not bounded", err)
	}
}

func TestEnvironmentTargetsRequireCompleteProtocolApproval(t *testing.T) {
	d1 := ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "http"}}}
	for name, targets := range map[string]EnvironmentTargets{
		"missing":                    nil,
		"unknown":                    {"other": {Address: "internal:3000"}},
		"partial":                    {},
		"empty TLS is not plaintext": {"api": {Address: "internal:443", TLS: &ProjectTargetTLS{}}},
		"unapproved HTTPS":           {"api": {Address: "https://internal:443"}},
		"local registration":         {"api": {Address: "app"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeEnvironmentTargets(targets, d1); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("invalid remote approval accepted", err)
			}
		})
	}
	bindings, err := normalizeEnvironmentTargets(EnvironmentTargets{"api": {Address: "http://internal:03000/"}}, d1)
	if err != nil || bindings["api"].Target != "internal:3000" || bindings["api"].protocol != "http" {
		t.Fatal(bindings, err)
	}
	d2 := ServiceDefinition{Services: map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}}}
	if err := validateEnvironmentBindings(bindings, d2); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("retained target approved a different protocol", err)
	}
	approved, err := normalizeEnvironmentTargets(EnvironmentTargets{"api": {Address: "internal:5432"}}, d2)
	if err != nil || approved["api"].protocol != "postgres" {
		t.Fatal(approved, err)
	}
	encoded, _ := json.Marshal(environmentTargets(approved))
	if bytes.Contains(encoded, []byte("protocol")) {
		t.Fatal("private protocol pins leaked into target metadata")
	}
	if environmentConfigurationHash(d1, bindings) == environmentConfigurationHash(d2, approved) {
		t.Fatal("effective application hash ignored target/protocol changes")
	}
	if bytes.Equal(environmentCreationDigest("staging", 1, bindings), environmentCreationDigest("staging", 2, bindings)) {
		t.Fatal("creation digest ignored original definition")
	}
}

func TestEnvironmentSelectorsAreNotDNSNames(t *testing.T) {
	for _, name := range []string{"customer_123", "Staging west", "production"} {
		if !validEnvironmentName(name) {
			t.Fatal("human selector was treated as DNS authority", name)
		}
	}
	for _, name := range []string{"", " padded", "line\nbreak", "\x00", strings.Repeat("x", 129)} {
		if validEnvironmentName(name) {
			t.Fatal("invalid selector accepted", name)
		}
	}
	for input, expected := range map[error]error{ErrProjectConfigurationStale: ErrEnvironmentStale, ErrProjectConfigurationInvalid: ErrEnvironmentInvalid, ErrServiceDefinitionInvalid: ErrEnvironmentInvalid} {
		if !errors.Is(environmentOperationError(input), expected) {
			t.Fatal("wrong operation diagnostic", input)
		}
	}
}
