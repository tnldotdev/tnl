package config

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestProjectValidationDoesNotMutateAccess(t *testing.T) {
	for _, boundary := range []string{"selected", "project", "aliases"} {
		for _, invalid := range []bool{false, true} {
			t.Run(boundary+map[bool]string{false: "/valid", true: "/invalid-after-access"}[invalid], func(t *testing.T) {
				raw := []string{"198.51.100.9", "192.0.2.7/24", "::ffff:192.0.2.8/120"}
				access := &Access{IP: slices.Clone(raw)}
				original := access.IP
				http := &HTTPService{Access: access}
				if invalid {
					http.Limits = &WorkLimits{Concurrency: new(0)}
				}
				var source any
				var validate func() error
				switch boundary {
				case "selected":
					value := TNL{Services: Services{"web": {HTTP: http}}}
					source, validate = value, func() error { return ValidateTNL(value) }
				case "project":
					value := Project{Services: map[string]ServiceDeclaration{"web": {}},
						Deployments: map[string]Deployment{"local": {Targets: map[string]DeploymentBinding{"web": {HTTP: http}}}}}
					source, validate = value, func() error { return ValidateProject(value) }
				case "aliases":
					alias := Alias{Service: "web", Access: access}
					if invalid {
						alias.Name = new("NotCanonical")
					}
					value := TNL{Services: Services{"web": {}}, Aliases: map[string]Alias{"review": alias}}
					source, validate = value, func() error { return ValidateAliases(value) }
				}
				before, err := json.Marshal(source)
				if err != nil {
					t.Fatal(err)
				}
				if err := validate(); (err != nil) != invalid {
					t.Fatalf("validation error = %v, invalid=%t", err, invalid)
				}
				after, err := json.Marshal(source)
				if err != nil || !bytes.Equal(before, after) || !slices.Equal(access.IP, raw) || &access.IP[0] != &original[0] {
					t.Fatalf("validation wrote through caller-owned policy: before=%s after=%s error=%v", before, after, err)
				}
			})
		}
	}
}

func TestAliasDefinitionCanonicalizesOnlyItsOwnedPolicy(t *testing.T) {
	raw := []string{"198.51.100.9", "192.0.2.7/24", "::ffff:192.0.2.8/120"}
	access := &Access{IP: slices.Clone(raw)}
	alias := Alias{Service: "web", Access: access}
	encoded, digest, err := alias.DefinitionBytes("review")
	if err != nil {
		t.Fatal(err)
	}
	canonical := Alias{Service: "web", Access: &Access{IP: []string{"192.0.2.0/24", "198.51.100.9/32"}}}
	want, wantDigest, err := canonical.DefinitionBytes("review")
	if err != nil || !bytes.Equal(encoded, want) || digest != wantDigest {
		t.Fatalf("equivalent alias policies have different definitions: got=%s want=%s error=%v", encoded, want, err)
	}
	if alias.Access != access || !slices.Equal(access.IP, raw) {
		t.Fatal("alias definition changed its caller's policy", access)
	}
}
