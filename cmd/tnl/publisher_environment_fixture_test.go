package main

import (
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// installed-publisher suites create the saved environment through control, not
// a second project-config publisher template. the CLI owns enrollment and serving.
func workflowPublisherEnvironment(t *testing.T, control *clientcontrol.Client, team, project string, target controlv1.EnvironmentTarget) controlv1.Environment {
	t.Helper()
	definition, err := control.CreateServiceDefinition(t.Context(), project, controlv1.CreateServiceDefinitionRequest{
		TeamId: team, SourceFingerprint: strings.Repeat("a", 64),
		Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: controlv1.ServiceProtocol("http")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := control.CreateEnvironment(t.Context(), project, controlv1.CreateEnvironmentRequest{
		TeamId: team, SourceFingerprint: definition.SourceFingerprint, Name: "production", DefinitionRevision: &definition.Revision,
		IdempotencyKey: key, Targets: controlv1.EnvironmentTargets{"api": target},
	})
	if err != nil {
		t.Fatal(err)
	}
	return environment
}
