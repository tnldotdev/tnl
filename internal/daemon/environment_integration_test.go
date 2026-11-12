package daemon

import (
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// use the real shape publication and environment APIs for runtime fixtures.
// targets and access never enter the reusable definition.
func createServiceRuntimeEnvironment(t *testing.T, f *privateSeparatedFixture, project string, definition controlv1.ServiceDefinition, request controlv1.CreateEnvironmentRequest) controlv1.Environment {
	t.Helper()
	request.TeamId, request.SourceFingerprint = f.identity.teamID, strings.Repeat("a", 64)
	revision, err := f.identity.routes.CreateServiceDefinition(t.Context(), project, controlv1.CreateServiceDefinitionRequest{TeamId: request.TeamId, SourceFingerprint: request.SourceFingerprint, ProjectLabel: request.ProjectLabel, Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	request.DefinitionRevision = &revision.Revision
	request.IdempotencyKey = "runtime/" + request.Name
	environment, err := f.identity.routes.CreateEnvironment(t.Context(), project, request)
	if err != nil {
		t.Fatal(err)
	}
	return environment
}
