package daemon

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// setup uses the manager's actual identity. visitor admission still traverses
// the serving authority verifier, possession proof, and saved permission.
func registerRuntimeWorkload(t *testing.T, f *privateSeparatedFixture, name, environment string) controlstate.MachineIdentity {
	t.Helper()
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]string{
		"sub": "repo:example/repository:ref:refs/heads/main", "repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789",
		"workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main",
	}
	if environment != "" {
		claims["sub"] = "repo:example/repository:environment:" + environment
		claims["environment"] = environment
	}
	machine, err := f.database.RegisterMachineIdentity(t.Context(), controlstate.RegisterMachineRequest{
		TeamID: f.identity.teamID, ActorID: person.Identity.Id, Name: name, ProofKind: "oidc",
		Trust: oidc.WorkloadTrust{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: oidc.GitHubIssuer + "/.well-known/jwks", Audience: f.controlConfig.ControlOrigin(), Claims: claims, Events: []string{"push"}},
	}, time.Now())
	if err != nil {
		t.Fatal("register runtime workload identity", err)
	}
	return machine
}

func runtimeWorkloadPermission(t *testing.T, f *privateSeparatedFixture, machine controlstate.MachineIdentity, environment controlv1.Environment, duration int, services ...string) string {
	t.Helper()
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(services) == 0 {
		for _, service := range environment.Services {
			services = append(services, service.Service)
		}
	}
	permission, err := f.database.CreateEnvironmentVisitorPermission(t.Context(), controlstate.EnvironmentVisitorPermission{
		TeamID: f.identity.teamID, MachineID: machine.ID, ProjectKey: environment.ProjectKey,
		Scope: controlstate.EnvironmentPermissionScope{EnvironmentIDs: []string{environment.Id}}, Services: services,
		MaxDurationSeconds: duration, ExpiresAt: time.Now().Add(time.Hour),
	}, person.Identity.Id, time.Now())
	if err != nil {
		t.Fatal("create runtime visitor permission", err)
	}
	return permission.ID
}

func runtimeEnvironmentReference(f *privateSeparatedFixture, environment controlv1.Environment) controlv1.EnvironmentReference {
	return controlv1.EnvironmentReference{Server: f.controlConfig.ControlOrigin(), ProjectKey: environment.ProjectKey, EnvironmentId: environment.Id}
}

func runtimeEnvironmentProtocols(environment controlv1.Environment) map[string]string {
	protocols := make(map[string]string, len(environment.Services))
	for _, service := range environment.Services {
		protocols[service.Service] = string(service.Protocol)
	}
	return protocols
}

func prepareRuntimeWorkload(t *testing.T, f *privateSeparatedFixture, environment controlv1.Environment, permission, assertion string) (*workload.Client, authorityv1.EnvironmentVisitorPreparation) {
	t.Helper()
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := job.Prepare(t.Context(), runtimeEnvironmentReference(f, environment), permission, assertion, runtimeEnvironmentProtocols(environment))
	if err != nil {
		t.Fatal("prepare environment visitor", err)
	}
	for _, saved := range environment.Services {
		selected, found := prepared.Services[saved.Service]
		if !found || selected.ServiceId != saved.ServiceId || selected.Endpoint.Public != saved.Public || selected.Endpoint.Hostname != saved.Hostname || selected.Endpoint.Port != saved.Port {
			t.Fatal("preparation did not retain exact saved service identity and reachability")
		}
	}
	return job, prepared
}
