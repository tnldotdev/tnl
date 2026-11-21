package resolve

import (
	"context"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/targettrust"
	api "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applyDeploymentLookup func(context.Context, string, string, string) (api.Deployment, error)

func (f applyDeploymentLookup) GetDeployment(ctx context.Context, team, project, selector string) (api.Deployment, error) {
	return f(ctx, team, project, selector)
}

func TestApplyComparisonBaseUsesSavedDeploymentAddressAndTLSHostnameMode(t *testing.T) {
	const host = "target.example.test"
	for _, test := range []struct {
		name     string
		address  string
		explicit *string
		wantHost string
	}{
		{"unchanged automatic hostname", host + ":443", nil, host},
		{"same explicit hostname", host + ":443", new(host), host},
		{"automatic hostname follows changed address", "other.example.test:443", nil, "other.example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			trust, err := targettrust.NewDeclaration(test.wantHost, nil)
			if err != nil {
				t.Fatal(err)
			}
			saved := api.AppliedProjectConfiguration{
				Revision:    8,
				Deployments: &[]api.AppliedDeployment{{Name: "production", Id: "deployment-id"}},
				Configuration: api.ProjectConfiguration{Services: map[string]api.ProjectServiceConfiguration{"web": {
					Target: "stale.example.test:443", DomainId: new("inherited"),
				}}},
			}
			lookup := applyDeploymentLookup(func(_ context.Context, team, project, id string) (api.Deployment, error) {
				if team != "team" || project != "project" || id != "deployment-id" {
					t.Fatalf("wrong deployment read: %s/%s/%s", team, project, id)
				}
				return api.Deployment{
					TeamId: team, ProjectKey: project, Id: id, Name: "production",
					Services: map[string]api.DeploymentService{"web": {Protocol: "http"}},
					Targets: map[string]api.DeploymentTargetStatus{"web": {
						Address: &test.address, Tls: &api.DeploymentTargetTLS{Ca: new("system"), Hostname: test.explicit},
					}},
				}, nil
			})
			resolved, err := ApplyComparisonBase(t.Context(), lookup, "team", "project", "production", saved)
			got := resolved.Configuration.Services["web"]
			if err != nil || got.Target != test.address || got.TargetTls == nil || got.TargetTls.Hostname != test.wantHost ||
				got.TargetTls.Digest != trust.Digest || got.TargetTls.HostnameFromTarget != (test.explicit == nil) ||
				got.DomainId == nil || *got.DomainId != "inherited" || resolved.Revision != saved.Revision {
				t.Fatalf("comparison target: %+v, tls: %+v (%v)", got, got.TargetTls, err)
			}
			if before := saved.Configuration.Services["web"]; before.Target != "stale.example.test:443" || before.TargetTls != nil {
				t.Fatalf("changed the original saved declaration: %+v", before)
			}
		})
	}
}
