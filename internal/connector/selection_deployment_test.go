package connector

import (
	"context"
	"errors"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentSelectionReader struct {
	calls    int
	services []controlv1.Service
}

func (r *deploymentSelectionReader) ListAvailableServices(context.Context) ([]controlv1.Service, error) {
	r.calls++
	return r.services, nil
}

func (*deploymentSelectionReader) GetLocalProjectService(context.Context, string, string, controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error) {
	return controlv1.LocalProjectService{}, errors.New("unexpected local binding lookup")
}

func (*deploymentSelectionReader) GetProjectService(context.Context, string, string, controlv1.GetProjectServiceParams) (controlv1.Service, error) {
	return controlv1.Service{}, errors.New("unexpected deployment binding lookup")
}

func TestConnectDeclaredServiceRequiresSelectedDeploymentBinding(t *testing.T) {
	for _, deployment := range []string{"local", "staging"} {
		t.Run(deployment, func(t *testing.T) {
			project := clientproject.Project{
				Declared: &config.Project{
					Services: map[string]config.ServiceDeclaration{"db": {Protocol: new("postgres")}},
					Deployments: map[string]config.Deployment{
						deployment: {Targets: map[string]config.DeploymentBinding{}},
						"production": {Targets: map[string]config.DeploymentBinding{
							"db": {ServiceTarget: config.ServiceTarget{Address: new(config.Target("production.internal:5432"))}},
						}},
					},
				},
				Config: config.TNL{Deployment: deployment, Services: config.Services{}},
			}
			reader := &deploymentSelectionReader{services: []controlv1.Service{{
				Id: "svc_production", Name: "db", TeamId: "tm_shop", Protocol: "postgres",
			}}}
			selected, err := Select(t.Context(), reader, project, "db", "tm_shop")
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
				t.Fatalf("unbound service selection = %q, %v", selected.Id, err)
			}
			if !strings.Contains(err.Error(), deployment) || reader.calls != 0 {
				t.Fatalf("unbound selection lost its deployment or queried global inventory: %v, calls=%d", err, reader.calls)
			}
		})
	}
}

func TestConnectTCPRequiresItsExplicitDeploymentBinding(t *testing.T) {
	project := clientproject.Project{Declared: &config.Project{
		Services: map[string]config.ServiceDeclaration{
			"internal": {Protocol: new("tcp")},
			"shell":    {Protocol: new("tcp")},
		},
		Deployments: map[string]config.Deployment{
			"internal": {Targets: map[string]config.DeploymentBinding{
				"internal": {ServiceTarget: config.ServiceTarget{Address: new(config.Target("sshd.internal:2222"))}},
			}},
			"production": {Targets: map[string]config.DeploymentBinding{
				"shell": {ServiceTarget: config.ServiceTarget{Address: new(config.Target("sshd.internal:2222"))}},
			}},
		},
	}}
	for _, service := range []struct{ name, deployment, sibling string }{
		{"internal", "internal", "production"}, {"shell", "production", "internal"},
	} {
		t.Run(service.name, func(t *testing.T) {
			reader := &deploymentSelectionReader{services: []controlv1.Service{{
				Id: "svc_sibling", Name: service.name, TeamId: "tm_shop", Protocol: "tcp",
			}}}
			for _, deployment := range []string{"", service.sibling} {
				selected, err := project.SelectDeployment(deployment)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Select(t.Context(), reader, selected, service.name, "tm_shop"); err == nil || reader.calls != 0 {
					t.Fatal("unbound TCP name borrowed inventory or a sibling deployment", deployment, err)
				} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
					t.Fatal("unbound TCP name lost its selection error", err)
				}
			}
			selected, err := project.SelectDeployment(service.deployment)
			if err != nil {
				t.Fatal(err)
			}
			key, err := ConfiguredService(selected, service.name)
			if err != nil || key != service.name || config.SelectedDeployment(selected.Config) != service.deployment || config.Protocol(selected.Config.Services[key]) != "tcp" {
				t.Fatal("explicit TCP deployment lost its exact binding", key, err)
			}
		})
	}
}

func TestConnectExactServiceIDRemainsExplicitWithUnboundDeclarations(t *testing.T) {
	project := clientproject.Project{
		Declared: &config.Project{Services: map[string]config.ServiceDeclaration{"db": {Protocol: new("postgres")}}},
		Config:   config.TNL{Deployment: "staging", Services: config.Services{}},
	}
	reader := &deploymentSelectionReader{services: []controlv1.Service{{
		Id: "svc_production", Name: "db", TeamId: "tm_shop", Protocol: "postgres",
	}}}
	selected, err := Select(t.Context(), reader, project, "svc_production", "tm_shop")
	if err != nil || selected.Id != "svc_production" || reader.calls != 1 {
		t.Fatalf("explicit ID selection = %q, %v, calls=%d", selected.Id, err, reader.calls)
	}
	project.Declared = nil
	selected, err = Select(t.Context(), reader, project, "db", "tm_shop")
	if err != nil || selected.Id != "svc_production" || reader.calls != 2 {
		t.Fatalf("unconfigured inventory selection = %q, %v, calls=%d", selected.Id, err, reader.calls)
	}
}
