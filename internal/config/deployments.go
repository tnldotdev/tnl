package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tnldotdev/tnl/internal/naming"
)

// Project separates logical service declarations from deployment bindings.
// TNL is the evaluated configuration of one selected deployment.
type Project struct {
	Name        *string                       `json:"name,omitempty" yaml:"name,omitempty"`
	Server      *string                       `json:"server,omitempty" yaml:"server,omitempty"`
	Team        *string                       `json:"team,omitempty" yaml:"team,omitempty"`
	Feedback    *bool                         `json:"feedback,omitempty" yaml:"feedback,omitempty"`
	OAuth       bool                          `json:"oauth,omitempty" yaml:"oauth,omitempty"`
	Inspection  *Inspection                   `json:"inspection,omitempty" yaml:"inspection,omitempty"`
	Tunnel      *Tunnel                       `json:"public_url,omitempty" yaml:"public_url,omitempty"`
	Services    map[string]ServiceDeclaration `json:"services,omitempty" yaml:"services,omitempty"`
	Deployments map[string]Deployment         `json:"deployments,omitempty" yaml:"deployments,omitempty"`
	Webhooks    map[string]Webhook            `json:"webhooks,omitempty" yaml:"webhooks,omitempty"`
	Aliases     map[string]Alias              `json:"aliases,omitempty" yaml:"aliases,omitempty"`
	Workloads   map[string]DeploymentWorkload `json:"workloads,omitempty" yaml:"workloads,omitempty"`
}

type ServiceDeclaration struct {
	Protocol *string `json:"protocol,omitempty" yaml:"protocol,omitempty" jsonschema:"enum=http,enum=tcp,enum=mysql,enum=postgres,enum=kubernetes" jsonschema_description:"Logical application protocol; defaults to http. Targets and publication settings belong to deployments."`
}

type Deployment struct {
	Description *string                      `json:"description,omitempty" yaml:"description,omitempty"`
	Domain      *string                      `json:"domain,omitempty" yaml:"domain,omitempty"`
	Public      bool                         `json:"public,omitempty" yaml:"public,omitempty"`
	Targets     map[string]DeploymentBinding `json:"targets,omitempty" yaml:"targets,omitempty"`
}

// DeploymentBinding reuses the target mechanics without repeating a protocol.
// an omitted target type selects address when present, otherwise an app listener.
type DeploymentBinding struct {
	ServiceTarget `yaml:",inline"`
	Name          *string        `json:"name,omitempty" yaml:"name,omitempty" jsonschema_description:"Saved endpoint label; defaults to the logical service key."`
	Access        *ServiceAccess `json:"access,omitempty" yaml:"access,omitempty"`
	Inspection    *Inspection    `json:"inspection,omitempty" yaml:"inspection,omitempty"`
	Tunnel        *Tunnel        `json:"public_url,omitempty" yaml:"public_url,omitempty"`
	HTTP          *HTTPService   `json:"http,omitempty" yaml:"http,omitempty"`
}

type DeploymentWorkload struct {
	Deployment string `json:"deployment" yaml:"deployment" jsonschema:"required" jsonschema_description:"Exact configured deployment whose services this provider identity may access."`
	Workload   `yaml:",inline"`
}

func DeclaredProtocol(service ServiceDeclaration) string {
	return Protocol(Service{Protocol: service.Protocol})
}

func ValidateProject(project Project) error {
	if len(project.Services) != 0 && (project.Name != nil || project.Tunnel != nil && (project.Tunnel.Name != nil || project.Tunnel.PublicURL != nil)) {
		return errors.New("name and public_url.hostname belong under deployments.NAME.targets.SERVICE when services are declared")
	}
	if len(project.Services) > 128 || len(project.Deployments) > 32 || len(project.Workloads) > 32 {
		return errors.New("configure at most 128 services, 32 deployments, and 32 workload policies")
	}
	for name, declaration := range project.Services {
		if !naming.ValidServiceName(name) {
			return errors.New("services must declare lowercase service names")
		}
		if !ValidProtocol(DeclaredProtocol(declaration)) {
			return fmt.Errorf("services.%s: %w", name, validateTarget(Service{Protocol: declaration.Protocol}))
		}
	}
	for name, policy := range project.Workloads {
		if policy.Deployment == "local" || !naming.ValidServiceName(policy.Deployment) {
			return fmt.Errorf("workloads.%s.deployment must select a configured deployment other than local", name)
		}
		if _, found := project.Deployments[policy.Deployment]; !found {
			return fmt.Errorf("workloads.%s.deployment is not configured", name)
		}
	}
	names := slices.Sorted(maps.Keys(project.Deployments))
	if _, exists := project.Deployments["local"]; !exists {
		names = append(names, "local")
	}
	for _, name := range names {
		if !naming.ValidServiceName(name) {
			return errors.New("deployment names must be lowercase DNS labels")
		}
		resolved, err := resolveProjectDeployment(project, name)
		if err != nil {
			return err
		}
		if err := ValidateTNL(resolved); err != nil {
			return fmt.Errorf("deployments.%s: %w", name, err)
		}
	}
	return nil
}

func NormalizeProjectPublicURLs(project *Project) {
	defaults := TNL{Tunnel: project.Tunnel, Aliases: project.Aliases}
	NormalizePublicURLs(&defaults)
	for _, deployment := range project.Deployments {
		for _, binding := range deployment.Targets {
			normalizeTunnelPublicURL(binding.Tunnel)
		}
	}
}

func ResolveDeployment(project Project, name string) (TNL, error) {
	if err := ValidateProject(project); err != nil {
		return TNL{}, err
	}
	if name == "" {
		name = "local"
	}
	if name != "local" {
		if _, found := project.Deployments[name]; !found {
			return TNL{}, errors.New("selected deployment is not configured")
		}
	}
	return resolveProjectDeployment(project, name)
}

func resolveProjectDeployment(project Project, name string) (TNL, error) {
	deployment := project.Deployments[name]
	resolved := TNL{Name: project.Name, Server: project.Server, Team: project.Team, Tunnel: project.Tunnel, Services: Services{}, Deployment: name, Workloads: map[string]Workload{}}
	if name == "local" {
		if deployment.Description != nil || deployment.Domain != nil || deployment.Public {
			return TNL{}, errors.New("local is client-side selection and has no server domain, description, or reachability")
		}
		resolved.Feedback, resolved.OAuth, resolved.Inspection = project.Feedback, project.OAuth, project.Inspection
		resolved.Webhooks, resolved.Aliases = project.Webhooks, project.Aliases
	} else {
		resolved.DeploymentSettings = DeploymentSettings{Description: deployment.Description, Domain: deployment.Domain, Public: deployment.Public}
	}
	for service, binding := range deployment.Targets {
		declaration, found := project.Services[service]
		if !found {
			return TNL{}, fmt.Errorf("deployments.%s.targets.%s has no logical service declaration", name, service)
		}
		target := binding.ServiceTarget
		if target.Type == "" {
			target.Type = "app"
			if target.Address != nil {
				target.Type = "address"
			}
		}
		protocol := DeclaredProtocol(declaration)
		resolved.Services[service] = Service{Name: binding.Name, Protocol: &protocol, Target: &target, Access: binding.Access, Inspection: binding.Inspection, Tunnel: binding.Tunnel, HTTP: binding.HTTP}
	}
	for policy, entry := range project.Workloads {
		if entry.Deployment == name {
			resolved.Workloads[policy] = entry.Workload
		}
	}
	return resolved, nil
}
