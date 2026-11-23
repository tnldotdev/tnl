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
	Naming      string                        `json:"naming,omitempty" yaml:"naming,omitempty" jsonschema:"enum=opaque" jsonschema_description:"Use opaque hosted addresses for new public HTTP development services."`
	Feedback    *bool                         `json:"feedback,omitempty" yaml:"feedback,omitempty"`
	OAuth       bool                          `json:"oauth,omitempty" yaml:"oauth,omitempty"`
	Inspection  *Inspection                   `json:"inspection,omitempty" yaml:"inspection,omitempty"`
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
	Targets     map[string]DeploymentBinding `json:"targets,omitempty" yaml:"targets,omitempty"`
}

// DeploymentBinding reuses the target mechanics without repeating a protocol.
// an omitted target type selects address when present, otherwise an app listener.
type DeploymentBinding struct {
	ServiceTarget      `yaml:",inline"`
	Name               *string        `json:"name,omitempty" yaml:"name,omitempty" jsonschema_description:"Saved endpoint label; defaults to the logical service key."`
	Access             *ServiceAccess `json:"access,omitempty" yaml:"access,omitempty"`
	Public             *bool          `json:"public,omitempty" yaml:"public,omitempty" jsonschema_description:"Add public endpoint access for this service binding. Visitor access remains separate; false keeps connector access only."`
	Inspection         *Inspection    `json:"inspection,omitempty" yaml:"inspection,omitempty"`
	Hostname           *string        `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	RunAliasParent     *string        `json:"publisher_alias_parent,omitempty" yaml:"publisher_alias_parent,omitempty"`
	CertificateScope   *string        `json:"certificate_scope,omitempty" yaml:"certificate_scope,omitempty"`
	Domain             *string        `json:"domain,omitempty" yaml:"domain,omitempty"`
	Ephemeral          *bool          `json:"ephemeral,omitempty" yaml:"ephemeral,omitempty"`
	RequirePostQuantum *bool          `json:"require_post_quantum,omitempty" yaml:"require_post_quantum,omitempty"`
	Traffic            *TrafficLimits `json:"traffic,omitempty" yaml:"traffic,omitempty"`
	HTTP               *HTTPService   `json:"http,omitempty" yaml:"http,omitempty"`
}

type DeploymentWorkload struct {
	Deployment string `json:"deployment" yaml:"deployment" jsonschema:"required" jsonschema_description:"Exact configured deployment whose services this provider identity may access."`
	Workload   `yaml:",inline"`
}

// ValidPublisherCertificateScope checks the shape, not ownership, of the
// dedicated DNS subtree requested for one public HTTP deployment binding.
func ValidPublisherCertificateScope(hostname, aliasParent, scope string) bool {
	depth, within := naming.ChildDepth(hostname, scope)
	return scope == aliasParent && naming.ValidGeneratedHostnameParent(scope) && within && depth == 1
}

func DeclaredProtocol(service ServiceDeclaration) string {
	return Protocol(Service{Protocol: service.Protocol})
}

func ValidateProject(project Project) error {
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
	resolved := TNL{Name: project.Name, Server: project.Server, Team: project.Team, Services: Services{}, Deployment: name, Workloads: map[string]Workload{}}
	if name == "local" {
		if deployment.Description != nil || deployment.Domain != nil {
			return TNL{}, errors.New("local is client-side selection and has no server domain or description")
		}
		resolved.Feedback, resolved.OAuth, resolved.Inspection = project.Feedback, project.OAuth, project.Inspection
		resolved.Naming = project.Naming
		resolved.Webhooks, resolved.Aliases = project.Webhooks, project.Aliases
	} else {
		resolved.DeploymentSettings = DeploymentSettings{Description: deployment.Description, Domain: deployment.Domain}
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
		resolved.Services[service] = Service{Name: binding.Name, Protocol: &protocol, Target: &target, Access: binding.Access, Public: binding.Public, Inspection: binding.Inspection, HTTP: binding.HTTP,
			Hostname: binding.Hostname, RunAliasParent: binding.RunAliasParent, CertificateScope: binding.CertificateScope, Domain: binding.Domain, Ephemeral: binding.Ephemeral, RequirePostQuantum: binding.RequirePostQuantum, Traffic: binding.Traffic}
	}
	for policy, entry := range project.Workloads {
		if entry.Deployment == name {
			resolved.Workloads[policy] = entry.Workload
		}
	}
	return resolved, nil
}
