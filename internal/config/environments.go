package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/tnldotdev/tnl/internal/naming"
)

// environment owns destinations and permission intent, not reusable shape.
type Environment struct {
	Server     *string                      `json:"server,omitempty" yaml:"server,omitempty"`
	Domain     *string                      `json:"domain,omitempty" yaml:"domain,omitempty"`
	Public     *bool                        `json:"public,omitempty" yaml:"public,omitempty"`
	Collection *string                      `json:"collection,omitempty" yaml:"collection,omitempty"`
	Targets    map[string]EnvironmentTarget `json:"targets,omitempty" yaml:"targets,omitempty"`
	Workloads  map[string]Workload          `json:"workloads,omitempty" yaml:"workloads,omitempty"`
}

// collection has no second service schema. a new collection captures the current
// immutable definition as its default; applying a member never updates siblings.
type Collection struct{}

// environment target follows the control target shape. local additionally owns
// app discovery, preview policy, inspection and listener readiness.
type EnvironmentTarget struct {
	Address    *Target               `json:"address,omitempty" yaml:"address,omitempty"`
	TLS        *EnvironmentTargetTLS `json:"tls,omitempty" yaml:"tls,omitempty"`
	Discovery  *ServiceTarget        `json:"discovery,omitempty" yaml:"discovery,omitempty"`
	HTTP       *HTTPService          `json:"http,omitempty" yaml:"http,omitempty"`
	Name       *string               `json:"name,omitempty" yaml:"name,omitempty"`
	Access     *ServiceAccess        `json:"access,omitempty" yaml:"access,omitempty"`
	Inspection *Inspection           `json:"inspection,omitempty" yaml:"inspection,omitempty"`
	Tunnel     *Tunnel               `json:"public_url,omitempty" yaml:"public_url,omitempty"`
}

type EnvironmentTargetTLS struct {
	Hostname *string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	CAFile   *string `json:"ca_file,omitempty" yaml:"ca_file,omitempty"`
	CAPEM    *string `json:"ca_pem,omitempty" yaml:"ca_pem,omitempty"`
}

// local services are evaluated facts consumed by the publisher. this projection
// does not change the declarations or copy another environment's targets.
func LocalServices(c TNL) Services {
	result := maps.Clone(c.Services)
	for name, target := range c.Environments["local"].Targets {
		service, found := result[name]
		if found {
			result[name] = target.Service(service.Protocol)
		}
	}
	return result
}

func (t EnvironmentTarget) Service(protocol *string) Service {
	service := Service{Protocol: protocol, Name: t.Name, Access: t.Access, Inspection: t.Inspection, Tunnel: t.Tunnel, HTTP: t.HTTP}
	if t.Address != nil {
		service.Target = &ServiceTarget{Type: "address", Address: t.Address}
	} else if t.Discovery != nil {
		copy := *t.Discovery
		service.Target = &copy
	}
	if t.TLS != nil {
		if service.Target == nil {
			service.Target = &ServiceTarget{Type: "app"}
		}
		service.Target.TLS = &TargetTLS{ServerName: t.TLS.Hostname, CAFile: t.TLS.CAFile}
	}
	return service
}

func ValidateEnvironments(c TNL) error {
	if len(c.Environments) > 128 || len(c.Collections) > 128 {
		return errors.New("environments and collections may contain at most 128 entries")
	}
	for _, name := range slices.Sorted(maps.Keys(c.Collections)) {
		if !naming.ValidServiceName(name) {
			return errors.New("collection name must be a lowercase DNS label")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.Environments)) {
		environment := c.Environments[name]
		if !naming.ValidServiceName(name) {
			return errors.New("environment name must be a lowercase DNS label")
		}
		if err := validateServerAndTeam(environment.Server, nil); err != nil {
			return fmt.Errorf("environments.%s: %w", name, err)
		}
		if environment.Collection != nil {
			if _, found := c.Collections[*environment.Collection]; !found || name == "local" {
				return fmt.Errorf("environments.%s.collection must name a declared collection for a remote environment", name)
			}
		}
		if name == "local" && (environment.Public != nil || environment.Domain != nil || len(environment.Workloads) != 0) {
			return errors.New("environments.local uses local public_url settings, not remote reachability, domains, or workloads")
		}
		if err := ValidateWorkloads(c.Services, environment.Workloads); err != nil {
			return fmt.Errorf("environments.%s: %w", name, err)
		}
		for _, key := range slices.Sorted(maps.Keys(environment.Targets)) {
			target := environment.Targets[key]
			service, found := c.Services[key]
			if !found {
				return fmt.Errorf("environments.%s.targets names an unknown service", name)
			}
			if target.Address != nil && target.Discovery != nil {
				return fmt.Errorf("environments.%s.targets.%s requires exactly one of address or discovery", name, key)
			}
			if d := target.Discovery; d != nil {
				if d.Type == "app" || d.Type == "address" || d.TLS != nil {
					return errors.New("discovery must select compose, docker, eks, or rds without nested tls")
				}
				if target.TLS != nil && (name != "local" || d.Type == "eks" || d.Type == "rds") {
					return fmt.Errorf("environments.%s.targets.%s: provider discovery supplies its own target trust", name, key)
				}
			}
			if target.TLS != nil && target.TLS.CAFile != nil && target.TLS.CAPEM != nil {
				return errors.New("target tls requires at most one of ca_file or ca_pem")
			}
			if name == "local" && target.TLS != nil && target.TLS.CAPEM != nil {
				return errors.New("local target TLS uses ca_file, not ca_pem")
			}
			if name != "local" {
				if target.Address == nil && target.Discovery == nil {
					return fmt.Errorf("environments.%s.targets.%s requires address or discovery", name, key)
				}
				if target.Name != nil || target.Access != nil || target.Inspection != nil || target.Tunnel != nil {
					return errors.New("name, access, inspection, and public_url target settings belong only in environments.local")
				}
				if target.Discovery != nil && target.Discovery.Type != "eks" && target.Discovery.Type != "rds" {
					return errors.New("remote discovery requires eks or rds")
				}
				if err := ValidateEnvironmentHTTP(target.HTTP); err != nil {
					return err
				}
			}
			resolved := target.Service(service.Protocol)
			if err := validateTarget(resolved); err != nil {
				return fmt.Errorf("environments.%s.targets.%s: %w", name, key, err)
			}
			if target.HTTP != nil && Protocol(service) != "http" {
				return errors.New("http target settings require protocol http")
			}
		}
		if name != "local" && len(environment.Targets) != len(c.Services) {
			return fmt.Errorf("environments.%s.targets must bind every configured service", name)
		}
	}
	return nil
}
