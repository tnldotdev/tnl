package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// selectors narrow already authorized inventory. names never substitute for
// project/team scope, and ambiguous name/ID collisions are rejected.
func SelectEnvironments(environments []controlv1.Environment, team, project, selector string) ([]controlv1.Environment, error) {
	selected := []controlv1.Environment{}
	seen := map[string]bool{}
	for _, environment := range environments {
		if environment.TeamId != team || environment.ProjectKey != project || environment.Id == "" || seen[environment.Id] {
			return nil, failure.Wrap("read environment inventory", failure.ServerResponseInvalid, errors.New("server returned another project or duplicate environment"))
		}
		seen[environment.Id] = true
		if selector == "" || environment.Id == selector || environment.Name == selector {
			selected = append(selected, environment)
		}
	}
	if selector != "" && len(selected) != 1 {
		return nil, failure.Wrap("select environment", failure.ServerResourceNotFound, errors.New("select one saved environment name or exact environment ID in this project"))
	}
	slices.SortFunc(selected, func(a, b controlv1.Environment) int { return strings.Compare(a.Name, b.Name) })
	return selected, nil
}

// environment targets capture only the selected environment's approvals. cloud
// discovery remains publisher-owned; applying never dials a target or calls AWS.
func EnvironmentTargets(ctx context.Context, project clientproject.Project, name string) (controlv1.EnvironmentTargets, error) {
	declared := project.Config
	if project.Declared != nil {
		declared = *project.Declared
	}
	if err := config.ValidateTNL(declared); err != nil {
		return nil, err
	}
	environment, found := declared.Environments[name]
	if !found || name == "local" {
		return nil, errors.New("select a declared remote environment; local app listeners are managed by their running worktree")
	}
	result := controlv1.EnvironmentTargets{}
	cache := targettrust.NewCache(nil)
	for key, target := range environment.Targets {
		service := target.Service(declared.Services[key].Protocol)
		value := controlv1.EnvironmentTarget{}
		if discovery := target.Discovery; discovery != nil {
			value.Discovery = &controlv1.ProjectTargetDiscovery{Type: controlv1.ProjectTargetDiscoveryType(discovery.Type), Region: *discovery.Region, Cluster: discovery.Cluster, Instance: discovery.Instance}
			if discovery.Endpoint != nil {
				value.Discovery.Endpoint = new(controlv1.ProjectTargetDiscoveryEndpoint(*discovery.Endpoint))
			}
		} else {
			resolved, err := config.ResolveServiceTarget(service, "")
			if err != nil {
				return nil, err
			}
			address := string(*resolved.Target)
			value.Address = &address
			if tls := target.TLS; tls != nil {
				dial := address
				if config.Protocol(service) == "http" || config.Protocol(service) == "kubernetes" {
					origin, err := url.Parse(address)
					if err != nil {
						return nil, err
					}
					dial = origin.Host
					if origin.Port() == "" {
						dial = net.JoinHostPort(origin.Hostname(), "443")
					}
				}
				setting := config.TrustSource{CA: "system", Hostname: tls.Hostname}
				if tls.CAFile != nil {
					setting.CA = *tls.CAFile
				}
				snapshot, err := cache.Capture(ctx, project.Root, dial, setting)
				if err != nil {
					return nil, err
				}
				if tls.CAPEM != nil {
					snapshot, err = targettrust.CapturePEM(snapshot.Hostname, []byte(*tls.CAPEM))
					if err != nil {
						return nil, err
					}
				}
				value.Tls = &controlv1.EnvironmentTargetTLS{Hostname: &snapshot.Hostname, Digest: &snapshot.Digest}
				if len(snapshot.PEM) != 0 {
					value.Tls.CaPem = new(string(snapshot.PEM))
				}
			}
		}
		if target.HTTP != nil {
			encoded, err := json.Marshal(target.HTTP)
			if err != nil {
				return nil, err
			}
			value.Http = &controlv1.EnvironmentServiceHTTP{}
			if err := json.Unmarshal(encoded, value.Http); err != nil {
				return nil, err
			}
		}
		result[key] = value
	}
	return result, nil
}
