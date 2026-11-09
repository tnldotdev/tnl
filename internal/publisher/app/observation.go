package app

import (
	"context"
	"errors"
	"slices"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// project configuration supplies declared services, not an allowlist for local
// observations. invocation registrations have independent owners and lifetimes.
func ReadProjectSnapshotFrom(ctx context.Context, state *clientstate.Database, project clientproject.Project) (Snapshot, error) {
	snapshot, err := ReadSnapshotFrom(ctx, state, project.Root)
	if err != nil {
		return snapshot, err
	}
	return projectObservationSnapshot(project, snapshot), nil
}

func projectObservationSnapshot(project clientproject.Project, snapshot Snapshot) Snapshot {
	services := ConfiguredServices(project)
	for index := range services {
		for _, saved := range snapshot.Services {
			if saved.Name != services[index].Name {
				continue
			}
			definition := services[index]
			services[index] = saved
			services[index].Directory, services[index].Readiness, services[index].ServiceProtocol = definition.Directory, definition.Readiness, definition.ServiceProtocol
			if saved.Readiness != definition.Readiness {
				services[index].Ready, services[index].Observation = false, nil
			}
			break
		}
	}
	for _, saved := range snapshot.Services {
		if opaqueid.Valid(saved.Name, opaqueid.InvocationPrefix) {
			services = append(services, saved)
		}
	}
	for index := range services {
		service := &services[index]
		for _, publication := range snapshot.Publications {
			if (service.TunnelID != "" && publication.ID == service.TunnelID || publication.Service == service.Name) && publication.Target == service.Target && publication.State == clientstate.TunnelStateStale {
				service.Registered, service.Routable, service.Ready = false, false, false
				service.Observation, service.Failure = nil, "runtime.manager_unavailable"
			}
		}
	}
	snapshot.Services = services
	return snapshot
}

// an explicit invocation ID can wait for a publication that has not registered
// yet. default selection includes declarations and currently reserved invocations,
// never stopped historical invocations or remote publisher groups.
func LocalObservationServices(project clientproject.Project, snapshot Snapshot, requested []string) ([]string, error) {
	names := slices.Clone(requested)
	for _, name := range names {
		definition, found := project.Config.Services[name]
		if !found {
			if opaqueid.Valid(name, opaqueid.InvocationPrefix) {
				continue
			}
			return nil, failure.Wrap("wait for service", failure.ServiceNotConfigured, errors.New("service is not configured and is not an invocation ID"))
		}
		if config.PublisherGroupName(definition) != "local" {
			return nil, failure.Wrap("wait for local service", failure.AppRemoteService, errors.New("service belongs to a remote publisher"))
		}
	}
	if len(names) == 0 {
		for _, service := range ConfiguredServices(project) {
			names = append(names, service.Name)
		}
		for _, service := range snapshot.Services {
			if opaqueid.Valid(service.Name, opaqueid.InvocationPrefix) && service.RegistrationID != "" {
				names = append(names, service.Name)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}
