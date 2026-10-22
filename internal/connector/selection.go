package connector

import (
	"context"
	"errors"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectInventoryReader interface {
	ListAvailableServices(context.Context) ([]controlv1.Service, error)
}

type ServiceReader interface {
	connectInventoryReader
	GetLocalProjectService(context.Context, string, string, controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error)
	GetProjectService(context.Context, string, string, controlv1.GetProjectServiceParams) (controlv1.Service, error)
}

// Select resolves the visitor's exact local/applied binding before inventory.
func Select(ctx context.Context, control ServiceReader, project clientproject.Project, name, team string) (controlv1.Service, error) {
	key, err := ConfiguredService(project, name)
	if err != nil {
		return controlv1.Service{}, err
	}
	localID := ""
	if key != "" {
		definition := project.Config.Services[key]
		if config.PublisherGroupName(definition) == "local" {
			source := project.LocalPublicationIdentity()
			params := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey()}
			bound, err := control.GetLocalProjectService(ctx, source.Key, key, params)
			if errors.Is(err, clientcontrol.ErrNotFound) {
				return controlv1.Service{}, failure.Wrap("find local service", failure.LocalServiceUnavailable, err)
			}
			if err != nil {
				return controlv1.Service{}, err
			}
			if bound.Service != key || bound.WorktreeKey != params.WorktreeKey || bound.ServiceKind != controlv1.LocalProjectServiceServiceKindService || bound.ServiceId == "" || bound.Metadata == nil {
				return controlv1.Service{}, failure.Wrap("find local service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
			}
			localID = bound.ServiceId
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.Service{}, failure.Wrap("identify applied project service", failure.ProjectConfigInvalid, err)
			}
			return control.GetProjectService(ctx, source.Key, key, controlv1.GetProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint})
		}
	}
	services, err := control.ListAvailableServices(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	if localID != "" {
		service, err := serviceIDSelection(services, localID, team)
		if err != nil {
			return service, failure.Wrap("select local service", failure.LocalServiceUnavailable, err)
		}
		return service, nil
	}
	return SelectService(services, name, team)
}

// ConfiguredService resolves a configured key or unique saved-name override.
// reject overlapping aliases rather than choosing a map iteration's first match.
func ConfiguredService(project clientproject.Project, name string) (string, error) {
	selected := ""
	publicMatch := false
	for key, service := range project.Config.Services {
		if key != name && config.ServiceName(key, service) != name {
			continue
		}
		if isConnectPublicURL(service) {
			publicMatch = true
			continue
		}
		if selected != "" {
			return "", publisherCLIError("configured service name is ambiguous; use an unambiguous service key or --no-config with the service ID")
		}
		selected = key
	}
	if publicMatch {
		return "", publisherCLIError("configured name selects a public URL service; use its HTTPS URL or --no-config with an exact service ID")
	}
	return selected, nil
}

// SelectService selects an exact ID before considering unambiguous names.
func SelectService(services []controlv1.Service, name, team string) (controlv1.Service, error) {
	for _, service := range services {
		if service.Id == name && (team == "" || team == service.TeamId) {
			return service, nil
		}
	}
	var selected controlv1.Service
	for _, service := range services {
		if (service.Id == name || service.Name == name) && (team == "" || team == service.TeamId) {
			if selected.Id != "" && selected.Id != service.Id {
				return selected, publisherCLIError("service name is ambiguous; pass its ID or select --team")
			}
			selected = service
		}
	}
	if selected.Id == "" {
		return selected, failure.Wrap("select service", failure.ServerResourceNotFound, errors.New("service is not available to this identity; run tnl connect available"))
	}
	return selected, nil
}

func serviceIDSelection(services []controlv1.Service, id, team string) (controlv1.Service, error) {
	for _, service := range services {
		if service.Id == id && (team == "" || service.TeamId == team) {
			return service, nil
		}
	}
	return controlv1.Service{}, failure.Wrap("select service ID", failure.ServerResourceNotFound, errors.New("service ID is absent from visitor inventory"))
}

// named publishers' public_url blocks are service HTTP policy, not public URLs.
func isConnectPublicURL(service config.Service) bool {
	return config.PublisherGroupName(service) == "local" && config.IsPublicService(service)
}
