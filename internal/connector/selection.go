package connector

import (
	"context"
	"errors"
	"fmt"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectInventoryReader interface {
	ListAvailableServices(context.Context, controlv1.ServiceAccessPath) ([]controlv1.ServiceSummary, error)
}

type ServiceReader interface {
	connectInventoryReader
	GetLocalProjectService(context.Context, string, string, controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error)
	GetProjectService(context.Context, string, string, controlv1.GetProjectServiceParams) (controlv1.Service, error)
}

// Select resolves the visitor's exact local/applied binding before inventory.
func Select(ctx context.Context, control ServiceReader, project clientproject.Project, name, team string) (controlv1.ServiceSummary, error) {
	key, err := ConfiguredService(project, name)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	boundID := ""
	if key != "" {
		if config.SelectedDeployment(project.Config) == "local" {
			source := project.LocalPublicationIdentity()
			if source.Key == "" || project.LocalWorktreeKey() == "" {
				return controlv1.ServiceSummary{}, failure.Wrap("identify local service", failure.ClientStateUnavailable, errors.New("project is not bound to client state"))
			}
			params := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey()}
			bound, err := control.GetLocalProjectService(ctx, source.Key, key, params)
			if errors.Is(err, clientcontrol.ErrNotFound) {
				return controlv1.ServiceSummary{}, failure.Wrap("find local service", failure.LocalServiceUnavailable, err)
			}
			if err != nil {
				return controlv1.ServiceSummary{}, err
			}
			if bound.Service != key || bound.WorktreeKey != params.WorktreeKey || bound.ServiceId == "" || bound.Metadata == nil {
				return controlv1.ServiceSummary{}, failure.Wrap("find local service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
			}
			boundID = bound.ServiceId
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.ServiceSummary{}, failure.Wrap("identify applied project service", failure.ProjectConfigInvalid, err)
			}
			bound, err := control.GetProjectService(ctx, source.Key, key, controlv1.GetProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, Deployment: config.SelectedDeployment(project.Config)})
			if err != nil {
				return controlv1.ServiceSummary{}, err
			}
			if bound.Id == "" {
				return controlv1.ServiceSummary{}, failure.Wrap("find applied service", failure.ServerResponseInvalid, errors.New("control returned no applied service identity"))
			}
			boundID = bound.Id
		}
	}
	services, err := control.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	if boundID != "" {
		service, err := serviceIDSelection(services, boundID, team)
		if err != nil && config.SelectedDeployment(project.Config) == "local" {
			return service, failure.Wrap("select local service", failure.LocalServiceUnavailable, err)
		}
		return service, err
	}
	return SelectService(services, name, team)
}

// ConfiguredService resolves a configured key or unique saved-name override.
// reject overlapping aliases rather than choosing a map iteration's first match.
func ConfiguredService(project clientproject.Project, name string) (string, error) {
	selected := ""
	for key, service := range project.Config.Services {
		if key != name && config.ServiceName(key, service) != name {
			continue
		}
		if selected != "" {
			return "", publisherCLIError("configured service name is ambiguous; use an unambiguous service key or --no-config with the service ID")
		}
		selected = key
	}
	if selected == "" && project.Declared != nil {
		if _, declared := project.Declared.Services[name]; declared {
			return "", publisherCLIError(fmt.Sprintf("service %q has no binding in deployment %q", name, config.SelectedDeployment(project.Config)))
		}
	}
	return selected, nil
}

// SelectService selects an exact ID before considering unambiguous names.
func SelectService(services []controlv1.ServiceSummary, name, team string) (controlv1.ServiceSummary, error) {
	for _, service := range services {
		if service.Id == name && (team == "" || team == service.TeamId) {
			return service, nil
		}
	}
	var selected controlv1.ServiceSummary
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

func serviceIDSelection(services []controlv1.ServiceSummary, id, team string) (controlv1.ServiceSummary, error) {
	for _, service := range services {
		if service.Id == id && (team == "" || service.TeamId == team) {
			return service, nil
		}
	}
	return controlv1.ServiceSummary{}, failure.Wrap("select service ID", failure.ServerResourceNotFound, errors.New("service ID is absent from visitor inventory"))
}
