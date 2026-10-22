package connector

import (
	"context"
	"errors"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type connectInventoryReader interface {
	ListAvailablePrivateServices(context.Context) ([]controlv1.PrivateService, error)
}

type ServiceReader interface {
	connectInventoryReader
	GetLocalProjectService(context.Context, string, string, controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error)
	GetProjectPrivateService(context.Context, string, string, controlv1.GetProjectPrivateServiceParams) (controlv1.PrivateService, error)
}

// Select resolves the visitor's exact local/applied binding before inventory.
func Select(ctx context.Context, control ServiceReader, project projectconfig.Project, name, team string) (controlv1.PrivateService, error) {
	key, err := ConfiguredService(project, name)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	localID := ""
	if key != "" {
		definition := project.Config.Services[key]
		if config.PublisherName(definition) == "local" {
			source := project.LocalPublicationIdentity()
			params := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey()}
			bound, err := control.GetLocalProjectService(ctx, source.Key, key, params)
			if errors.Is(err, controlclient.ErrNotFound) {
				return controlv1.PrivateService{}, failure.Wrap("find local private service", failure.LocalPrivateServiceUnavailable, err)
			}
			if err != nil {
				return controlv1.PrivateService{}, err
			}
			if bound.Service != key || bound.WorktreeKey != params.WorktreeKey || bound.ServiceKind != controlv1.LocalProjectServiceServiceKindPrivateService || bound.ServiceId == "" || bound.PrivateService == nil {
				return controlv1.PrivateService{}, failure.Wrap("find local private service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
			}
			localID = bound.ServiceId
		} else {
			source, err := project.SourceIdentity(ctx)
			if err != nil {
				return controlv1.PrivateService{}, failure.Wrap("identify applied project service", failure.ProjectConfigInvalid, err)
			}
			return control.GetProjectPrivateService(ctx, source.Key, key, controlv1.GetProjectPrivateServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint})
		}
	}
	services, err := control.ListAvailablePrivateServices(ctx)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	if localID != "" {
		service, err := privateServiceIDSelection(services, localID, team)
		if err != nil {
			return service, failure.Wrap("select local private service", failure.LocalPrivateServiceUnavailable, err)
		}
		return service, nil
	}
	return SelectService(services, name, team)
}

// ConfiguredService resolves a configured key or unique saved-name override.
// reject overlapping aliases rather than choosing a map iteration's first match.
func ConfiguredService(project projectconfig.Project, name string) (string, error) {
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
			return "", publisherCLIError("configured private service name is ambiguous; use an unambiguous service key or --no-config with the service ID")
		}
		selected = key
	}
	if publicMatch {
		return "", publisherCLIError("configured name selects a public URL service; use its HTTPS URL or --no-config with an exact private service ID")
	}
	return selected, nil
}

// SelectService selects an exact ID before considering unambiguous names.
func SelectService(services []controlv1.PrivateService, name, team string) (controlv1.PrivateService, error) {
	for _, service := range services {
		if service.Id == name && (team == "" || team == service.TeamId) {
			return service, nil
		}
	}
	var selected controlv1.PrivateService
	for _, service := range services {
		if (service.Id == name || service.Name == name) && (team == "" || team == service.TeamId) {
			if selected.Id != "" && selected.Id != service.Id {
				return selected, publisherCLIError("private service name is ambiguous; pass its ID or select --team")
			}
			selected = service
		}
	}
	if selected.Id == "" {
		return selected, failure.Wrap("select private service", failure.ServerResourceNotFound, errors.New("private service is not available to this identity; run tnl connect available"))
	}
	return selected, nil
}

func privateServiceIDSelection(services []controlv1.PrivateService, id, team string) (controlv1.PrivateService, error) {
	for _, service := range services {
		if service.Id == id && (team == "" || service.TeamId == team) {
			return service, nil
		}
	}
	return controlv1.PrivateService{}, failure.Wrap("select private service ID", failure.ServerResourceNotFound, errors.New("private service ID is absent from visitor inventory"))
}

// named publishers' public_url blocks are managed HTTP policy, not public URLs.
func isConnectPublicURL(service config.Service) bool {
	return config.PublisherName(service) == "local" && config.IsPublicService(service)
}
