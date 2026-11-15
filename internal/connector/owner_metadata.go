package connector

import (
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func workloadInventoryServices(inventory controlv1.WorkloadServices, team string) (map[string]controlv1.ServiceSummary, error) {
	services := make(map[string]controlv1.ServiceSummary, len(inventory.Services))
	for _, service := range inventory.Services {
		if _, duplicate := services[service.Service]; duplicate {
			return nil, connectorruntime.ErrInvalid
		}
		services[service.Service] = controlv1.ServiceSummary{Id: service.Id, Name: service.Service, TeamId: team, Protocol: service.Protocol,
			Enabled: true, Endpoint: &service.Endpoint, KubernetesAuth: service.KubernetesAuth}
	}
	return services, nil
}

func connectionServiceMetadata(service controlv1.ServiceSummary, protocol string) (meta.Service, error) {
	if ValidateService(service) != nil || string(service.Protocol) != protocol {
		return meta.Service{}, connectorruntime.ErrInvalid
	}
	endpoint := service.Endpoint
	return meta.NewEndpoint(endpoint.Hostname, endpoint.Hostname, protocol, endpoint.Port, endpoint.Public)
}

// projectConnectionMetadata projects only requested, valid services. callers
// install the returned values at their existing startup/replacement boundary.
func projectConnectionMetadata(configuration config.TNL, names []string, inventory map[string]controlv1.ServiceSummary) (map[string]controlv1.ServiceSummary, meta.PublicMetadata, error) {
	services := make(map[string]controlv1.ServiceSummary, len(names))
	metadata := meta.Metadata{Version: meta.Version, Services: map[string]meta.Service{}}
	for _, name := range names {
		service, ok := inventory[name]
		if !ok {
			continue
		}
		value, err := connectionServiceMetadata(service, config.Protocol(configuration.Services[name]))
		if err != nil {
			continue
		}
		services[name], metadata.Services[name] = service, value
		if metadata.Namespace == "" {
			metadata.Namespace = value.Namespace
		}
	}
	if err := metadata.Validate(); err != nil {
		return nil, meta.PublicMetadata{}, err
	}
	return services, metadata.Public(false), nil
}
