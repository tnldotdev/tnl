package resolve

import (
	"errors"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// definition publishes logical shape only. local destinations, workload setup,
// visitor policy and environment membership never enter the immutable revision.
func Definition(project clientproject.Project) (controlv1.ServiceDefinition, error) {
	declared := project.Config
	if project.Declared != nil {
		declared = *project.Declared
	}
	if err := config.ValidateTNL(declared); err != nil {
		return controlv1.ServiceDefinition{}, err
	}
	if len(declared.Services) == 0 {
		return controlv1.ServiceDefinition{}, failure.Wrap("publish service definition", failure.ProjectConfigInvalid, errors.New("declare at least one service"))
	}
	definition := controlv1.ServiceDefinition{Services: make(map[string]controlv1.ServiceDefinitionService, len(declared.Services))}
	for name, service := range declared.Services {
		definition.Services[name] = controlv1.ServiceDefinitionService{Protocol: controlv1.ServiceProtocol(config.Protocol(service))}
	}
	return definition, nil
}
