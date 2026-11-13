package app

import (
	"slices"
	"strings"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func ConfiguredServices(project clientproject.Project) []Service {
	services := make([]Service, 0, len(project.Config.Services))
	if config.SelectedDeployment(project.Config) != "local" {
		return services
	}
	for name, definition := range project.Config.Services {
		readiness := Readiness{Path: "/"}
		if definition.HTTP != nil && definition.HTTP.Readiness != nil {
			readiness.Path = definition.HTTP.Readiness.Path
		}
		services = append(services, Service{Name: name, Directory: ".", ServiceProtocol: config.Protocol(definition), Readiness: readiness})
	}
	slices.SortFunc(services, func(a, b Service) int { return strings.Compare(a.Name, b.Name) })
	return services
}
