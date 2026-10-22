package app

import (
	"slices"
	"strings"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func ConfiguredServices(project projectconfig.Project) []Service {
	services := make([]Service, 0, len(project.Config.Services))
	for name, definition := range project.Config.Services {
		if config.PublisherName(definition) != "local" {
			continue
		}
		readiness := Readiness{Path: "/"}
		if definition.HTTP != nil && definition.HTTP.Readiness != nil {
			readiness.Path = definition.HTTP.Readiness.Path
		}
		services = append(services, Service{Name: name, Directory: ".", ServiceProtocol: config.Protocol(definition), Readiness: readiness})
	}
	slices.SortFunc(services, func(a, b Service) int { return strings.Compare(a.Name, b.Name) })
	return services
}
