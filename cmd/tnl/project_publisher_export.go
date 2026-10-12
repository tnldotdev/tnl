package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

func runProjectPublisherCredentialExport(ctx context.Context, flags cli, output io.Writer) error {
	options := flags.Project.Publisher.Credential.Export
	root, err := clientStateRoot(options.StateDir)
	if err != nil {
		return err
	}
	project, err := loadProjectConfiguration(ctx, flags, root)
	if err != nil {
		return err
	}
	service, found := project.Config.Services[options.Service]
	if !found || !naming.ValidServiceName(options.Service) || service.Target == nil || service.Target.Type != "app" {
		return failure.Wrap("export app publisher credential", failure.ServiceNotConfigured,
			errors.New("select a configured app service"))
	}
	publisher := project.Config.Publisher
	if publisher == nil || publisher.Type == "local" {
		return failure.Wrap("export app publisher credential", failure.ProjectConfigInvalid,
			errors.New("select an external publisher in project configuration"))
	}
	if publisher.Type == "docker" {
		if publisher.Compose == nil || publisher.Compose.Project != project.Worktree.Label.FullLabel {
			return failure.Wrap("export app publisher credential", failure.ProjectConfigInvalid,
				errors.New("the Compose publisher project differs from this worktree"))
		}
		if err := dockertarget.ComposeServiceDeclared(ctx, project.Root, publisher.Compose.Project, publisher.Compose.File, options.Service); err != nil {
			return failure.Wrap("export app publisher credential", failure.ProjectConfigInvalid, err)
		}
	}
	endpoint, err := remotePublisherScope(ctx, project, true, false, options.Service)
	if err != nil {
		return err
	}
	endpoint, err = containerAppEndpoint(*publisher, endpoint)
	if err != nil {
		return err
	}
	path := filepath.Join(project.Root, ".tnl", "publisher-"+options.Service+".endpoint.json")
	if err := writeRuntimeTCPEndpoint(path, endpoint); err != nil {
		return failure.Wrap("export app publisher credential", failure.ClientStateUnavailable, err)
	}
	switch options.Output {
	case scalarOutputRaw:
		_, err = fmt.Fprintln(output, path)
		return err
	case scalarOutputJSON:
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Path          string `json:"path"`
		}{1, path})
	default:
		return clioutput.Write(output, clioutput.Frame{Command: "tnl project publisher credential export", State: "saved",
			Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "file", Value: path})},
			Footer: "mount this file read-only in the app container",
		})
	}
}

func containerAppEndpoint(publisher config.ProjectPublisher, endpoint localPublisherEndpoint) (localPublisherEndpoint, error) {
	if publisher.Type == "docker" {
		if publisher.Compose == nil || publisher.ContainerPort == nil || !naming.ValidServiceName(publisher.Compose.Service) {
			return localPublisherEndpoint{}, failure.Wrap("export app publisher credential", failure.ProjectConfigInvalid,
				errors.New("container apps require a Compose publisher service on their network"))
		}
		endpoint.URL = "http://" + net.JoinHostPort(publisher.Compose.Service, strconv.Itoa(*publisher.ContainerPort))
	}
	return endpoint, nil
}
