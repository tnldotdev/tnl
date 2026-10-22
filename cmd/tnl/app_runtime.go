package main

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/local"
)

type runtimeCommand struct {
	Connections   connectionsCommand     `cmd:"" hidden:""`
	Endpoint      runtimeEndpointOptions `cmd:"" hidden:""`
	OwnerEndpoint runtimeOptions         `cmd:"" hidden:""`
	Serve         runtimeOptions         `cmd:"" hidden:""`
}

type runtimeOptions struct {
	Directory     string `name:"directory" required:"" type:"path"`
	StateDir      string `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	SnapshotStdin bool   `name:"snapshot-stdin" hidden:""`
}

type runtimeEndpointOptions struct {
	runtimeOptions `embed:""`
	Service        string `name:"service"`
	InvocationID   string `name:"invocation-id"`
}

func (o runtimeOptions) settings() local.Options {
	settings := local.Options{Directory: o.Directory, StateDir: o.StateDir}
	if o.SnapshotStdin {
		settings.Snapshot = os.Stdin
	}
	return settings
}

func runRuntimeOwnerEndpoint(ctx context.Context, options runtimeOptions, output io.Writer) error {
	endpoint, err := local.OwnerEndpoint(ctx, options.settings())
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

func runRuntimeEndpoint(ctx context.Context, options runtimeEndpointOptions, output io.Writer) error {
	endpoint, err := local.Endpoint(ctx, options.settings(), options.Service, options.InvocationID)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(endpoint)
}

func runRuntimeServe(ctx context.Context, options runtimeOptions) error {
	return local.Serve(ctx, options.settings())
}

func runtimeProject(ctx context.Context, options runtimeOptions) (projectConfiguration, string, error) {
	project, root, err := local.ResolveProject(ctx, options.settings())
	return projectConfiguration{Project: project}, root, err
}

func configuredRuntimeServices(project projectConfiguration) []app.Service {
	return app.ConfiguredServices(project.Project)
}
