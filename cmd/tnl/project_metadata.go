package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func runConfigGenerate(ctx context.Context, stateRoot string, project projectConfiguration, stdout, stderr io.Writer) error {
	if !project.Found() {
		return failure.Wrap("generate project metadata", failure.ProjectConfigMissing, errors.New("no project configuration file found"))
	}
	state, err := clientstate.Open(ctx, stateRoot)
	if err != nil {
		return err
	}
	defer state.Close()
	resolver := newProjectMetadataResolver(state, project, os.Stdin, stderr, "tnl config generate")
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		return err
	}
	if err := projectmeta.Write(ctx, project.Root, metadata); err != nil {
		return err
	}
	actions, err := projectTypeIncludeActions(project)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{
		{Label: "metadata", Value: filepath.Join(project.Root, projectmeta.DirectoryName, projectmeta.JSONName)},
		{Label: "declarations", Value: filepath.Join(project.Root, projectmeta.DirectoryName, projectmeta.DeclarationsName)},
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	for _, action := range actions {
		blocks = append(blocks, clioutput.Section("action", clioutput.Text(action)))
	}
	return writeHumanFrame(stdout, "tnl config generate", "generated", "", blocks...)
}

func newProjectMetadataResolver(state *clientstate.Database, project projectConfiguration, input io.Reader, diagnostics io.Writer, command string) *localpublisher.MetadataResolver {
	if input == nil {
		input = os.Stdin
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	return localpublisher.NewMetadataResolver(state, project.Project, func(ctx context.Context, server string) (*clientauth.Client, error) {
		return authenticatePublisher(ctx, state, server, "", command, input, diagnostics)
	})
}
func configuredProjectService(service string, worktree projectconfig.Worktree, effective config.TNL, current teamContext) (projectmeta.Service, error) {
	return localpublisher.ConfiguredProjectService(service, worktree, effective, current.facts())
}
