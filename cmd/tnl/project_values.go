package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

type scalarOutputMode string

const (
	scalarOutputHuman scalarOutputMode = "human"
	scalarOutputRaw   scalarOutputMode = "raw"
	scalarOutputJSON  scalarOutputMode = "json"
)

type projectCommand struct {
	Label     projectLabelCommand     `cmd:"" help:"Show this project's worktree label."`
	Publisher projectPublisherCommand `cmd:"" help:"Prepare a project publisher."`
}

type projectPublisherCommand struct {
	Credential projectPublisherCredentialCommand `cmd:"" help:"Manage the project publisher owner credential."`
}

type projectPublisherCredentialCommand struct {
	Create projectPublisherCredentialCreateCommand `cmd:"" help:"Create the private owner credential for an external publisher."`
	Export projectPublisherCredentialExportCommand `cmd:"" help:"Save one app-scoped endpoint for a container."`
}

type projectPublisherCredentialExportCommand struct {
	StateDir string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Service  string           `name:"service" required:"" help:"Configured app service using this endpoint."`
	Output   scalarOutputMode `name:"output" enum:"human,raw,json" default:"human" help:"Output format: ${enum}."`
}

type projectPublisherCredentialCreateCommand struct {
	StateDir string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Output   scalarOutputMode `name:"output" enum:"human,raw,json" default:"human" help:"Output format: ${enum}."`
}

type projectLabelCommand struct {
	StateDir string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path"`
	Output   scalarOutputMode `name:"output" enum:"human,raw,json" default:"human" help:"Output format: ${enum}."`
}

func runProjectLabel(ctx context.Context, flags cli, output io.Writer) error {
	root, err := projectRoot(ctx, flags)
	if err != nil {
		return err
	}
	stateDir, err := clientStateRoot(flags.Project.Label.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, stateDir)
	if err != nil {
		return err
	}
	defer state.Close()
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return err
	}
	worktree, err := projectconfig.ResolveWorktree(ctx, root)
	if err != nil {
		return err
	}
	label := projectconfig.ApplyWorktreeHashSalt(worktree, root, salt).Label.FullLabel
	switch flags.Project.Label.Output {
	case scalarOutputRaw:
		_, err = fmt.Fprintln(output, label)
		return err
	case scalarOutputJSON:
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Label         string `json:"label"`
		}{1, label})
	default:
		return clioutput.Write(output, clioutput.Frame{
			Command: "tnl project label", State: "selected",
			Blocks: []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "label", Value: label})},
		})
	}
}
