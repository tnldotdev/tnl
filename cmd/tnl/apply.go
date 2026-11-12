package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/clioutput"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type applyCommand struct {
	scopedTeamFlags `embed:""`
	Environment     string           `name:"environment" help:"Apply only this declared environment."`
	Collection      string           `name:"collection" help:"Set only this collection's default for future environments."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func applyEnvironmentCommandContext(project projectConfiguration, flags *applyCommand) error {
	declared := project.Config
	if project.Declared != nil {
		declared = *project.Declared
	}
	server := declared.Server
	if (flags.Environment == "") == (flags.Collection == "") {
		return errors.New("select exactly one of --environment or --collection")
	}
	if flags.Collection != "" {
		if _, found := declared.Collections[flags.Collection]; !found {
			return errors.New("--collection must select a declared collection")
		}
	} else {
		environment, found := declared.Environments[flags.Environment]
		if !found || flags.Environment == "local" {
			return errors.New("--environment must select a declared remote environment")
		}
		if environment.Server != nil {
			server = environment.Server
		}
	}
	var err error
	flags.ServerURL, _, err = resolve.Server(flags.ServerURL, server, flags.AccessToken)
	if err != nil {
		return err
	}
	flags.ProjectTeam, err = resolve.TeamForServer(flags.ServerURL, server, declared.Team)
	return err
}

func runApply(ctx context.Context, flags applyCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if err := applyEnvironmentCommandContext(project, &flags); err != nil {
		return err
	}
	selection := flags.selection()
	session, err := openTeamSession(ctx, selection, "tnl apply", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	if flags.Collection != "" {
		applied, err := resolve.ApplyCollection(ctx, session.Authenticated().Control, project.Project, current.Team().Id, flags.Collection)
		if err != nil {
			return err
		}
		if flags.Output == statusOutputJSON {
			return json.NewEncoder(output).Encode(applied)
		}
		return writeHumanFrame(output, "tnl apply", "default updated", "existing environments are unchanged", clioutput.Fields(
			clioutput.Field{Label: "collection", Value: applied.Name},
			clioutput.Field{Label: "collection ID", Value: string(applied.CollectionId)},
			clioutput.Field{Label: "definition revision", Value: strconv.FormatInt(applied.DefaultDefinitionRevision, 10)},
			clioutput.Field{Label: "mutation revision", Value: strconv.FormatInt(applied.MutationRevision, 10)},
		))
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		return err
	}
	applied, err := resolve.ApplyEnvironment(ctx, session.Authenticated().Control, project.Project, current, flags.Environment, key)
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(applied)
	}
	return writeHumanFrame(output, "tnl apply", "applied", "", appliedEnvironmentBlocks(applied)...)
}

func appliedEnvironmentBlocks(applied controlv1.Environment) []clioutput.Block {
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "environment", Value: applied.Name},
		clioutput.Field{Label: "environment ID", Value: applied.Id},
		clioutput.Field{Label: "definition revision", Value: strconv.FormatInt(applied.AppliedDefinitionRevision, 10)},
		clioutput.Field{Label: "mutation revision", Value: strconv.FormatInt(applied.MutationRevision, 10)},
	)}
	services := slices.Clone(applied.Services)
	slices.SortFunc(services, func(a, b controlv1.EnvironmentService) int { return strings.Compare(a.Service, b.Service) })
	for _, service := range services {
		blocks = append(blocks, clioutput.Section(service.Service, clioutput.Fields(clioutput.Field{Label: "service ID", Value: string(service.ServiceId)}, clioutput.Field{Label: "protocol", Value: string(service.Protocol)})))
	}
	return blocks
}
