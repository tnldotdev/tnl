package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherGroupCommand struct {
	scopedTeamFlags `embed:""`
	Name            string           `arg:"" name:"group" help:"Concrete publisher group name."`
	ProjectKey      string           `name:"project-key" help:"Applied project key; defaults to this project's Git source."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type publisherCreateCommand struct {
	publisherGroupCommand `embed:""`
	From                  string `name:"from" required:"" help:"Applied publisher group template to follow."`
}

func runPublisherTemplate(ctx context.Context, flags publisherGroupCommand, project projectConfiguration, action, template string, output, diagnostics io.Writer) error {
	key := flags.ProjectKey
	if key == "" {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		key = source.Key
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher "+action, diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	client, team := session.Authenticated().Control, current.Team().Id
	var connection controlv1.PublisherGroupConnection
	switch action {
	case "create":
		connection, err = publishergroup.Create(ctx, client, team, key, flags.Name, template)
	case "connection":
		connection, err = client.GetPublisherGroupConnection(ctx, team, key, flags.Name)
	case "remove":
		err = publishergroup.Remove(ctx, client, team, key, flags.Name)
	}
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		if action == "remove" {
			return json.NewEncoder(output).Encode(map[string]string{"group": flags.Name, "state": "removed"})
		}
		return json.NewEncoder(output).Encode(connection)
	}
	state, hint := "created", "enroll a publisher with tnl publisher enroll --group "+flags.Name
	if action == "connection" {
		state, hint = "selected", "use --output json to save the nonsecret connection descriptor"
	}
	if action == "remove" {
		state, hint = "removed", "publisher identities and service access are revoked"
	}
	fields := []clioutput.Field{
		clioutput.Field{Label: "group", Value: flags.Name}, clioutput.Field{Label: "project key", Value: key}, clioutput.Field{Label: "team ID", Value: team},
	}
	if action != "remove" {
		fields = append(fields, clioutput.Field{Label: "group ID", Value: connection.GroupId})
	}
	return writeHumanFrame(output, "tnl publisher "+action, state, hint, clioutput.Fields(fields...))
}
