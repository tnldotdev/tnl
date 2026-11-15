package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
)

type urlAvailableCommand struct {
	remoteFlags `embed:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

func runURLAvailable(ctx context.Context, f urlAvailableCommand, o, d io.Writer) error {
	s, err := openTeamSession(ctx, f.remoteFlags, "tnl url available", d)
	if err != nil {
		return err
	}
	defer s.Close()
	items, err := visitorURLList(ctx, s.Authenticated().Control, "")
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return json.NewEncoder(o).Encode(items)
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		address, err := servicePublicAddress(item.Protocol, item.Endpoint)
		if err != nil {
			return err
		}
		blocks = append(blocks, clioutput.Section(item.Endpoint.Hostname, clioutput.Fields(
			clioutput.Field{Label: "public URL", Value: address},
			clioutput.Field{Label: "service ID", Value: item.Id},
			clioutput.Field{Label: "team ID", Value: item.TeamId},
			clioutput.Field{Label: "team", Value: item.TeamName},
			clioutput.Field{Label: "protocol", Value: string(item.Protocol)},
			clioutput.Field{Label: "access", Value: string(item.VisitorAccess)},
		)))
	}
	return writeHumanFrame(o, "tnl url available", countState(len(items), "public URL", "public URLs"), "", blocks...)
}
