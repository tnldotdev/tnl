package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	items := []controlv1.AvailablePublicURL{}
	cursor := ""
	for {
		page, err := s.authenticated.Control.ListAvailablePublicURLs(ctx, "", cursor)
		if err != nil {
			return err
		}
		items = append(items, page.PublicUrls...)
		if page.NextCursor == nil {
			break
		}
		if *page.NextCursor == cursor {
			return failure.Wrap("read visitor inventory", failure.ServerResponseInvalid, errors.New("invalid visitor inventory cursor"))
		}
		cursor = *page.NextCursor
	}
	if f.Output == statusOutputJSON {
		return json.NewEncoder(o).Encode(items)
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		blocks = append(blocks, clioutput.Section(item.CanonicalHostname, clioutput.Fields(clioutput.Field{Label: "public URL ID", Value: item.Id}, clioutput.Field{Label: "team", Value: item.TeamName}, clioutput.Field{Label: "protocol", Value: item.ServiceProtocol}, clioutput.Field{Label: "access", Value: string(item.VisitorAccess)})))
	}
	return writeHumanFrame(o, "tnl url available", countState(len(items), "public URL", "public URLs"), "", blocks...)
}
