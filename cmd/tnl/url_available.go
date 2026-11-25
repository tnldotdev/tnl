package main

import (
	"context"
	"encoding/json"
	"io"
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
	return writeVisitorURLs(o, items)
}
