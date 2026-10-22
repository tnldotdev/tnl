package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
)

type pingCommand struct {
	URL      string           `arg:"" name:"url" help:"Public HTTPS URL to check from this machine."`
	Protocol string           `name:"protocol" enum:"http" default:"http" help:"Public URL protocol: http."`
	Output   statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runPing(ctx context.Context, flags pingCommand, output io.Writer) error {
	address, protocol, err := clientruntime.PingAddress(flags.URL, flags.Protocol)
	if err != nil {
		return failure.Wrap("select visitor address", failure.InvalidCommand, err)
	}
	result := clientruntime.Ping(ctx, address, protocol)
	if flags.Output == statusOutputJSON {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return err
		}
	} else if err := writeHumanFrame(output, "tnl ping", result.State, "", clioutput.Fields(
		clioutput.Field{Label: "visitor", Value: "this machine"},
		clioutput.Field{Label: "address", Value: result.Address},
		clioutput.Field{Label: "protocol", Value: result.Protocol},
		clioutput.Field{Label: "checked at", Value: result.CheckedAt.Format("2006-01-02T15:04:05.999999999Z07:00")},
		clioutput.Field{Label: "HTTP status", Value: pingStatus(result.Status)},
		clioutput.Field{Label: "tnl error code", Value: result.Code},
		clioutput.Field{Label: "note", Value: result.Note},
	)); err != nil {
		return err
	}
	if result.State == "unavailable" || result.State == "tnl denied" || result.State == "invalid address" || result.State == "invalid protocol" {
		return failure.Wrap("ping public URL", failure.TunnelUnavailable, errors.New(result.State))
	}
	return nil
}

func pingStatus(status int) string {
	if status == 0 {
		return ""
	}
	return strconv.Itoa(status)
}
