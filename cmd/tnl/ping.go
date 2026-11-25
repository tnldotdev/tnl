package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

type pingCommand struct {
	URL    string           `arg:"" name:"url" help:"HTTP or HTTPS URL to check from this machine."`
	Output statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runPing(ctx context.Context, flags pingCommand, output io.Writer) error {
	address, protocol, err := publisherapp.PingAddress(flags.URL)
	if err != nil {
		return failure.Wrap("select visitor address", failure.InvalidCommand, err)
	}
	result := publisherapp.Ping(ctx, address, protocol)
	if flags.Output == statusOutputJSON {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return err
		}
	} else {
		state := result.State
		if result.Status != 0 {
			state = "HTTP " + strconv.Itoa(result.Status) + " (" + state + ")"
		}
		if result.Code != "" {
			state += ": " + result.Code
		} else if result.Note != "" {
			state += ": " + result.Note
		}
		if err := writeResult(output, clioutput.Line(state+"  "+result.Address)); err != nil {
			return err
		}
	}
	if result.State == "unavailable" || result.State == "tnl denied" || result.State == "invalid address" || result.State == "invalid protocol" {
		return failure.Wrap("ping public URL", failure.TunnelUnavailable, errors.New(result.State))
	}
	return nil
}

func (a *commandApp) newPingCommand() *cobra.Command {
	f := a.flags
	cPing := &cobra.Command{
		Use: "ping", Short: "Check an HTTP or HTTPS URL without signing in.", GroupID: "observe",
		Long: "Send a GET request from this machine and report the result without following redirects. Use the full URL, including http:// or https://.",
	}
	a.leaf(cPing, &f.Ping, func(call commandCall) error {
		return runPing(call.ctx, f.Ping, a.out)
	})
	return cPing
}
