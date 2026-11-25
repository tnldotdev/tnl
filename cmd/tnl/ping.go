package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

type pingCommand struct {
	URL    string           `arg:"" name:"url" help:"HTTP or HTTPS URL to check from this machine."`
	Output statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runPing(ctx context.Context, flags pingCommand, output, diagnostics io.Writer) error {
	address, protocol, err := publisherapp.PingAddress(flags.URL)
	if err != nil {
		return failure.Wrap("select visitor address", failure.InvalidCommand, &pingFailure{state: "invalid address", cause: err})
	}
	stopProgress := clioutput.StartProgress(ctx, output, diagnostics, flags.Output != statusOutputJSON, "Checking HTTP response")
	result := publisherapp.Ping(ctx, address, protocol)
	stopProgress()
	if flags.Output == statusOutputJSON {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return err
		}
	} else {
		if err := writeResult(output, clioutput.Line(pingStatus(result)+"  "+result.Address)); err != nil {
			return err
		}
	}
	if result.State == "unavailable" || result.State == "tnl denied" || result.State == "invalid address" || result.State == "invalid protocol" {
		return failure.Wrap("ping public URL", failure.TunnelUnavailable, &pingFailure{state: result.State, code: result.Code})
	}
	return nil
}

func pingStatus(result publisherapp.PingResult) string {
	if result.Status == 0 {
		return "No HTTP response"
	}
	status := "HTTP " + strconv.Itoa(result.Status)
	if name := http.StatusText(result.Status); name != "" {
		status += " " + name
	}
	if result.Code != "" {
		return status + " (tnl: " + result.Code + ")"
	}
	switch result.Status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		status += " (redirect not followed)"
	}
	return status
}

type pingFailure struct {
	state, code string
	cause       error
}

func (e *pingFailure) Unwrap() error { return e.cause }

func (e *pingFailure) Error() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return e.state
}

func (e *pingFailure) message() string {
	switch e.state {
	case "tnl denied":
		if code := diagnostic.Code(e.code); slices.Contains(diagnostic.Codes(), code) {
			return diagnostic.Summary(code)
		}
		return "tnl rejected the request before the app responded."
	case "invalid address", "invalid protocol":
		return "provide a full HTTP or HTTPS URL."
	default:
		return "the connection or TLS verification failed."
	}
}

func (a *commandApp) newPingCommand() *cobra.Command {
	f := a.flags
	cPing := &cobra.Command{
		Use: "ping", Short: "Check an HTTP or HTTPS URL without signing in.", GroupID: "observe",
		Long: "Send a GET request from this machine without following redirects. Use the full URL, including http:// or https://. The command exits 0 when the app sends any HTTP response, even a 404 or 500. Use tnl wait to check configured readiness.",
	}
	a.leaf(cPing, &f.Ping, func(call commandCall) error {
		return runPing(call.ctx, f.Ping, a.out, a.errOut)
	})
	return cPing
}
