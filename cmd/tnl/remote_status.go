package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/remoteprobe"
)

type remoteProbeFlags struct {
	Remote   string `name:"remote" help:"Probe this public HTTPS origin or TCP hostname:port from this machine."`
	Protocol string `name:"protocol" help:"Protocol for a TCP address: ssh, postgres, mysql, or redis."`
	Path     string `name:"path" help:"HTTP path to probe; defaults to /."`
}

func (flags remoteProbeFlags) selection() remoteprobe.Selection {
	return remoteprobe.Selection{Address: flags.Remote, Protocol: flags.Protocol, Path: flags.Path}
}

func runRemoteStatus(ctx context.Context, flags remoteProbeFlags, outputMode statusOutputMode, output io.Writer) error {
	result, err := remoteprobe.Probe(ctx, flags.selection())
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return err
		}
		return failure.Wrap("probe public URL", failure.InvalidCommand, err)
	}
	return writeRemoteProbe(output, "tnl status", string(outputMode), result)
}

func runRemoteWait(ctx context.Context, flags waitCommand, output io.Writer) error {
	if flags.Timeout <= 0 {
		return failure.Wrap("wait for remote public URL", failure.InvalidCommand, errors.New("timeout must be positive"))
	}
	selected := flags.remoteProbeFlags.selection()
	if err := selected.Validate(); err != nil {
		return failure.Wrap("wait for remote public URL", failure.InvalidCommand, err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, flags.Timeout)
	defer cancel()
	var latest remoteprobe.Result
	for attempt := 0; ; attempt++ {
		result, err := remoteprobe.Probe(waitCtx, selected)
		if err != nil && waitCtx.Err() == nil {
			return failure.Wrap("probe remote public URL", failure.InvalidCommand, err)
		}
		if result.Reachable {
			return writeRemoteProbe(output, "tnl wait", flags.Output, result)
		}
		if !result.CheckedAt.IsZero() {
			latest = result
		}
		if waitCtx.Err() != nil {
			break
		}
		timer := time.NewTimer(clientruntime.RetryDelay(attempt))
		select {
		case <-waitCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !latest.CheckedAt.IsZero() {
		if err := writeRemoteProbe(output, "tnl wait", flags.Output, latest); err != nil {
			return err
		}
	}
	return failure.Wrap("wait for remote public URL", failure.AppReadinessTimeout,
		errors.New("public URL is not reachable from this machine; check DNS, visitor IP policy, and the publisher"))
}

func writeRemoteProbe(output io.Writer, command, mode string, result remoteprobe.Result) error {
	state := "not reachable"
	if result.Reachable {
		state = "reachable"
	}
	if mode == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int `json:"schema_version"`
			remoteprobe.Result
			State string `json:"state"`
		}{1, result, state})
	}
	fields := []clioutput.Field{{Label: "public URL", Value: result.Address}, {Label: "protocol", Value: result.Protocol},
		{Label: "checked", Value: result.CheckedAt.Format(time.RFC3339)}}
	if result.TLSVerified {
		fields = append(fields, clioutput.Field{Label: "visitor TLS", Value: "verified"})
	}
	if result.HTTPStatus != 0 {
		fields = append(fields, clioutput.Field{Label: "HTTP status", Value: strconv.Itoa(result.HTTPStatus)})
	}
	footer := "a protocol response arrived over the public visitor path"
	if !result.Reachable {
		fields = append(fields, clioutput.Field{Label: "reason", Value: result.Reason})
		footer = "check DNS, this IP's policy, and the publisher"
	}
	return writeHumanFrame(output, command, state, footer, clioutput.Fields(fields...))
}
