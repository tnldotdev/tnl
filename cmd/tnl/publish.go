package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/publisher"
)

type publishCommand struct {
	openOptions `embed:""`
	remoteFlags `embed:""`
	tunnelFlags `embed:""`
	Target      string `arg:"" name:"service-or-target" optional:"" help:"Configured service name, local port, or HTTP URL on this computer."`
	Output      string `name:"output" enum:"human,ndjson" default:"human" help:"Output format: ${enum}."`

	serverFromConfig bool
	selectedTeam     string
	projectRoot      string
	Service          string `kong:"-"`
}

func runPublish(ctx context.Context, flags publishCommand, stdout, stderr io.Writer, reporters ...telemetryReporter) (result error) {
	telemetry := optionalTelemetryReporter(reporters)
	output, err := newPublishOutput(flags.Output, "tnl publish", stdout, stderr, browserOpener(flags.Open))
	if err != nil {
		return err
	}
	fail := func(err error) error {
		err = classifyCommandError(err)
		if cause := context.Cause(ctx); cause != nil {
			cause = classifyCommandError(cause)
			if errors.Is(cause, context.Canceled) {
				return errors.Join(cause, output.stopped())
			}
			_ = output.failed(cause)
			return cause
		}
		_ = output.failed(err)
		return err
	}
	target, err := localproxy.NormalizeTarget(flags.Target)
	if err != nil {
		return fail(err)
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return fail(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: serverURL, Target: target,
		Project: flags.projectRoot, Service: flags.Service,
	})
	if err != nil {
		return fail(err)
	}
	ctx = tunnel.Context()
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		result = errors.Join(result, tunnel.Finish(finishCtx, result))
	}()
	if err := output.starting(tunnel.ID(), target); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, target); err != nil {
		return fail(err)
	}
	authenticated, err := authenticatePublisher(ctx, state, serverURL, flags.AccessToken, "tnl publish", os.Stdin, stderr)
	if err != nil {
		return fail(err)
	}
	allowedIPPrefixes, currentIP, err := resolveIPPolicy(ctx, authenticated.Control, flags.AllowIP, flags.Public)
	if err != nil {
		return fail(err)
	}
	if currentIP != "" {
		if err := output.currentIP(currentIP); err != nil {
			return err
		}
	}
	services, err := preparePublisherServices(
		ctx, state, serverURL, flags.Host, flags.Subdomain, flags.selectedTeam, flags.Ephemeral, authenticated,
	)
	if err != nil {
		return fail(err)
	}
	publisherConfig := services.config(target, allowedIPPrefixes)
	publisherConfig.Logf = output.logf
	publisherConfig.Observe = withTelemetryObserver(telemetry, "publish", serverURL, "", func(event publisher.Event) error {
		return handlePublisherEvent(ctx, tunnel, output, event)
	})
	err = publisher.Run(ctx, publisherConfig)
	if cause := context.Cause(ctx); cause != nil {
		return fail(cause)
	}
	if err != nil && !(ctx.Err() != nil && errors.Is(err, context.Canceled)) {
		return fail(err)
	}
	return output.stopped()
}
