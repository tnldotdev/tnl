package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/integrationurls"
)

func runWebhookChoice(ctx context.Context, flags webhookChoiceCommand, project projectConfiguration, use, force bool, stdout io.Writer) error {
	if !project.Found() {
		return failure.Wrap("select webhook", failure.ProjectConfigMissing, errors.New("project configuration with an exclusive webhook is required"))
	}
	definition, found := project.Config.Webhooks[flags.Endpoint]
	if !found || definition.Delivery != "exclusive" {
		return failure.Wrap("select webhook", failure.ProjectConfigInvalid, fmt.Errorf("webhook %q must be configured with delivery: exclusive", flags.Endpoint))
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	snapshot, err := state.SnapshotProject(ctx, project.Root)
	if err != nil {
		return failure.Wrap("read webhook receivers", failure.ClientStateUnavailable, err)
	}
	var selected *clientstate.TunnelInfo
	for i := range snapshot.Tunnels {
		candidate := &snapshot.Tunnels[i]
		if candidate.Server != server || candidate.Service != definition.Service || candidate.IntegrationGroup == "" || (use && candidate.State != clientstate.TunnelStateReady) || candidate.State == clientstate.TunnelStateStale {
			continue
		}
		if selected != nil {
			return failure.Wrap("select webhook receiver", failure.InvalidTunnelFlags, fmt.Errorf("more than one %s tunnel is running in this worktree", definition.Service))
		}
		selected = candidate
	}
	if selected == nil {
		return failure.Wrap("select webhook receiver", failure.WebhookReceiverUnready, fmt.Errorf("start the %s service in this worktree before selecting webhook %s", definition.Service, flags.Endpoint))
	}
	hostname, err := state.WebhookHostname(ctx, server, selected.IntegrationGroup)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return failure.Wrap("read webhook URL", failure.WebhookReceiverUnready, err)
		}
		return failure.Wrap("read webhook URL", failure.ClientStateUnavailable, err)
	}
	_, digest, err := integrationurls.DefinitionBytes(definition)
	if err != nil {
		return failure.Wrap("validate webhook endpoint", failure.ProjectConfigInvalid, err)
	}
	command, status := "tnl webhook use", "selected"
	if use {
		err = state.ClaimWebhookReceiver(ctx, server, selected.IntegrationGroup, flags.Endpoint, selected.ID, digest, force)
	} else {
		command, status = "tnl webhook release", "released"
		err = state.ReleaseWebhookReceiver(ctx, server, selected.IntegrationGroup, flags.Endpoint, selected.ID)
	}
	if err != nil {
		switch {
		case errors.Is(err, clientstate.ErrWebhookOwned):
			return failure.Wrap("select webhook receiver", failure.WebhookOwned, err)
		case errors.Is(err, clientstate.ErrWebhookReceiverUnavailable):
			return failure.Wrap("select webhook receiver", failure.WebhookReceiverUnready, err)
		case errors.Is(err, clientstate.ErrWebhookNotSelected):
			return failure.Wrap("release webhook receiver", failure.WebhookNotSelected, err)
		default:
			return failure.Wrap("update webhook receiver", failure.ClientStateUnavailable, err)
		}
	}
	return writeHumanFrame(stdout, command, status, "", clioutput.Fields(
		clioutput.Field{Label: "webhook", Value: "https://" + hostname + definition.Path},
		clioutput.Field{Label: "receiver", Value: selected.PublicURL},
	))
}
