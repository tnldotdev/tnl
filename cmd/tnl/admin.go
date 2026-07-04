package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type adminCommand struct {
	Server      adminServerCommands      `cmd:"" help:"Inspect a tnl server."`
	Relays      adminRelayCommands       `cmd:"" help:"Inspect and drain relay leases."`
	Maintenance adminMaintenanceCommands `cmd:"" help:"Manage maintenance controls."`
}

type adminServerCommands struct {
	Status adminServerStatusCommand `cmd:"" help:"Show control, ingress, and relay status."`
}

type adminServerStatusCommand struct {
	remoteFlags `embed:""`
}

type adminRelayCommands struct {
	List  adminRelaysListCommand `cmd:"" help:"List relay leases."`
	Drain adminRelayDrainCommand `cmd:"" help:"Drain one exact relay lease."`
}

type adminRelaysListCommand struct {
	remoteFlags `embed:""`
}

type adminRelayDrainCommand struct {
	remoteFlags        `embed:""`
	RelayID            string        `arg:"" name:"relay-id" required:""`
	RelayRunID         string        `name:"relay-run-id" required:"" help:"Exact relay process run ID."`
	RelayLeaseRevision int64         `name:"relay-lease-revision" required:"" help:"Exact relay lease revision."`
	Deadline           time.Duration `name:"deadline" default:"30s" help:"Drain deadline from now."`
}

type adminMaintenanceCommands struct {
	List    adminMaintenanceListCommand `cmd:"" help:"List maintenance controls."`
	Enable  adminMaintenanceSetCommand  `cmd:"" help:"Enable a maintenance control."`
	Disable adminMaintenanceSetCommand  `cmd:"" help:"Disable a maintenance control."`
}

type adminMaintenanceListCommand struct {
	remoteFlags `embed:""`
}

type adminMaintenanceSetCommand struct {
	remoteFlags `embed:""`
	Name        string `arg:"" name:"name" required:"" enum:"route_creation,route_session_creation,certificate_issuance"`
}

func runAdminServerStatus(ctx context.Context, command adminServerStatusCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin server status", stderr, func(client *controlclient.Client) error {
		value, err := client.AdminServerStatus(ctx)
		if err != nil {
			return err
		}
		return writeHumanFrame(stdout, "tnl admin server status", "serving", "",
			clioutput.Tree(clioutput.TreeNode{Label: "control", Children: []clioutput.TreeNode{
				{Label: "ingress", Value: countState(value.IngressLeases, "lease", "leases")},
				{Label: "relays", Value: countState(value.RelayLeases, "lease", "leases")},
			}}),
			clioutput.Fields(
				clioutput.Field{Label: "mode", Value: string(value.Mode)},
				clioutput.Field{Label: "routes", Value: fmt.Sprintf("%d enabled / %d suspended", value.EnabledRoutes, value.SuspendedRoutes)},
				clioutput.Field{Label: "sessions", Value: fmt.Sprintf("%d ready / %d starting", value.ReadyRouteSessions, value.StartingRouteSessions)},
				clioutput.Field{Label: "started", Value: adminTime(value.StartedAt)},
				clioutput.Field{Label: "current", Value: adminTime(value.CurrentTime)},
			),
		)
	})
}

func runAdminRelaysList(ctx context.Context, command adminRelaysListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin relays list", stderr, func(client *controlclient.Client) error {
		page, err := client.AdminListRelays(ctx)
		if err != nil {
			return err
		}
		blocks := make([]clioutput.Block, 0, len(page.Relays))
		for _, value := range page.Relays {
			state := "active"
			if value.Draining {
				state = "draining"
			}
			fields := []clioutput.Field{
				{Label: "service", Value: string(value.RelayServiceId)},
				{Label: "run", Value: string(value.RelayRunId)},
				{Label: "revision", Value: strconv.FormatInt(value.RelayLeaseRevision, 10)},
				{Label: "relay address", Value: value.RelayAddress},
				{Label: "internal address", Value: value.InternalRelayAddress},
				{Label: "connections", Value: fmt.Sprintf("%d / %d", value.ReportedConnections, value.ConnectionCapacity)},
				{Label: "streams", Value: fmt.Sprintf("%d / %d", value.ReportedStreams, value.StreamCapacity)},
				{Label: "expires", Value: adminTime(value.ExpiresAt)},
			}
			if value.DrainDeadline != nil {
				fields = append(fields, clioutput.Field{Label: "drain deadline", Value: adminTime(*value.DrainDeadline)})
			}
			blocks = append(blocks, clioutput.Section(string(value.RelayId)+" / "+state, clioutput.Fields(fields...)))
		}
		return writeHumanFrame(stdout, "tnl admin relays list", countState(len(blocks), "relay process", "relay processes"), "", blocks...)
	})
}

func runAdminRelayDrain(ctx context.Context, command adminRelayDrainCommand, stdout, stderr io.Writer) error {
	if command.RelayLeaseRevision < 1 || command.Deadline <= 0 {
		return errors.New("relay lease revision and deadline must be positive")
	}
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin relays drain", stderr, func(client *controlclient.Client) error {
		lease, err := client.AdminDrainRelay(ctx, command.RelayID, controlv1.AdminDrainRelayRequest{
			RelayRunId: command.RelayRunID, RelayLeaseRevision: command.RelayLeaseRevision,
			Deadline: time.Now().Add(command.Deadline).UTC(),
		})
		if err != nil {
			return err
		}
		footer := "rejecting new work"
		if lease.DrainDeadline != nil {
			footer = "deadline " + adminTime(*lease.DrainDeadline)
		}
		return writeHumanTransition(stdout, "tnl admin relays drain", "draining", string(lease.RelayId), "", "rejecting new work", footer,
			clioutput.Field{Label: "run", Value: string(lease.RelayRunId)},
			clioutput.Field{Label: "revision", Value: strconv.FormatInt(lease.RelayLeaseRevision, 10)},
		)
	})
}

func runAdminMaintenanceList(ctx context.Context, command adminMaintenanceListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin maintenance list", stderr, func(client *controlclient.Client) error {
		values, err := client.AdminListMaintenanceControls(ctx)
		if err != nil {
			return err
		}
		blocks := make([]clioutput.Block, 0, len(values))
		for _, value := range values {
			blocks = append(blocks, clioutput.Section(string(value.Name), clioutput.Fields(
				clioutput.Field{Label: "state", Value: enabledState(value.Enabled)},
				clioutput.Field{Label: "revision", Value: strconv.FormatInt(value.Revision, 10)},
				clioutput.Field{Label: "updated", Value: adminTime(value.UpdatedAt)},
				clioutput.Field{Label: "updated by", Value: string(value.UpdatedBy)},
			)))
		}
		return writeHumanFrame(stdout, "tnl admin maintenance list", countState(len(blocks), "control", "controls"), "", blocks...)
	})
}

func runAdminMaintenanceSet(ctx context.Context, command adminMaintenanceSetCommand, enabled bool, stdout, stderr io.Writer) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	commandName := "tnl admin maintenance " + action
	return withRemoteAdminClient(ctx, command.remoteFlags, commandName, stderr, func(client *controlclient.Client) error {
		value, err := client.AdminSetMaintenanceControl(ctx, controlv1.MaintenanceControlName(command.Name), enabled)
		if err != nil {
			return err
		}
		return writeHumanTransition(stdout, commandName, "updated", string(value.Name), "", enabledState(value.Enabled), "",
			clioutput.Field{Label: "revision", Value: strconv.FormatInt(value.Revision, 10)})
	})
}

func withRemoteAdminClient(ctx context.Context, flags remoteFlags, command string, diagnostics io.Writer, run func(*controlclient.Client) error) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: state, AccessToken: flags.AccessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
		AuthenticationPrompt: authenticationPrompt(diagnostics, command),
		OpenURL:              interactiveBrowserOpener(os.Stdin),
	})
	if err != nil {
		return err
	}
	return run(authenticated.Control)
}

func adminTime(value time.Time) string { return value.UTC().Format(time.RFC3339) }
