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
	Drain adminRelayDrainCommand `cmd:"" help:"Drain one matching relay lease."`
}

type adminRelaysListCommand struct {
	remoteFlags `embed:""`
}

type adminRelayDrainCommand struct {
	remoteFlags        `embed:""`
	RelayID            string        `arg:"" name:"relay-id" required:"" help:"Relay ID to drain."`
	RelayRunID         string        `name:"relay-run-id" required:"" help:"Exact relay process run ID."`
	RelayLeaseRevision int64         `name:"relay-lease-revision" required:"" help:"Exact relay lease revision."`
	Deadline           time.Duration `name:"deadline" default:"30s" help:"Drain deadline from now."`
}

type adminMaintenanceCommands struct {
	List  adminMaintenanceListCommand `cmd:"" help:"List maintenance controls."`
	Allow adminMaintenanceSetCommand  `cmd:"" help:"Allow the selected operation."`
	Block adminMaintenanceSetCommand  `cmd:"" help:"Block the selected operation."`
}

type adminMaintenanceListCommand struct {
	remoteFlags `embed:""`
}

type adminMaintenanceSetCommand struct {
	remoteFlags `embed:""`
	Name        controlv1.MaintenanceControlName `arg:"" name:"name" required:"" enum:"public_url_creation,publish_run_creation,certificate_issuance" help:"Maintenance control to change."`
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
				clioutput.Field{Label: "role", Value: string(value.Role)},
				clioutput.Field{Label: "public URLs", Value: fmt.Sprintf("%d enabled / %d suspended", value.EnabledPublicUrls, value.SuspendedPublicUrls)},
				clioutput.Field{Label: "publish runs", Value: fmt.Sprintf("%d ready / %d starting", value.ReadyPublishRuns, value.StartingPublishRuns)},
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
				{Label: "relay service", Value: string(value.RelayServiceId)},
				{Label: "process run", Value: string(value.RelayRunId)},
				{Label: "lease revision", Value: strconv.FormatInt(value.RelayLeaseRevision, 10)},
				{Label: "relay address", Value: value.RelayAddress},
				{Label: "internal address", Value: value.InternalRelayAddress},
				{Label: "publisher connections", Value: fmt.Sprintf("%d / %d", value.ReportedConnections, value.ConnectionCapacity)},
				{Label: "visitor streams", Value: fmt.Sprintf("%d / %d", value.ReportedStreams, value.StreamCapacity)},
				{Label: "lease expires", Value: adminTime(value.LeaseExpiresAt)},
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
			clioutput.Field{Label: "process run", Value: string(lease.RelayRunId)},
			clioutput.Field{Label: "lease revision", Value: strconv.FormatInt(lease.RelayLeaseRevision, 10)},
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
				clioutput.Field{Label: "state", Value: allowedState(value.Allowed)},
				clioutput.Field{Label: "control revision", Value: strconv.FormatInt(value.Revision, 10)},
				clioutput.Field{Label: "updated", Value: adminTime(value.UpdatedAt)},
				clioutput.Field{Label: "updated by", Value: string(value.UpdatedBy)},
			)))
		}
		return writeHumanFrame(stdout, "tnl admin maintenance list", countState(len(blocks), "control", "controls"), "", blocks...)
	})
}

func runAdminMaintenanceSet(ctx context.Context, command adminMaintenanceSetCommand, allowed bool, stdout, stderr io.Writer) error {
	action := "block"
	if allowed {
		action = "allow"
	}
	commandName := "tnl admin maintenance " + action
	return withRemoteAdminClient(ctx, command.remoteFlags, commandName, stderr, func(client *controlclient.Client) error {
		value, err := client.AdminSetMaintenanceControl(ctx, command.Name, allowed)
		if err != nil {
			return err
		}
		return writeHumanTransition(stdout, commandName, "updated", string(value.Name), "", allowedState(value.Allowed), "",
			clioutput.Field{Label: "control revision", Value: strconv.FormatInt(value.Revision, 10)})
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
