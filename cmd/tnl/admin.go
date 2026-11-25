package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type adminCommand struct {
	Server      adminServerCommands
	Relays      adminRelayCommands
	Maintenance adminMaintenanceCommands
}

type adminServerCommands struct {
	Status adminServerStatusCommand
}

type adminServerStatusCommand struct {
	remoteFlags `embed:""`
}

type adminRelayCommands struct {
	List  adminRelaysListCommand
	Drain adminRelayDrainCommand
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
	List  adminMaintenanceListCommand
	Allow adminMaintenanceSetCommand
	Block adminMaintenanceSetCommand
}

type adminMaintenanceListCommand struct {
	remoteFlags `embed:""`
}

type adminMaintenanceSetCommand struct {
	remoteFlags `embed:""`
	Name        controlv1.MaintenanceControlName `arg:"" name:"name" required:"" enum:"service_creation,service_run_creation,certificate_issuance" help:"Maintenance control to change."`
}

func runAdminServerStatus(ctx context.Context, command adminServerStatusCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin server status", stderr, func(client *clientcontrol.Client, server string) error {
		value, err := client.AdminServerStatus(ctx)
		if err != nil {
			return err
		}
		return writeResult(stdout,
			clioutput.Fields(
				clioutput.Field{Label: "server", Value: server},
				clioutput.Field{Label: "role", Value: string(value.Role)},
				clioutput.Field{Label: "ingress", Value: countState(value.IngressLeases, "lease", "leases")},
				clioutput.Field{Label: "relays", Value: countState(value.RelayLeases, "lease", "leases")},
				clioutput.Field{Label: "services", Value: fmt.Sprintf("%d enabled / %d suspended", value.EnabledServices, value.SuspendedServices)},
				clioutput.Field{Label: "service runs", Value: fmt.Sprintf("%d ready / %d starting", value.ReadyServiceRuns, value.StartingServiceRuns)},
			),
		)
	})
}

func runAdminRelaysList(ctx context.Context, command adminRelaysListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin relays list", stderr, func(client *clientcontrol.Client, server string) error {
		page, err := client.AdminListRelays(ctx)
		if err != nil {
			return err
		}
		var rows [][]string
		for _, value := range page.Relays {
			state := "active"
			if value.Draining {
				state = "draining"
			}
			if value.DrainDeadline != nil {
				state += " until " + adminTime(*value.DrainDeadline)
			}
			rows = append(rows, []string{string(value.RelayId), state, fmt.Sprint(value.ReportedConnections, "/", value.ConnectionCapacity), string(value.RelayRunId), strconv.FormatInt(value.RelayLeaseRevision, 10)})
		}
		return writeResult(stdout, clioutput.Table([]string{"RELAY", "STATE", "CONNECTIONS", "RUN ID", "LEASE REVISION"}, rows, "No relay leases."))
	})
}

func runAdminRelayDrain(ctx context.Context, command adminRelayDrainCommand, stdout, stderr io.Writer) error {
	if command.RelayLeaseRevision < 1 || command.Deadline <= 0 {
		return failure.Wrap("validate relay drain", failure.InvalidCommand, errors.New("relay lease revision and deadline must be positive"))
	}
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin relays drain", stderr, func(client *clientcontrol.Client, server string) error {
		lease, err := client.AdminDrainRelay(ctx, command.RelayID, controlv1.AdminDrainRelayRequest{
			RelayRunId: command.RelayRunID, RelayLeaseRevision: command.RelayLeaseRevision,
			Deadline: time.Now().Add(command.Deadline).UTC(),
		})
		if err != nil {
			return err
		}
		footer := ""
		if lease.DrainDeadline != nil {
			footer = "deadline " + adminTime(*lease.DrainDeadline)
		}
		return writeWithHint(stdout, footer, clioutput.Line(string(lease.RelayId)+": rejecting new work"))
	})
}

func runAdminMaintenanceList(ctx context.Context, command adminMaintenanceListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, "tnl admin maintenance list", stderr, func(client *clientcontrol.Client, server string) error {
		values, err := client.AdminListMaintenanceControls(ctx)
		if err != nil {
			return err
		}
		var rows [][]string
		for _, value := range values {
			rows = append(rows, []string{string(value.Name), allowedState(value.Allowed)})
		}
		return writeResult(stdout, clioutput.Table([]string{"OPERATION", "STATE"}, rows, "No maintenance controls."))
	})
}

func runAdminMaintenanceSet(ctx context.Context, command adminMaintenanceSetCommand, allowed bool, stdout, stderr io.Writer) error {
	action := "block"
	if allowed {
		action = "allow"
	}
	commandName := "tnl admin maintenance " + action
	return withRemoteAdminClient(ctx, command.remoteFlags, commandName, stderr, func(client *clientcontrol.Client, server string) error {
		value, err := client.AdminSetMaintenanceControl(ctx, command.Name, allowed)
		if err != nil {
			return err
		}
		return writeResult(stdout, clioutput.Line(string(value.Name)+": "+allowedState(value.Allowed)))
	})
}

func withRemoteAdminClient(ctx context.Context, flags remoteFlags, command string, diagnostics io.Writer, run func(*clientcontrol.Client, string) error) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	if err := auth.RequireSignInOutsideDemo(ctx, state, serverURL, flags.AccessToken); err != nil {
		return err
	}
	authenticated, err := auth.Authenticate(ctx, auth.Config{
		ServerEndpoint: serverURL, State: state, AccessToken: flags.AccessToken,
		Diagnostics:          diagnostics,
		AuthenticationPrompt: authenticationPrompt(diagnostics, command),
		OpenURL:              interactiveBrowserOpener(os.Stdin),
	})
	if err != nil {
		return err
	}
	return run(authenticated.Control, serverURL)
}

func adminTime(value time.Time) string { return value.UTC().Format(time.RFC3339) }

func (a *commandApp) newAdminCommand() *cobra.Command {
	f := a.flags
	cAdmin := &cobra.Command{Use: "admin", Short: "Check or maintain a self-hosted tnl server.", GroupID: "observe"}
	cAdminServer := &cobra.Command{Use: "server", Short: "Inspect a tnl server."}
	cAdminServerStatus := &cobra.Command{Use: "status", Short: "Show control, ingress, and relay status."}
	a.leaf(cAdminServerStatus, &f.Admin.Server.Status, func(call commandCall) error {
		return runAdminServerStatus(call.ctx, f.Admin.Server.Status, a.out, a.errOut)
	})
	cAdminServer.AddCommand(cAdminServerStatus)
	cAdmin.AddCommand(cAdminServer)
	cAdminRelays := &cobra.Command{Use: "relays", Short: "Inspect and drain relay leases."}
	cAdminRelaysList := &cobra.Command{Use: "list", Short: "List relay leases."}
	a.leaf(cAdminRelaysList, &f.Admin.Relays.List, func(call commandCall) error {
		return runAdminRelaysList(call.ctx, f.Admin.Relays.List, a.out, a.errOut)
	})
	cAdminRelays.AddCommand(cAdminRelaysList)
	cAdminRelaysDrain := &cobra.Command{Use: "drain", Short: "Drain one relay lease; use tnl admin relays list for its run ID and revision."}
	a.leaf(cAdminRelaysDrain, &f.Admin.Relays.Drain, func(call commandCall) error {
		return runAdminRelayDrain(call.ctx, f.Admin.Relays.Drain, a.out, a.errOut)
	})
	cAdminRelays.AddCommand(cAdminRelaysDrain)
	cAdmin.AddCommand(cAdminRelays)
	cAdminMaintenance := &cobra.Command{Use: "maintenance", Short: "Manage maintenance controls."}
	cAdminMaintenanceList := &cobra.Command{Use: "list", Short: "List maintenance controls."}
	a.leaf(cAdminMaintenanceList, &f.Admin.Maintenance.List, func(call commandCall) error {
		return runAdminMaintenanceList(call.ctx, f.Admin.Maintenance.List, a.out, a.errOut)
	})
	cAdminMaintenance.AddCommand(cAdminMaintenanceList)
	cAdminMaintenanceAllow := &cobra.Command{Use: "allow", Short: "Allow the selected operation."}
	a.leaf(cAdminMaintenanceAllow, &f.Admin.Maintenance.Allow, func(call commandCall) error {
		return runAdminMaintenanceSet(call.ctx, f.Admin.Maintenance.Allow, true, a.out, a.errOut)
	})
	cAdminMaintenance.AddCommand(cAdminMaintenanceAllow)
	cAdminMaintenanceBlock := &cobra.Command{Use: "block", Short: "Block the selected operation."}
	a.leaf(cAdminMaintenanceBlock, &f.Admin.Maintenance.Block, func(call commandCall) error {
		return runAdminMaintenanceSet(call.ctx, f.Admin.Maintenance.Block, false, a.out, a.errOut)
	})
	cAdminMaintenance.AddCommand(cAdminMaintenanceBlock)
	cAdmin.AddCommand(cAdminMaintenance)
	return cAdmin
}
