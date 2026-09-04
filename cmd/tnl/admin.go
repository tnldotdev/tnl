package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

type adminCommand struct {
	Server          adminServerCommands         `cmd:"" help:"Inspect a server and manage local server state."`
	Routes          adminRouteCommands          `cmd:"" help:"Inspect, suspend, and resume routes."`
	Hostnames       adminHostnameCommands       `cmd:"" help:"Inspect, remove, and quarantine hostnames."`
	Credentials     adminCredentialCommands     `cmd:"" help:"List and revoke route credentials."`
	ControlSessions adminControlSessionCommands `cmd:"" help:"List and revoke control sessions."`
	Maintenance     adminMaintenanceCommands    `cmd:"" help:"Manage maintenance controls."`
}

type adminServerCommands struct {
	Status     adminServerStatusCommand `cmd:"" help:"Show server process and route status."`
	LoginToken adminLoginTokenCommand   `cmd:"" help:"Read or rotate the local server login token."`
	Token      adminTokenCommands       `cmd:"" help:"Generate an internal authentication token."`
	Relay      adminRelayCommands       `cmd:"" help:"Manage the selected relay region."`
}

type adminServerStatusCommand struct {
	remoteFlags `embed:""`
}

type adminLoginTokenCommand struct {
	StateDir string `name:"state-dir" env:"TNLD_STATE_DIR" type:"path" help:"Directory containing persistent server state."`
	Rotate   bool   `name:"rotate" help:"Replace the login token; the server must be stopped."`
}

type adminTokenCommands struct {
	Worker  struct{} `cmd:"" help:"Generate an edge-to-worker token."`
	Service struct{} `cmd:"" help:"Generate a route-usage service token."`
}

type adminRelayCommands struct {
	Refresh adminRelayRefreshCommand `cmd:"" help:"Discover and pin the best Tailcat relay region; the server must be stopped."`
}

type adminRelayRefreshCommand struct {
	StateDir string `name:"state-dir" env:"TNLD_STATE_DIR" type:"path" help:"Directory containing persistent server state."`
}

type adminRouteCommands struct {
	List    adminRoutesListCommand   `cmd:"" help:"List current routes."`
	Show    adminRouteShowCommand    `cmd:"" help:"Show one current route."`
	Suspend adminRouteSuspendCommand `cmd:"" help:"Suspend a route and drain its sessions."`
	Resume  adminRouteResumeCommand  `cmd:"" help:"Resume a suspended route."`
}

type adminRoutesListCommand struct {
	remoteFlags `embed:""`
}
type adminRouteShowCommand struct {
	remoteFlags `embed:""`
	RouteID     string `arg:"" name:"route-id" required:""`
}
type adminRouteSuspendCommand struct {
	remoteFlags `embed:""`
	RouteID     string `arg:"" name:"route-id" required:""`
	Revision    uint64 `name:"revision" required:"" help:"Monotonically increasing suspension revision."`
	Reason      string `name:"reason" required:"" help:"Audit reason, at most 256 bytes."`
}
type adminRouteResumeCommand struct {
	remoteFlags `embed:""`
	RouteID     string `arg:"" name:"route-id" required:""`
	Revision    uint64 `name:"revision" required:"" help:"Monotonically increasing suspension revision."`
}

type adminHostnameCommands struct {
	List       adminHostnamesListCommand      `cmd:"" help:"List hostnames."`
	Show       adminHostnameShowCommand       `cmd:"" help:"Show one hostname."`
	Remove     adminHostnameRemoveCommand     `cmd:"" help:"Remove a hostname."`
	Quarantine adminHostnameQuarantineCommand `cmd:"" help:"Quarantine a hostname and drain its routes."`
}

type adminHostnamesListCommand struct {
	remoteFlags `embed:""`
}
type adminHostnameShowCommand struct {
	remoteFlags `embed:""`
	HostnameID  string `arg:"" name:"hostname-id" required:""`
}
type adminHostnameRemoveCommand struct {
	remoteFlags `embed:""`
	HostnameID  string `arg:"" name:"hostname-id" required:""`
}
type adminHostnameQuarantineCommand struct {
	remoteFlags `embed:""`
	HostnameID  string `arg:"" name:"hostname-id" required:""`
	Reason      string `name:"reason" required:"" help:"Audit reason, at most 256 bytes."`
}

type adminCredentialCommands struct {
	List   adminCredentialsListCommand  `cmd:"" help:"List route credentials without secret material."`
	Revoke adminCredentialRevokeCommand `cmd:"" help:"Revoke a route credential."`
}

type adminCredentialsListCommand struct {
	remoteFlags `embed:""`
}
type adminCredentialRevokeCommand struct {
	remoteFlags  `embed:""`
	CredentialID string `arg:"" name:"credential-id" required:""`
}

type adminControlSessionCommands struct {
	List   adminControlSessionsListCommand  `cmd:"" help:"List control sessions without tokens."`
	Revoke adminControlSessionRevokeCommand `cmd:"" help:"Revoke a control session."`
}

type adminControlSessionsListCommand struct {
	remoteFlags `embed:""`
}
type adminControlSessionRevokeCommand struct {
	remoteFlags      `embed:""`
	ControlSessionID string `arg:"" name:"control-session-id" required:""`
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

func runAdminServerStatus(
	ctx context.Context,
	command adminServerStatusCommand,
	stdout, stderr io.Writer,
) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminServerStatus(ctx)
		if err != nil {
			return adminClientError(err)
		}
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "MODE\tSTARTED\tCURRENT\tENABLED\tSUSPENDED\tPROVISIONING\tWORKERS")
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%d\t%d\t%d\n", value.Mode, adminTime(value.StartedAt),
			adminTime(value.CurrentTime), value.EnabledRoutes, value.SuspendedRoutes, value.ProvisioningRoutes, value.ConnectedWorkers)
		return table.Flush()
	})
}

func runAdminRoutesList(ctx context.Context, command adminRoutesListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tSTATUS\tHOSTNAME\tLOCAL TARGET\tROUTE VERSION\tSUSPENSION REVISION")
		if err := paginateAdmin(
			func(cursor string) ([]serverv1.AdminRoute, *serverv1.RouteID, error) {
				page, err := client.AdminListRoutes(ctx, cursor)
				return page.Routes, page.NextCursor, err
			},
			func(value serverv1.AdminRoute) { writeAdminRoute(table, value) },
			"route",
		); err != nil {
			return err
		}
		return table.Flush()
	})
}

func runAdminRouteShow(ctx context.Context, command adminRouteShowCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminRoute(ctx, command.RouteID)
		if err != nil {
			return adminClientError(err)
		}
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tSTATUS\tHOSTNAME\tLOCAL TARGET\tROUTE VERSION\tSUSPENSION REVISION")
		writeAdminRoute(table, value)
		return table.Flush()
	})
}

func runAdminRouteSuspend(ctx context.Context, command adminRouteSuspendCommand, stdout, stderr io.Writer) error {
	if !validAdminReason(command.Reason) || command.Revision == 0 {
		return errors.New("reason must be 1-256 bytes without surrounding whitespace and revision must be positive")
	}
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminSuspendRoute(ctx, command.RouteID, command.Revision, command.Reason)
		if err != nil {
			return adminClientError(err)
		}
		_, err = fmt.Fprintf(stdout, "Suspended %s at revision %d\n", value.Id, value.SuspensionRevision)
		return err
	})
}

func runAdminRouteResume(ctx context.Context, command adminRouteResumeCommand, stdout, stderr io.Writer) error {
	if command.Revision == 0 {
		return errors.New("revision must be positive")
	}
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminResumeRoute(ctx, command.RouteID, command.Revision)
		if err != nil {
			return adminClientError(err)
		}
		_, err = fmt.Fprintf(stdout, "Resumed %s at route version %d\n", value.Id, value.RouteVersion)
		return err
	})
}

func runAdminHostnamesList(ctx context.Context, command adminHostnamesListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tSTATUS\tKIND\tSOURCE\tHOSTNAME\tIDENTITY")
		if err := paginateAdmin(
			func(cursor string) ([]serverv1.AdminHostname, *serverv1.HostnameID, error) {
				page, err := client.AdminListHostnames(ctx, cursor)
				return page.Hostnames, page.NextCursor, err
			},
			func(value serverv1.AdminHostname) { writeAdminHostname(table, value) },
			"hostname",
		); err != nil {
			return err
		}
		return table.Flush()
	})
}

func runAdminHostnameShow(ctx context.Context, command adminHostnameShowCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminHostname(ctx, command.HostnameID)
		if err != nil {
			return adminClientError(err)
		}
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tSTATUS\tKIND\tSOURCE\tHOSTNAME\tIDENTITY")
		writeAdminHostname(table, value)
		return table.Flush()
	})
}

func runAdminHostnameRemove(ctx context.Context, command adminHostnameRemoveCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		if err := client.AdminRemoveHostname(ctx, command.HostnameID); err != nil {
			return adminClientError(err)
		}
		_, err := fmt.Fprintf(stdout, "Removed %s\n", command.HostnameID)
		return err
	})
}

func runAdminHostnameQuarantine(ctx context.Context, command adminHostnameQuarantineCommand, stdout, stderr io.Writer) error {
	if !validAdminReason(command.Reason) {
		return errors.New("reason must be 1-256 bytes without surrounding whitespace")
	}
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		if err := client.AdminQuarantineHostname(ctx, command.HostnameID, command.Reason); err != nil {
			return adminClientError(err)
		}
		_, err := fmt.Fprintf(stdout, "Quarantined %s\n", command.HostnameID)
		return err
	})
}

func runAdminCredentialsList(ctx context.Context, command adminCredentialsListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tROUTE\tCREATED\tREVOKED")
		if err := paginateAdmin(
			func(cursor string) ([]serverv1.AdminCredential, *serverv1.CredentialID, error) {
				page, err := client.AdminListCredentials(ctx, cursor)
				return page.Credentials, page.NextCursor, err
			},
			func(value serverv1.AdminCredential) {
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\n", value.Id, value.RouteId, adminTime(value.CreatedAt), adminOptionalTime(value.RevokedAt))
			},
			"credential",
		); err != nil {
			return err
		}
		return table.Flush()
	})
}

func runAdminCredentialRevoke(ctx context.Context, command adminCredentialRevokeCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		if err := client.AdminRevokeCredential(ctx, command.CredentialID); err != nil {
			return adminClientError(err)
		}
		_, err := fmt.Fprintf(stdout, "Revoked %s\n", command.CredentialID)
		return err
	})
}

func runAdminControlSessionsList(ctx context.Context, command adminControlSessionsListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "ID\tIDENTITY\tAUTHENTICATION\tGRANTS\tACCESS EXPIRES\tREFRESH EXPIRES\tREVOKED")
		if err := paginateAdmin(
			func(cursor string) ([]serverv1.AdminControlSession, *serverv1.ControlSessionID, error) {
				page, err := client.AdminListControlSessions(ctx, cursor)
				return page.ControlSessions, page.NextCursor, err
			},
			func(value serverv1.AdminControlSession) {
				grants := make([]string, len(value.Grants))
				for index, grant := range value.Grants {
					grants[index] = string(grant)
				}
				fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", value.Id, value.IdentityId,
					value.AuthenticationMethod, strings.Join(grants, ","), adminTime(value.AccessExpiresAt),
					adminTime(value.RefreshExpiresAt), adminOptionalTime(value.RevokedAt))
			},
			"control-session",
		); err != nil {
			return err
		}
		return table.Flush()
	})
}

func paginateAdmin[T any, C ~string](
	fetch func(string) ([]T, *C, error),
	write func(T),
	resource string,
) error {
	cursor := ""
	for {
		values, next, err := fetch(cursor)
		if err != nil {
			return adminClientError(err)
		}
		for _, value := range values {
			write(value)
		}
		if next == nil {
			return nil
		}
		nextCursor := string(*next)
		if nextCursor <= cursor || len(values) == 0 {
			return fmt.Errorf("server returned an invalid admin %s cursor", resource)
		}
		cursor = nextCursor
	}
}

func runAdminControlSessionRevoke(ctx context.Context, command adminControlSessionRevokeCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		if err := client.AdminRevokeControlSession(ctx, command.ControlSessionID); err != nil {
			return adminClientError(err)
		}
		_, err := fmt.Fprintf(stdout, "Revoked %s\n", command.ControlSessionID)
		return err
	})
}

func runAdminMaintenanceList(ctx context.Context, command adminMaintenanceListCommand, stdout, stderr io.Writer) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		values, err := client.AdminListMaintenanceControls(ctx)
		if err != nil {
			return adminClientError(err)
		}
		table := newAdminTable(stdout)
		fmt.Fprintln(table, "NAME\tENABLED\tREVISION\tUPDATED\tUPDATED BY")
		for _, value := range values {
			fmt.Fprintf(table, "%s\t%t\t%d\t%s\t%s\n", value.Name, value.Enabled, value.Revision, adminTime(value.UpdatedAt), value.UpdatedBy)
		}
		return table.Flush()
	})
}

func runAdminMaintenanceSet(
	ctx context.Context,
	command adminMaintenanceSetCommand,
	enabled bool,
	stdout, stderr io.Writer,
) error {
	return withRemoteAdminClient(ctx, command.remoteFlags, stderr, func(client *serverclient.Client) error {
		value, err := client.AdminSetMaintenanceControl(ctx, serverv1.MaintenanceControlName(command.Name), enabled)
		if err != nil {
			return adminClientError(err)
		}
		_, err = fmt.Fprintf(stdout, "%s enabled=%t revision=%d\n", value.Name, value.Enabled, value.Revision)
		return err
	})
}

func runAdminLoginToken(ctx context.Context, command adminLoginTokenCommand, stdout io.Writer) error {
	directory, err := adminServerStateDir(command.StateDir)
	if err != nil {
		return err
	}
	if command.Rotate {
		lock, err := state.LockExistingDirectory(directory)
		if err != nil {
			return err
		}
		defer lock.Close()
		db, err := state.Open(ctx, directory)
		if err != nil {
			return err
		}
		defer db.Close()
		token, err := state.RotateLoginToken(ctx, db)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, token.String())
		return err
	}
	db, err := state.OpenReadOnly(ctx, directory)
	if err != nil {
		return err
	}
	defer db.Close()
	token, err := state.ReadLoginToken(ctx, db)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token.String())
	return err
}

func runAdminTokenWorker(stdout io.Writer) error {
	token, _, err := credentials.NewWorkerToken()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token.String())
	return err
}

func runAdminTokenService(stdout io.Writer) error {
	token, err := credentials.NewServiceToken()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, token.String())
	return err
}

func runAdminRelayRefresh(ctx context.Context, command adminRelayRefreshCommand, stdout io.Writer) error {
	directory, err := adminServerStateDir(command.StateDir)
	if err != nil {
		return err
	}
	lock, err := state.LockExistingDirectory(directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	db, err := state.Open(ctx, directory)
	if err != nil {
		return err
	}
	defer db.Close()
	_, relayRegion, err := config.LoadTailcatRelayRegions(ctx, db, true)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, relayRegion)
	return err
}

func withRemoteAdminClient(
	ctx context.Context,
	flags remoteFlags,
	diagnostics io.Writer,
	run func(*serverclient.Client) error,
) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: state, AccessToken: flags.AccessToken,
		Diagnostics: diagnostics, LoginToken: loginTokenPrompt(os.Stdin, diagnostics),
	})
	if err != nil {
		return err
	}
	if err := serverclient.RequireAdministrationCapability(authenticated.ServerCapabilities); err != nil {
		return adminClientError(err)
	}
	return run(authenticated.Server)
}

func adminClientError(err error) error {
	if errors.Is(err, serverclient.ErrUnsupported) {
		return errors.New("server does not support administration version 1")
	}
	return err
}

func adminServerStateDir(value string) (string, error) {
	if value != "" {
		return value, nil
	}
	return config.DefaultStateDir()
}

func newAdminTable(output io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
}

func writeAdminRoute(table io.Writer, value serverv1.AdminRoute) {
	fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%d\t%d\n", value.Id, value.Status, value.Hostname,
		value.LocalTarget, value.RouteVersion, value.SuspensionRevision)
}

func writeAdminHostname(table io.Writer, value serverv1.AdminHostname) {
	identity := "-"
	if value.IdentityId != nil {
		identity = *value.IdentityId
	}
	fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", value.Id, value.Status, value.Kind, value.Source, value.Hostname, identity)
}

func adminTime(value time.Time) string { return value.UTC().Format(time.RFC3339) }

func adminOptionalTime(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return adminTime(*value)
}

func validAdminReason(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}
