package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicURLCommand struct {
	List      publicURLListCommand
	Available urlAvailableCommand
	Inventory publicURLInventoryCommand
	Access    urlAccessCommand
	Update    publicURLUpdateCommand
	Delete    publicURLDeleteCommand
}

type publicURLUpdateCommand struct {
	scopedTeamFlags `embed:""`
	Service         string `arg:"" name:"service-or-address" required:"" help:"Service name, service ID, hostname, host:port, or service URL."`
	Target          string `name:"target" help:"New HTTP or HTTPS target origin; no connection is made from this command."`
}

type publicURLListCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type publicURLInventoryCommand struct {
	scopedTeamFlags `embed:""`
}

type publicURLDeleteCommand struct {
	scopedTeamFlags `embed:""`
	Service         string `arg:"" name:"service-or-address" required:"" help:"Service name, service ID, hostname, host:port, or service URL to delete."`
	Unconditional   bool   `name:"unconditional" help:"Delete despite concurrent saved-service changes; current management permission is still required."`
	selector        naming.ServiceSelector
}

func runURLList(ctx context.Context, command publicURLListCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	items, err := visitorURLList(ctx, session.Authenticated().Control, command.Team)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(items)
	}
	return writeVisitorURLs(output, items)
}

func writeVisitorURLs(output io.Writer, items []controlv1.ServiceSummary) error {
	var rows [][]string
	for _, item := range items {
		address, err := servicePublicAddress(item.Protocol, item.Endpoint)
		if err != nil {
			return err
		}
		rows = append(rows, []string{item.TeamName, item.Name, string(item.VisitorAccess), address})
	}
	return writeResult(output, clioutput.Table([]string{"TEAM", "SERVICE", "ACCESS", "ADDRESS"}, rows, "No public URLs."))
}

type visitorURLListClient interface {
	ListAvailableServices(context.Context, controlv1.ServiceAccessPath) ([]controlv1.ServiceSummary, error)
}

func visitorURLList(ctx context.Context, control visitorURLListClient, team string) ([]controlv1.ServiceSummary, error) {
	items, err := control.ListAvailableServices(ctx, controlv1.ServiceAccessPathPublicEndpoint)
	if err != nil {
		return nil, err
	}
	items = slices.DeleteFunc(items, func(item controlv1.ServiceSummary) bool {
		return item.Endpoint == nil || !item.Endpoint.Public || team != "" && item.TeamId != team && item.TeamName != team
	})
	return items, nil
}

func servicePublicAddress(protocol controlv1.ServiceProtocol, endpoint *controlv1.ServiceEndpoint) (string, error) {
	if endpoint == nil || !endpoint.Public || !serviceendpoint.Valid(string(protocol), endpoint.Hostname, endpoint.Port, endpoint.Public) {
		return "", failure.Wrap("read service endpoint", failure.ServerResponseInvalid, errors.New("service has no public endpoint"))
	}
	address := net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port))
	if protocol == controlv1.ServiceProtocolHTTP {
		if endpoint.Port == 443 {
			address = endpoint.Hostname
		}
		return "https://" + address, nil
	}
	return address, nil
}

func resolveManagedService(ctx context.Context, session *clientteam.Session, selector string) (controlv1.ServiceSummary, error) {
	input, err := parseWholeService(selector, failure.InvalidCommand)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	return lookupManagedService(ctx, session, input)
}

func lookupManagedService(ctx context.Context, session *clientteam.Session, input naming.ServiceSelector) (controlv1.ServiceSummary, error) {
	current, err := session.Current(ctx)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	// a manager need not also have visitor permission. retain defining inventory
	// summaries; trust/configuration operations fetch their exact service later.
	items, err := session.Authenticated().Control.ListServices(ctx, current.Team().Id)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	items = slices.DeleteFunc(items, func(item controlv1.ServiceSummary) bool { return item.TeamId != current.Team().Id })
	return matchInventory(input, items, failure.InvalidCommand)
}

func runURLInventory(ctx context.Context, command publicURLInventoryCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url inventory", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	services, err := session.Authenticated().Control.ListServices(ctx, current.Team().Id)
	if err != nil {
		return err
	}
	var rows [][]string
	for _, service := range services {
		if service.Endpoint == nil || !service.Endpoint.Public {
			continue
		}
		state := "disabled"
		if service.Enabled {
			state = "enabled"
		}
		address, err := servicePublicAddress(service.Protocol, service.Endpoint)
		if err != nil {
			return err
		}
		rows = append(rows, []string{service.Name, state, service.Id, address})
	}
	return writeResult(output, clioutput.Table([]string{"SERVICE", "STATE", "SERVICE ID", "ADDRESS"}, rows, "No public URLs."))
}

func runURLDelete(ctx context.Context, command publicURLDeleteCommand, output, diagnostics io.Writer) error {
	if command.selector.Kind == naming.SelectorOmitted {
		return serviceInputError(failure.InvalidCommand, "Select a service to delete.")
	}
	session, err := openTeamSession(ctx, command.selection(), "tnl url delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, err := lookupManagedService(ctx, session, command.selector)
	if err != nil {
		return err
	}
	if err := deleteManagedService(ctx, session.Authenticated().Control, selected.Id, command.Unconditional); err != nil {
		return err
	}
	return writeResult(output, clioutput.Line("Deleted "+selected.Name+"."))
}

type serviceDeletionClient interface {
	GetService(context.Context, string) (controlv1.Service, error)
	DeleteService(context.Context, string, controlv1.DeleteServiceParams) error
}

func deleteManagedService(ctx context.Context, control serviceDeletionClient, id string, unconditional bool) error {
	if unconditional {
		return control.DeleteService(ctx, id, controlv1.DeleteServiceParams{UnconditionalDelete: new(true)})
	}
	current, err := control.GetService(ctx, id)
	if err != nil {
		return err
	}
	if current.Id != id || current.ServiceRevision < 1 {
		return failure.Wrap("read service before deletion", failure.ServerResponseInvalid, errors.New("control returned an invalid service ID or revision"))
	}
	return control.DeleteService(ctx, id, controlv1.DeleteServiceParams{ExpectedServiceRevision: &current.ServiceRevision})
}

func runURLUpdate(ctx context.Context, flags publicURLUpdateCommand, output, diagnostics io.Writer) error {
	if flags.Target == "" {
		return failure.Wrap("validate URL update", failure.InvalidTunnelFlags, errors.New("set --target to update this public URL"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl url update", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := resolveManagedService(ctx, session, flags.Service)
	if err != nil {
		return err
	}
	if service.Protocol != controlv1.ServiceProtocolHTTP {
		return failure.Wrap("validate TCP URL update", failure.InvalidTunnelFlags,
			errors.New("this command changes HTTP targets only"))
	}
	target, err := targetsyntax.NormalizeTarget(flags.Target)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return err
	}
	updated, declaration, err := updateServiceDeclaration(ctx, session.Authenticated().Control, service, func(saved *controlv1.ProjectServiceConfiguration, metadata *controlv1.UpdateServiceRequest) error {
		saved.Target, saved.TargetDiscovery = parsed.Host, nil
		if parsed.Scheme == "http" {
			saved.TargetTls, metadata.TargetTls = nil, nil
		} else if saved.TargetTls == nil || saved.TargetTls.HostnameFromTarget {
			trust, err := targettrust.NewDeclaration(parsed.Hostname(), nil)
			if err != nil {
				return err
			}
			snapshot, err := trust.Snapshot()
			if err != nil {
				return err
			}
			saved.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, HostnameFromTarget: true}
			metadata.TargetTls = &controlv1.ServiceTargetTLS{Hostname: snapshot.Hostname, Digest: snapshot.Digest, System: true}
		}
		return nil
	})
	if err != nil {
		return err
	}
	access := "No public endpoint reported."
	if updated.Endpoint != nil && updated.Endpoint.Public {
		address, err := servicePublicAddress(updated.Protocol, updated.Endpoint)
		if err != nil {
			return err
		}
		access = "Public URL: " + address
	} else if updated.Endpoint != nil || declaration != nil && declaration.Public != nil && !*declaration.Public {
		access = "Access: connector-only"
	}
	return writeResult(output, clioutput.Line("Saved target for "+updated.Name+": "+target),
		clioutput.Line(access), clioutput.Text("Restart the publisher to use the new target."))
}

func (a *commandApp) newURLCommand() *cobra.Command {
	f := a.flags
	cURL := &cobra.Command{
		Use: "url", Short: "Find public URLs and manage visitor access.", GroupID: "access",
		Long: "Use list for URLs you can visit. Use inventory for public service endpoints owned by your team, including ones you manage but cannot visit.",
	}
	cURLList := &cobra.Command{Use: "list", Short: "List public URLs you may visit; --team filters the results."}
	a.leaf(cURLList, &f.URL.List, func(call commandCall) error {
		return runURLList(call.ctx, f.URL.List, a.out, a.errOut)
	})
	cURL.AddCommand(cURLList)
	cURLAvailable := &cobra.Command{Use: "available", Short: "List public URLs you may visit."}
	a.leaf(cURLAvailable, &f.URL.Available, func(call commandCall) error {
		return runURLAvailable(call.ctx, f.URL.Available, a.out, a.errOut)
	})
	cURL.AddCommand(cURLAvailable)
	cURLInventory := &cobra.Command{Use: "inventory", Short: "List public service endpoints owned by the selected team."}
	a.leaf(cURLInventory, &f.URL.Inventory, func(call commandCall) error {
		return runURLInventory(call.ctx, f.URL.Inventory, a.out, a.errOut)
	})
	cURL.AddCommand(cURLInventory)
	cURLAccess := &cobra.Command{Use: "access", Short: "Show or replace one HTTP service's visitor access policy."}
	cURLAccessShow := &cobra.Command{Use: "show", Short: "Show the saved visitor access policy."}
	a.leaf(cURLAccessShow, &f.URL.Access.Show, func(call commandCall) error {
		return runURLAccessShow(call.ctx, f.URL.Access.Show, a.out, a.errOut)
	})
	cURLAccess.AddCommand(cURLAccessShow)
	cURLAccessSet := &cobra.Command{
		Use: "set", Short: "Replace the access mode and the entire IP allowlist.",
		Long: "Set restricted to require a tnl visitor credential or anonymous to allow visitors without one. Repeat --ip for every allowed network; omitting it clears the IP filter. The publisher keeps running.",
	}
	a.leaf(cURLAccessSet, &f.URL.Access.Set, func(call commandCall) error {
		return runURLAccessSet(call.ctx, f.URL.Access.Set, a.out, a.errOut)
	})
	cURLAccess.AddCommand(cURLAccessSet)
	cURL.AddCommand(cURLAccess)
	cURLUpdate := &cobra.Command{Use: "update", Short: "Change an HTTP service target."}
	a.leaf(cURLUpdate, &f.URL.Update, func(call commandCall) error {
		return runURLUpdate(call.ctx, f.URL.Update, a.out, a.errOut)
	})
	cURL.AddCommand(cURLUpdate)
	cURLDelete := &cobra.Command{Use: "delete", Short: "Delete a service by ID or public address; use tnl url inventory to find it."}
	a.leaf(cURLDelete, &f.URL.Delete, func(call commandCall) error {
		return runURLDelete(call.ctx, f.URL.Delete, a.out, a.errOut)
	})
	bind := cURLDelete.Args
	cURLDelete.Args = func(cmd *cobra.Command, args []string) error {
		if err := bind(cmd, args); err != nil {
			return err
		}
		input, err := parseWholeService(f.URL.Delete.Service, failure.InvalidCommand)
		f.URL.Delete.selector = input
		if err == nil && input.Kind == naming.SelectorOmitted {
			return serviceInputError(failure.InvalidCommand, "Select a service to delete.")
		}
		return err
	}
	cURL.AddCommand(cURLDelete)
	return cURL
}
