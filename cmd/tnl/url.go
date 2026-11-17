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

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicURLCommand struct {
	List      publicURLListCommand      `cmd:"" help:"List public URLs you may visit; --team filters the results."`
	Available urlAvailableCommand       `cmd:"" help:"List public URLs you may visit."`
	Inventory publicURLInventoryCommand `cmd:"" help:"List public service endpoints owned by the selected team."`
	Access    urlAccessCommand          `cmd:"" help:"Show or replace one HTTP service's visitor access policy."`
	Update    publicURLUpdateCommand    `cmd:"" help:"Change an HTTP service target."`
	Delete    publicURLDeleteCommand    `cmd:"" help:"Delete a service by ID or public address; use tnl url inventory to find it."`
}

type publicURLUpdateCommand struct {
	scopedTeamFlags `embed:""`
	Service         string `arg:"" name:"service-or-address" required:"" help:"Service ID, public hostname, or HTTPS origin."`
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
	Service         string `arg:"" name:"service-or-address" required:"" help:"Service ID, public hostname, or HTTPS origin to delete."`
	Unconditional   bool   `name:"unconditional" help:"Delete despite concurrent saved-service changes; current management permission is still required."`
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
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		address, err := servicePublicAddress(item.Protocol, item.Endpoint)
		if err != nil {
			return err
		}
		blocks = append(blocks, clioutput.Section(item.Endpoint.Hostname, clioutput.Fields(
			clioutput.Field{Label: "public URL", Value: address},
			clioutput.Field{Label: "service ID", Value: item.Id},
			clioutput.Field{Label: "team ID", Value: item.TeamId},
			clioutput.Field{Label: "team", Value: item.TeamName},
			clioutput.Field{Label: "protocol", Value: string(item.Protocol)},
			clioutput.Field{Label: "access", Value: string(item.VisitorAccess)},
		)))
	}
	return writeHumanFrame(output, "tnl url list", countState(len(items), "public URL", "public URLs"), "", blocks...)
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
	item, err := selectShareService(selector, items)
	if err != nil {
		return item, err
	}
	if item.TeamId != current.Team().Id {
		return controlv1.ServiceSummary{}, clientcontrol.ErrNotFound
	}
	return item, nil
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
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "server", Value: session.Authenticated().ServerEndpoint},
		clioutput.Field{Label: "team", Value: current.Team().DisplayName},
	)}
	count := 0
	for _, service := range services {
		if service.Endpoint == nil || !service.Endpoint.Public {
			continue
		}
		count++
		state := "disabled"
		if service.Enabled {
			state = "enabled"
		}
		address, err := servicePublicAddress(service.Protocol, service.Endpoint)
		if err != nil {
			return err
		}
		fields := []clioutput.Field{
			{Label: "state", Value: state},
			{Label: "service ID", Value: service.Id},
			{Label: "protocol", Value: string(service.Protocol)},
			{Label: "public URL", Value: address},
		}
		if service.RunNumber != nil {
			fields = append(fields, clioutput.Field{Label: "service run number", Value: strconv.FormatInt(*service.RunNumber, 10)})
		}
		blocks = append(blocks, clioutput.Section(service.Endpoint.Hostname, clioutput.Fields(fields...)))
	}
	return writeHumanFrame(output, "tnl url inventory", countState(count, "public URL", "public URLs"), "", blocks...)
}

func runURLDelete(ctx context.Context, command publicURLDeleteCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.selection(), "tnl url delete", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, err := resolveManagedService(ctx, session, command.Service)
	if err != nil {
		return err
	}
	if err := deleteManagedService(ctx, session.Authenticated().Control, selected.Id, command.Unconditional); err != nil {
		return err
	}
	return writeHumanTransition(output, "tnl url delete", "deleted", selected.Name, "", "service deleted", "",
		clioutput.Field{Label: "id", Value: selected.Id})
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
	updated, _, err := updateServiceDeclaration(ctx, session.Authenticated().Control, service, func(saved *controlv1.ProjectServiceConfiguration, metadata *controlv1.UpdateServiceRequest) error {
		saved.Target, saved.TargetDiscovery = parsed.Host, nil
		if parsed.Scheme == "http" {
			saved.TargetTls, metadata.TargetTls = nil, nil
		} else if saved.TargetTls == nil {
			trust, err := targettrust.NewDeclaration(parsed.Hostname(), nil)
			if err != nil {
				return err
			}
			saved.TargetTls = &controlv1.ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest}
			metadata.TargetTls = &controlv1.ServiceTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest, System: true}
		}
		return nil
	})
	if err != nil {
		return err
	}
	address, err := servicePublicAddress(updated.Protocol, updated.Endpoint)
	if err != nil {
		return err
	}
	fields := []clioutput.Field{{Label: "public URL", Value: address}, {Label: "target", Value: target}}
	return writeHumanFrame(output, "tnl url update", "updated", "restart the publisher to use the new target",
		clioutput.Fields(fields...))
}
