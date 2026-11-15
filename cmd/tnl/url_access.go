package main

import (
	"context"
	"errors"
	"io"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type urlAccessCommand struct {
	Show urlAccessShowCommand `cmd:"" help:"Show the saved visitor access policy."`
	Set  urlAccessSetCommand  `cmd:"" help:"Replace the complete visitor access policy, including its IP list, without stopping the publisher."`
}

type urlAccessShowCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" required:"" help:"Service ID, public hostname, or HTTPS origin."`
}

type urlAccessSetCommand struct {
	urlAccessShowCommand `embed:""`
	Mode                 controlv1.VisitorAccessMode `arg:"" enum:"restricted,anonymous" required:"" help:"Require a tnl visitor credential or admit visitors anonymously."`
	IP                   []string                    `name:"ip" help:"Restrict source IPs to an address, CIDR, or 'current'. Repeat to allow several networks."`
}

func writeAccessPolicy(out io.Writer, command, id string, endpoint *controlv1.ServiceEndpoint, declaration *controlv1.ProjectServiceConfiguration) error {
	access := "server default"
	var ips []string
	if declaration != nil && declaration.Http != nil && declaration.Http.Access != nil {
		policy := declaration.Http.Access
		if policy.Mode != nil {
			access = string(*policy.Mode)
		}
		if policy.Ip != nil {
			ips = *policy.Ip
		}
	}
	fields := []clioutput.Field{{Label: "service ID", Value: id}, {Label: "access", Value: access}}
	if endpoint != nil {
		fields = append(fields, clioutput.Field{Label: "hostname", Value: endpoint.Hostname})
	}
	if len(ips) == 0 {
		fields = append(fields, clioutput.Field{Label: "IP filter", Value: "none"})
	} else {
		for _, prefix := range ips {
			fields = append(fields, clioutput.Field{Label: "IP", Value: prefix})
		}
	}
	return writeHumanFrame(out, command, "saved", "new visitor work uses this policy", clioutput.Fields(fields...))
}

func runURLAccessShow(ctx context.Context, flags urlAccessShowCommand, out, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access show", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveManagedService(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	declaration, _, err := session.Authenticated().Control.GetServiceConfiguration(ctx, item.Id)
	if err != nil {
		return err
	}
	if item.Protocol != controlv1.ServiceProtocolHTTP {
		return failure.Wrap("read HTTP access", failure.InvalidTunnelFlags, errors.New("HTTP access requires an HTTP service"))
	}
	return writeAccessPolicy(out, "tnl url access show", item.Id, item.Endpoint, declaration)
}

func runURLAccessSet(ctx context.Context, flags urlAccessSetCommand, out, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl url access set", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveManagedService(ctx, session, flags.URL)
	if err != nil {
		return err
	}
	ips, err := invocation.AccessIPPrefixes(ctx, session.Authenticated().Control, flags.IP)
	if err != nil {
		return err
	}
	updated, declaration, err := replaceServiceHTTPAccess(ctx, session.Authenticated().Control, item, flags.Mode, ips)
	if err != nil {
		return err
	}
	return writeAccessPolicy(out, "tnl url access set", updated.Id, updated.Endpoint, declaration)
}

func replaceServiceHTTPAccess(ctx context.Context, control serviceDeclarationClient, item controlv1.ServiceSummary, mode controlv1.VisitorAccessMode, ips []string) (controlv1.Service, *controlv1.ProjectServiceConfiguration, error) {
	return updateServiceDeclaration(ctx, control, item, func(saved *controlv1.ProjectServiceConfiguration, metadata *controlv1.UpdateServiceRequest) error {
		if metadata.Protocol != controlv1.ServiceProtocolHTTP {
			return failure.Wrap("change HTTP access", failure.InvalidTunnelFlags, errors.New("HTTP access requires an HTTP service"))
		}
		if saved.Http == nil {
			saved.Http = &controlv1.ProjectServiceHTTP{}
		}
		saved.Http.Access = &controlv1.ProjectHTTPAccess{Mode: &mode, Ip: &ips}
		return nil
	})
}

type serviceDeclarationClient interface {
	GetService(context.Context, string) (controlv1.Service, error)
	GetServiceConfiguration(context.Context, string) (*controlv1.ProjectServiceConfiguration, string, error)
	ConfigureService(context.Context, string, controlv1.UpdateServiceRequest) (controlv1.Service, error)
}

// read the defining declaration on each attempt. trust and intent have separate
// fences; a retry never reselects a hostname or synthesizes omitted policy.
func updateServiceDeclaration(ctx context.Context, control serviceDeclarationClient, selected controlv1.ServiceSummary, change func(*controlv1.ProjectServiceConfiguration, *controlv1.UpdateServiceRequest) error) (controlv1.Service, *controlv1.ProjectServiceConfiguration, error) {
	for attempt := 0; attempt < 3; attempt++ {
		current, err := control.GetService(ctx, selected.Id)
		if err != nil {
			return controlv1.Service{}, nil, err
		}
		if current.Id != selected.Id || current.TeamId != selected.TeamId {
			return controlv1.Service{}, nil, serviceShareResponse()
		}
		declaration, digest, err := control.GetServiceConfiguration(ctx, selected.Id)
		if err != nil {
			return controlv1.Service{}, nil, err
		}
		if declaration == nil {
			return controlv1.Service{}, nil, failure.Wrap("change service configuration", failure.InvalidTunnelFlags, errors.New("service has no saved declaration; configure it with its owning project or publisher"))
		}
		body := controlv1.UpdateServiceRequest{Configuration: declaration, ExpectedConfigurationDigest: &digest,
			ExpectedPublisherPool: new(current.PublisherPool),
			ExpectedTrustRevision: current.TrustRevision, Protocol: current.Protocol, PublisherPool: current.PublisherPool, TargetTls: current.TargetTls}
		if err := change(declaration, &body); err != nil {
			return controlv1.Service{}, nil, err
		}
		updated, err := control.ConfigureService(ctx, selected.Id, body)
		if errors.Is(err, clientcontrol.ErrStatusConflict) && !errors.Is(err, clientcontrol.ErrProjectManaged) && attempt < 2 {
			continue
		}
		if err != nil {
			return controlv1.Service{}, nil, err
		}
		if updated.Id != selected.Id || updated.TeamId != selected.TeamId {
			return controlv1.Service{}, nil, serviceShareResponse()
		}
		return updated, declaration, nil
	}
	return controlv1.Service{}, nil, clientcontrol.ErrStatusConflict
}
