package main

import (
	"context"
	"errors"
	"io"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// endpoint capacity belongs to control, not the installed publication supervisor.
type endpointCommand struct {
	Release endpointReleaseCommand `cmd:"" help:"Retire a disabled service's public port reservation without deleting the service."`
}

type endpointReleaseCommand struct {
	scopedTeamFlags `embed:""`
	ServiceID       string `arg:"" name:"service-id" help:"Exact saved service ID."`
	Port            int    `name:"port" required:"" help:"Exact positive public port reservation to retire."`
}

func runEndpointRelease(ctx context.Context, flags endpointReleaseCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.ServiceID, opaqueid.ServicePrefix) || flags.Port < 1024 || flags.Port > 65535 {
		return failure.Wrap("select service endpoint", failure.InvalidTunnelFlags, errors.New("use an exact service ID and --port from 1024 to 65535"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl endpoint release", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	service, err := session.Authenticated().Control.GetService(ctx, flags.ServiceID)
	if err != nil {
		return err
	}
	if service.Id != flags.ServiceID || service.TeamId != current.Team().Id || service.Endpoint == nil ||
		service.Endpoint.Port != flags.Port || service.EndpointRevision < 1 {
		return failure.Wrap("select service endpoint", failure.InvalidTunnelFlags, errors.New("service does not have this port reservation in the selected team"))
	}
	if service.Endpoint.Public {
		return failure.Wrap("release service endpoint", failure.InvalidTunnelFlags, errors.New("disable public access in the binding and apply before releasing its reservation"))
	}
	released, err := session.Authenticated().Control.ReleaseServiceEndpoint(ctx, service.Id, controlv1.ReleaseServiceEndpointRequest{
		ExpectedEndpointRevision: service.EndpointRevision, ExpectedPort: flags.Port,
	})
	if err != nil {
		return err
	}
	if released.Id != service.Id || released.TeamId != service.TeamId || released.Endpoint == nil || released.Endpoint.Public ||
		released.Endpoint.Port != 0 || released.Endpoint.Hostname != service.Endpoint.Hostname || released.EndpointRevision != service.EndpointRevision+1 || released.TrustRevision != service.TrustRevision {
		return failure.Wrap("release service endpoint", failure.ServerResponseInvalid, errors.New("control returned an unexpected service binding"))
	}
	return writeHumanFrame(output, "tnl endpoint release", "retired", "connector access is unchanged", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: released.Id},
		clioutput.Field{Label: "TLS hostname", Value: released.Endpoint.Hostname},
		clioutput.Field{Label: "former public port", Value: strconv.Itoa(flags.Port)},
		clioutput.Field{Label: "capacity", Value: "quarantined until old authority expires and cleanup finishes"},
		clioutput.Field{Label: "local connector port", Value: "saved assignment unchanged"},
	))
}
