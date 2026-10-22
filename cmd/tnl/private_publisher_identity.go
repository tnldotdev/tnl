package main

import (
	"context"
	"io"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func managedService(ctx context.Context, session *clientteam.Session, id string) (controlv1.Service, error) {
	current, err := session.Current(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	services, err := session.Authenticated().Control.ListServices(ctx, current.Team().Id)
	if err != nil {
		return controlv1.Service{}, err
	}
	service, err := connector.SelectService(services, id, current.Team().Id)
	if err != nil {
		return service, err
	}
	if !service.Enabled {
		return service, publisheridentity.ErrScope
	}
	service, err = session.Authenticated().Control.GetService(ctx, service.Id)
	if err != nil {
		return service, err
	}
	if service.Id != id || service.TeamId != current.Team().Id || !service.Enabled {
		return service, publisheridentity.ErrScope
	}
	_, err = publisheridentity.ServiceTrust(service)
	return service, err
}

func runPrivatePublisherSetup(ctx context.Context, flags publisherSetupCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.ServiceID, opaqueid.ServicePrefix) {
		return publisherCLIError("pass an exact service ID")
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher setup", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := managedService(ctx, session, flags.ServiceID)
	if err != nil {
		return err
	}
	native, identity, err := publisheridentity.EnsureServiceOwner(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, service)
	if err != nil {
		return err
	}
	if _, err := native.SavedService(ctx); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher setup", "ready", "", clioutput.Fields(
		clioutput.Field{Label: "service ID", Value: service.Id}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId}))
}

func runPrivatePublisherProvision(ctx context.Context, flags publisherProvisionCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.ServiceID, opaqueid.ServicePrefix) {
		return publisherCLIError("pass an exact service ID")
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher provision", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := managedService(ctx, session, flags.ServiceID)
	if err != nil {
		return err
	}
	enrollment, err := session.Authenticated().Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Name: "deployment", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return err
	}
	if enrollment.Kind != "service" || enrollment.ServiceId == nil || *enrollment.ServiceId != service.Id || enrollment.TeamId != service.TeamId {
		return publisheridentity.ErrScope
	}
	native, identity, err := publisheridentity.EnrollNative(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, enrollment.EnrollmentKey)
	if err != nil {
		return err
	}
	if identity.Kind != "service" || identity.ServiceId == nil || *identity.ServiceId != service.Id || identity.TeamId != service.TeamId {
		return publisheridentity.ErrScope
	}
	if _, err := native.SavedService(ctx); err != nil {
		return err
	}
	_, signing, err := invocation.SigningIdentity(ctx, session.Store(), identity.ClientId)
	if err != nil {
		return err
	}
	file, err := credentialfile.New(session.Authenticated().ServerEndpoint, identity, signing)
	if err != nil {
		return err
	}
	if err := credentialfile.Write(flags.OutputFile, file); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "mount the file and set TNL_PUBLISHER_CREDENTIAL_FILE", clioutput.Fields(
		clioutput.Field{Label: "file", Value: flags.OutputFile}, clioutput.Field{Label: "service ID", Value: service.Id}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId}))
}
