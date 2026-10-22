package main

import (
	"context"
	"io"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func managedPrivateService(ctx context.Context, session *clientteam.Session, id string) (controlv1.PrivateService, error) {
	current, err := session.Current(ctx)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	services, err := session.Authenticated().Control.ListPrivateServices(ctx, current.Team().Id)
	if err != nil {
		return controlv1.PrivateService{}, err
	}
	service, err := connector.SelectService(services, id, current.Team().Id)
	if err != nil {
		return service, err
	}
	if !service.Enabled {
		return service, nativeauth.ErrScope
	}
	service, err = session.Authenticated().Control.GetPrivateService(ctx, service.Id)
	if err != nil {
		return service, err
	}
	if service.Id != id || service.TeamId != current.Team().Id || !service.Enabled {
		return service, nativeauth.ErrScope
	}
	_, err = nativeauth.PrivateServiceTrust(service)
	return service, err
}

func runPrivatePublisherSetup(ctx context.Context, flags publisherSetupCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PrivateServiceID, opaqueid.PrivateServicePrefix) {
		return publisherCLIError("pass an exact private service ID")
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher setup", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := managedPrivateService(ctx, session, flags.PrivateServiceID)
	if err != nil {
		return err
	}
	native, identity, err := nativeauth.EnsurePrivateServiceOwner(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, service)
	if err != nil {
		return err
	}
	if _, err := native.SavedPrivateService(ctx); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher setup", "ready", "", clioutput.Fields(
		clioutput.Field{Label: "private service ID", Value: service.Id}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId}))
}

func runPrivatePublisherProvision(ctx context.Context, flags publisherProvisionCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.PrivateServiceID, opaqueid.PrivateServicePrefix) {
		return publisherCLIError("pass an exact private service ID")
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher provision", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	service, err := managedPrivateService(ctx, session, flags.PrivateServiceID)
	if err != nil {
		return err
	}
	enrollment, err := session.Authenticated().Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, PrivateServiceId: &service.Id, Name: "deployment", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return err
	}
	if enrollment.Kind != "private_service" || enrollment.PrivateServiceId == nil || *enrollment.PrivateServiceId != service.Id || enrollment.TeamId != service.TeamId {
		return nativeauth.ErrScope
	}
	native, identity, err := nativeauth.EnrollNative(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, enrollment.EnrollmentKey)
	if err != nil {
		return err
	}
	if identity.Kind != "private_service" || identity.PrivateServiceId == nil || *identity.PrivateServiceId != service.Id || identity.TeamId != service.TeamId {
		return nativeauth.ErrScope
	}
	if _, err := native.SavedPrivateService(ctx); err != nil {
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
	return writeHumanFrame(output, "tnl publisher provision", "created", "mount the file and set TNL_PUBLISHER_FILE", clioutput.Fields(
		clioutput.Field{Label: "file", Value: flags.OutputFile}, clioutput.Field{Label: "private service ID", Value: service.Id}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId}))
}
