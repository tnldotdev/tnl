package invocation

import (
	"context"
	"errors"
	"slices"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func nativeIntegrationConfig(ctx context.Context, database *clientstate.Database, services publisherServices, hostname string, purpose controlv1.PublicURLPurpose, allowed ...[]string) (publisher.Config, error) {
	cfg := integrationURLConfig(services, hostname, purpose)
	if len(allowed) != 0 {
		cfg.AllowedIPPrefixes = slices.Clone(allowed[0])
	}
	lock, err := clientstate.LockHostnameContext(ctx, services.state, hostname)
	if err != nil {
		return cfg, err
	}
	defer lock.Close()
	publicURL, err := services.routes.GetPublicURLByHostname(ctx, services.teamID, hostname)
	if errors.Is(err, clientcontrol.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return cfg, keyErr
		}
		protocol := controlv1.Http
		body := controlv1.CreatePublicURLRequest{TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: hostname, PublicUrlScope: services.publicURLScope, Purpose: purpose, ServiceProtocol: &protocol, Target: integrationURLTarget, AllowedIpPrefixes: &cfg.AllowedIPPrefixes}
		if services.publicURLScope == controlv1.Member {
			body.MembershipId = &services.membershipID
		}
		publicURL, err = services.routes.CreatePublicURL(ctx, body, key)
	}
	if err != nil {
		return cfg, err
	}
	if publicURL.TeamId != services.teamID || publicURL.DomainId != services.domainID || publicURL.CanonicalHostname != hostname || publicURL.Purpose != purpose || publicURL.ServiceProtocol != controlv1.Http || publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled || publicURL.PublicUrlScope != services.publicURLScope {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL differs from the selected project"))
	}
	if publicURL.PublicUrlScope == controlv1.Member && (publicURL.MembershipId == nil || *publicURL.MembershipId != services.membershipID) || publicURL.PublicUrlScope == controlv1.Shared && publicURL.MembershipId != nil {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL belongs to a different membership"))
	}
	currentPolicy := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		currentPolicy = *publicURL.AllowedIpPrefixes
	}
	if publicURL.Target != integrationURLTarget || !slices.Equal(currentPolicy, cfg.AllowedIPPrefixes) {
		publicURL, err = services.routes.UpdatePublicURL(ctx, publicURL.Id, controlv1.UpdatePublicURLRequest{Target: integrationURLTarget, AllowedIpPrefixes: cfg.AllowedIPPrefixes})
		if err != nil {
			return cfg, err
		}
	}
	native, _, err := publisheridentity.EnsureOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, publicURL)
	if err != nil {
		return cfg, err
	}
	if err := native.SelectPublicURL(publicURL); err != nil {
		return cfg, err
	}
	cfg.Control, cfg.PreserveSavedPublicURLTarget = nativePublicationControl(native, services.routes), true
	cfg.PublisherIdentityID = native.PublisherIdentityID()
	return cfg, nil
}
