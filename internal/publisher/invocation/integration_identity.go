package invocation

import (
	"context"
	"errors"
	"slices"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	route, err := services.routes.GetPublicURLByHostname(ctx, services.teamID, hostname)
	if errors.Is(err, controlclient.ErrNotFound) {
		key, keyErr := opaqueid.New(opaqueid.IdempotencyPrefix)
		if keyErr != nil {
			return cfg, keyErr
		}
		protocol := controlv1.Http
		body := controlv1.CreatePublicURLRequest{TeamId: services.teamID, DomainId: services.domainID, CanonicalHostname: hostname, PublicUrlScope: services.publicURLScope, Purpose: purpose, ServiceProtocol: &protocol, Target: integrationURLTarget, AllowedIpPrefixes: &cfg.AllowedIPPrefixes}
		if services.publicURLScope == controlv1.Member {
			body.MembershipId = &services.membershipID
		}
		route, err = services.routes.CreatePublicURL(ctx, body, key)
	}
	if err != nil {
		return cfg, err
	}
	if route.TeamId != services.teamID || route.DomainId != services.domainID || route.CanonicalHostname != hostname || route.Purpose != purpose || route.ServiceProtocol != controlv1.Http || route.Ephemeral || route.LifecycleState != controlv1.Enabled || route.PublicUrlScope != services.publicURLScope {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL differs from the selected project"))
	}
	if route.PublicUrlScope == controlv1.Member && (route.MembershipId == nil || *route.MembershipId != services.membershipID) || route.PublicUrlScope == controlv1.Shared && route.MembershipId != nil {
		return cfg, failure.Wrap("read integration URL", failure.ServerResponseInvalid, errors.New("integration URL belongs to a different membership"))
	}
	currentPolicy := []string{}
	if route.AllowedIpPrefixes != nil {
		currentPolicy = *route.AllowedIpPrefixes
	}
	if route.Target != integrationURLTarget || !slices.Equal(currentPolicy, cfg.AllowedIPPrefixes) {
		route, err = services.routes.UpdatePublicURL(ctx, route.Id, controlv1.UpdatePublicURLRequest{Target: integrationURLTarget, AllowedIpPrefixes: cfg.AllowedIPPrefixes})
		if err != nil {
			return cfg, err
		}
	}
	native, _, err := nativeauth.EnsureOwner(ctx, services.state, services.authenticated.Control, services.authenticated.Authority, route)
	if err != nil {
		return cfg, err
	}
	if err := native.SelectRoute(route); err != nil {
		return cfg, err
	}
	cfg.Control, cfg.PreserveSavedURLTarget = nativePublicationControl(native, services.routes), true
	cfg.PublisherID = native.PublisherID()
	return cfg, nil
}
