package invocation

import (
	"context"
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func opaqueNamingAvailable(discovery controlv1.ControlDiscovery) bool {
	return discovery.DnsAutomation && discovery.ManagedUrlMode == controlv1.Generated
}

func previewPublisher(ctx context.Context, state *clientstate.Store, client *auth.Client, selected team.Context) (*publisheridentity.Native, authorityv1.PublisherEnrollmentResult, error) {
	if !opaqueNamingAvailable(client.Discovery) || selected.Mode() != naming.ManagedURLModeGenerated {
		return nil, authorityv1.PublisherEnrollmentResult{}, failure.Wrap("select opaque naming", failure.InvalidTunnelFlags, errors.New("opaque naming requires hosted DNS automation"))
	}
	domain, err := selected.ManagedDomain()
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	return publisheridentity.EnsurePreviewPublisher(ctx, state, client.Control, client.Authority, selected.Team().Id, selected.Membership().Id, domain.Id, domain.CanonicalDomain)
}

func prepareOpaqueService(ctx context.Context, services publisherServices, flags PublicOptions, policy resolvedVisitorAccess, plan targetplan.TargetPlan) (*publisheridentity.Native, controlv1.Service, targetplan.TargetPlan, error) {
	client := services.authenticated
	if services.previewResume {
		saved, err := client.Control.GetServiceByHostname(ctx, services.teamID, services.hostname)
		if err != nil {
			return nil, controlv1.Service{}, plan, err
		}
		if saved.Ephemeral || saved.Source != nil || saved.TeamId != services.teamID || !saved.Enabled ||
			saved.Endpoint == nil || saved.Endpoint.Hostname != services.hostname {
			return nil, saved, plan, publisheridentity.ErrScope
		}
		if policy.explicit || flags.Limits.Requests != 0 || flags.Limits.Concurrency != 0 || flags.Limits.RateRequests != 0 ||
			flags.Limits.RateBurst != 0 || flags.RequirePostQuantum != nil {
			return nil, saved, plan, failure.Wrap("resume preview", failure.InvalidTunnelFlags, errors.New("resuming a saved preview keeps its visitor policy; change it with tnl url"))
		}
		if !foregroundTrustSelected(flags) {
			plan.Trust, err = publisheridentity.ServiceTrust(saved)
			if err != nil {
				return nil, saved, plan, err
			}
			if plan.Trust != nil && !strings.Contains(flags.Target, "://") {
				plan.Target = "https://" + strings.TrimPrefix(plan.Target, "http://")
			}
		}
		return selectSavedPreview(ctx, services.state, client, services.context, saved, plan)
	}
	native, identity, err := previewPublisher(ctx, services.state, client, services.context)
	if err != nil {
		return nil, controlv1.Service{}, plan, err
	}
	declaration, err := foregroundServiceDeclaration(flags, policy, plan, nil)
	if err != nil {
		return nil, controlv1.Service{}, plan, err
	}
	declaration.Ephemeral = new(flags.Ephemeral)
	random, err := naming.RandomHostnameLabel()
	if err != nil {
		return nil, controlv1.Service{}, plan, err
	}
	name := "s-" + random
	var saved controlv1.Service
	for range 3 {
		saved, err = client.Control.CreateServiceAt(ctx, services.teamID, name, random,
			&controlv1.ServicePlacement{DomainId: &services.domainID, PreviewPublisherId: &identity.ClientId},
			controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, TargetTls: publisheridentity.ServiceTargetTLS(plan.Trust)}, &declaration)
		if err == nil || !retryServiceReservation(ctx, err) {
			break
		}
	}
	if err != nil {
		return nil, saved, plan, err
	}
	if saved.Endpoint == nil || saved.TeamId != services.teamID || identity.Namespace == nil {
		return nil, saved, plan, publisheridentity.ErrScope
	}
	parent, ok := naming.PreviewHostname(saved.Endpoint.Hostname, client.Discovery.ManagedDomain)
	if !ok || parent != *identity.Namespace {
		return nil, saved, plan, publisheridentity.ErrScope
	}
	native, approved, err := native.ForService(ctx, saved.Id)
	if err != nil {
		return nil, saved, plan, err
	}
	return native, approved, plan, err
}

func selectSavedPreview(ctx context.Context, state *clientstate.Store, client *auth.Client, selected team.Context, saved controlv1.Service, plan targetplan.TargetPlan) (*publisheridentity.Native, controlv1.Service, targetplan.TargetPlan, error) {
	if saved.Endpoint == nil {
		return nil, saved, plan, publisheridentity.ErrScope
	}
	parent, ok := naming.PreviewHostname(saved.Endpoint.Hostname, client.Discovery.ManagedDomain)
	if !ok {
		return nil, saved, plan, publisheridentity.ErrScope
	}
	domain, err := selected.ManagedDomain()
	if err != nil {
		return nil, saved, plan, err
	}
	if native, found, err := publisheridentity.LoadPreviewPublisher(ctx, state, client.Control, client.Authority,
		selected.Team().Id, selected.Membership().Id, domain.Id, domain.CanonicalDomain, parent); err != nil {
		return nil, saved, plan, err
	} else if found {
		worker, approved, err := native.ForService(ctx, saved.Id)
		return worker, approved, plan, err
	}
	native, _, err := publisheridentity.EnsureServiceOwner(ctx, state, client.Control, client.Authority, saved)
	return native, saved, plan, err
}
