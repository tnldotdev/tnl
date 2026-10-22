package invocation

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherServices struct {
	authenticated         *clientauth.Client
	state                 *clientstate.Store
	hostname              string
	namespace             string
	teamID                string
	membershipID          string
	domainID              string
	publicURLScope        controlv1.PublicURLScope
	domainKind            authorityv1.DomainKind
	customDomainAvailable bool
	policyRevision        uint64
	ephemeral             bool
	routes                *controlclient.Client
}

type clientIPLookup interface {
	ClientIP(context.Context) (controlv1.ClientIPResponse, error)
}

type resolvedVisitorAccess struct {
	prefixes []string
	access   controlv1.VisitorAccessMode
	explicit bool
}

func resolveVisitorAccess(ctx context.Context, control clientIPLookup, configured *config.Access, anonymous bool, ips []string) (resolvedVisitorAccess, error) {
	result := resolvedVisitorAccess{access: controlv1.Restricted}
	if configured != nil {
		if err := configured.Validate(); err != nil {
			return result, err
		}
		result.access = controlv1.VisitorAccessMode(configured.VisitorMode())
		result.prefixes = slices.Clone(configured.IP)
		result.explicit = true
	}
	if anonymous || len(ips) != 0 {
		result.access = controlv1.Restricted
		if anonymous {
			result.access = controlv1.Anonymous
		}
		result.prefixes = ips
		result.explicit = true
	}
	if result.explicit {
		var err error
		result.prefixes, err = AccessIPPrefixes(ctx, control, result.prefixes)
		if err != nil {
			return resolvedVisitorAccess{}, err
		}
	}
	return result, nil
}

func preparePublisherServices(
	ctx context.Context,
	state *clientstate.Database,
	serverURL, publicURL, name, selectedDomain, selectedTeam string,
	ephemeral bool,
	authenticated *clientauth.Client,
) (publisherServices, error) {
	publisherState, err := state.Server(ctx, serverURL)
	if err != nil {
		return publisherServices{}, err
	}
	discovery := authenticated.Discovery
	if discovery.ManagedDomain == "" {
		return publisherServices{}, failure.Wrap("read server discovery", failure.ServerResponseInvalid, errors.New("control discovery omitted the managed domain"))
	}
	identity, err := authenticated.Authority.IdentityContext(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	session := team.NewSession(nil, publisherState, authenticated, identity, team.Options{ProjectTeam: selectedTeam})
	selected, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	current := FromTeamContext(selected)
	if current.team.PolicyRevision < 0 {
		return publisherServices{}, failure.Wrap("read team policy", failure.ServerResponseInvalid, errors.New("authority returned an invalid team policy revision"))
	}
	hostname, domain, publicURLScope, err := resolve.PublishHostname(publicURL, name, selectedDomain, selected)
	if err != nil {
		return publisherServices{}, err
	}
	customAvailable := slices.ContainsFunc(current.domains, func(domain authorityv1.Domain) bool {
		return domain.Kind == authorityv1.Custom && domain.State == authorityv1.DomainStateReady
	})
	return publisherServices{
		domainKind: domain.Kind, customDomainAvailable: customAvailable,
		authenticated:  authenticated,
		state:          publisherState,
		hostname:       hostname,
		namespace:      namespaceForMembership(current, domain),
		teamID:         current.team.Id,
		membershipID:   current.membership.Id,
		domainID:       domain.Id,
		publicURLScope: publicURLScope,
		policyRevision: uint64(current.team.PolicyRevision),
		ephemeral:      ephemeral,
		routes:         authenticated.Control,
	}, nil
}

func namespaceForMembership(current TeamSelection, domain authorityv1.Domain) string {
	namespace, _ := current.Context().Namespace(domain)
	return namespace
}

func (p publisherServices) config(target string, allowedIPPrefixes []string, limits publisher.ApplicationLimits) publisher.Config {
	relayTransportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	return publisher.Config{
		Control:           p.routes,
		TeamID:            p.teamID,
		MembershipID:      p.membershipID,
		DomainID:          p.domainID,
		Hostname:          p.hostname,
		PublicURLScope:    p.publicURLScope,
		Purpose:           controlv1.App,
		ServiceProtocol:   controlv1.Http,
		PolicyRevision:    p.policyRevision,
		Target:            target,
		Limits:            limits,
		AllowedIPPrefixes: allowedIPPrefixes,
		Ephemeral:         p.ephemeral,
		State:             p.state,
		QUICConnector:     muxsession.QUICConnector{TLSConfig: relayTransportTLS},
		TCPConnector:      muxsession.TLSYamuxConnector{TLSConfig: relayTransportTLS},
	}
}
