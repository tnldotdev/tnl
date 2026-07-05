package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherServices struct {
	authenticated   *clientauth.Client
	state           *clientstate.Store
	hostname        string
	memberNamespace string
	teamID          string
	membershipID    string
	domainID        string
	routeScope      controlv1.RouteScope
	policyRevision  uint64
	ephemeral       bool
	routes          *routeclient.Client
}

type clientIPLookup interface {
	ClientIP(context.Context) (controlv1.ClientIPResponse, error)
}

func authenticatePublisher(
	ctx context.Context,
	state *clientstate.Database,
	serverURL, accessToken string,
	command string,
	stdin io.Reader,
	diagnostics io.Writer,
) (*clientauth.Client, error) {
	return clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint:       serverURL,
		State:                state,
		AccessToken:          accessToken,
		Diagnostics:          diagnostics,
		OpenURL:              interactiveBrowserOpener(stdin),
		LoginToken:           loginTokenPrompt(stdin, diagnostics),
		AuthenticationPrompt: authenticationPrompt(diagnostics, command),
	})
}

func resolveIPPolicy(
	ctx context.Context,
	control clientIPLookup,
	allowedIPPrefixes []string,
	public bool,
) ([]string, string, error) {
	if public {
		return []string{}, "", nil
	}
	if len(allowedIPPrefixes) > authorization.MaxIPPrefixes-1 {
		return nil, "", errors.New("at most 63 explicit IP prefixes may be allowed")
	}
	canonical, err := authorization.CanonicalizeIPPrefixes(allowedIPPrefixes)
	if err != nil {
		return nil, "", fmt.Errorf("invalid allowed IP prefix: %w", err)
	}
	current, err := control.ClientIP(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("read current IP: %w", err)
	}
	address, err := netip.ParseAddr(current.Ip)
	if err != nil || address.Zone() != "" {
		return nil, "", errors.New("control returned an invalid current IP")
	}
	address = address.Unmap()
	currentIP := address.String()
	currentPrefix := netip.PrefixFrom(address, address.BitLen()).String()
	if !slices.Contains(canonical, currentPrefix) {
		canonical = append(canonical, currentPrefix)
		slices.Sort(canonical)
	}
	return canonical, currentIP, nil
}

func preparePublisherServices(
	ctx context.Context,
	state *clientstate.Database,
	serverURL, hostname, subdomain, selectedTeam string,
	ephemeral bool,
	authenticated *clientauth.Client,
) (publisherServices, error) {
	publisherState, err := state.Server(ctx, serverURL)
	if err != nil {
		return publisherServices{}, err
	}
	discovery := authenticated.Discovery
	if discovery.ManagedDeploymentDomain == "" {
		return publisherServices{}, errors.New("control discovery omitted the managed deployment domain")
	}
	api := teamAPI(authenticated.Authority)
	identity, err := api.IdentityContext(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	teamSession := teamSession{
		store: publisherState, authenticated: authenticated, api: api, identity: identity,
		projectTeam: selectedTeam,
	}
	current, err := teamSession.current(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	if current.team.PolicyRevision < 0 {
		return publisherServices{}, errors.New("authority returned an invalid team policy revision")
	}
	hostname, domain, routeScope, err := resolvePublishHostname(hostname, subdomain, current)
	if err != nil {
		return publisherServices{}, err
	}
	routes, err := routeAPI(authenticated)
	if err != nil {
		return publisherServices{}, err
	}
	return publisherServices{
		authenticated:   authenticated,
		state:           publisherState,
		hostname:        hostname,
		memberNamespace: memberNamespace(current.membership, domain),
		teamID:          current.team.Id,
		membershipID:    current.membership.Id,
		domainID:        domain.Id,
		routeScope:      routeScope,
		policyRevision:  uint64(current.team.PolicyRevision),
		ephemeral:       ephemeral,
		routes:          routes,
	}, nil
}

func resolvePublishHostname(
	hostname, subdomain string,
	current teamContext,
) (string, authorityv1.Domain, controlv1.RouteScope, error) {
	if hostname != "" && subdomain != "" {
		return "", authorityv1.Domain{}, "", errors.New("--host and --subdomain are mutually exclusive")
	}
	domain, err := defaultReadyDomain(current)
	if err != nil {
		return "", authorityv1.Domain{}, "", err
	}
	namespace := memberNamespace(current.membership, domain)
	if subdomain != "" {
		canonical, err := naming.CanonicalizeHostname(subdomain)
		if err != nil || canonical != subdomain || strings.Contains(subdomain, ".") {
			return "", authorityv1.Domain{}, "", errors.New("subdomain must be one canonical DNS label")
		}
		hostname = subdomain + "." + namespace
	}
	if hostname == "" {
		label, err := naming.GeneratedHostnameLabel()
		if err != nil {
			return "", authorityv1.Domain{}, "", err
		}
		hostname = label + "." + namespace
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return "", authorityv1.Domain{}, "", errors.New("hostname must be canonical")
	}
	if hostname != namespace && !strings.HasSuffix(hostname, "."+namespace) {
		domain, err = readyDomainForHostname(current.domains, hostname)
		if err != nil {
			return "", authorityv1.Domain{}, "", err
		}
		namespace = memberNamespace(current.membership, domain)
	}
	routeScope := controlv1.Shared
	if hostname == namespace || strings.HasSuffix(hostname, "."+namespace) && strings.Count(strings.TrimSuffix(hostname, "."+namespace), ".") == 0 {
		routeScope = controlv1.Member
	} else if current.membership.Role == authorityv1.TeamRoleMember {
		return "", authorityv1.Domain{}, "", errors.New("shared routes require a team administrator or owner")
	}
	return hostname, domain, routeScope, nil
}

func defaultReadyDomain(current teamContext) (authorityv1.Domain, error) {
	for _, domain := range current.domains {
		if domain.Id == current.team.DefaultDomainId {
			if domain.State != authorityv1.DomainStateReady {
				return authorityv1.Domain{}, fmt.Errorf("default domain %s is not ready", domain.CanonicalDomain)
			}
			return domain, nil
		}
	}
	return authorityv1.Domain{}, errors.New("selected team has no available default domain")
}

func readyDomainForHostname(domains []authorityv1.Domain, hostname string) (authorityv1.Domain, error) {
	var selected authorityv1.Domain
	for _, domain := range domains {
		if domain.State != authorityv1.DomainStateReady || hostname != domain.CanonicalDomain && !strings.HasSuffix(hostname, "."+domain.CanonicalDomain) {
			continue
		}
		if len(domain.CanonicalDomain) > len(selected.CanonicalDomain) {
			selected = domain
		}
	}
	if selected.Id == "" {
		return authorityv1.Domain{}, fmt.Errorf("hostname %s is outside the selected team's ready domains", hostname)
	}
	return selected, nil
}

func memberNamespace(membership authorityv1.Membership, domain authorityv1.Domain) string {
	label := membership.MemberSlug
	if domain.Kind == authorityv1.Managed {
		label = membership.ManagedLabel
	}
	return label + "." + domain.CanonicalDomain
}

func (p publisherServices) config(target string, allowedIPPrefixes []string) publisher.Config {
	relayTransportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	return publisher.Config{
		Control:           p.routes,
		TeamID:            p.teamID,
		MembershipID:      p.membershipID,
		DomainID:          p.domainID,
		Hostname:          p.hostname,
		RouteScope:        p.routeScope,
		PolicyRevision:    p.policyRevision,
		Target:            target,
		AllowedIPPrefixes: allowedIPPrefixes,
		Ephemeral:         p.ephemeral,
		State:             p.state,
		QUICConnector:     muxsession.QUICConnector{TLSConfig: relayTransportTLS},
		TCPConnector:      muxsession.TLSYamuxConnector{TLSConfig: relayTransportTLS},
	}
}
