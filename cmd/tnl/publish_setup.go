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
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
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

type resolvedIPPolicy struct {
	prefixes []string
	current  string
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
) (resolvedIPPolicy, error) {
	if public {
		return resolvedIPPolicy{prefixes: []string{}}, nil
	}
	canonical, err := authorization.CanonicalizeIPPrefixes(allowedIPPrefixes)
	if err != nil {
		return resolvedIPPolicy{}, failure.Wrap("validate allowed IP prefixes", failure.InvalidTunnelFlags, err)
	}
	seen := make(map[string]bool, len(canonical))
	for _, prefix := range canonical {
		seen[prefix] = true
	}
	current, err := control.ClientIP(ctx)
	if err != nil {
		return resolvedIPPolicy{}, fmt.Errorf("read current IP: %w", err)
	}
	address, err := netip.ParseAddr(current.Ip)
	if err != nil || address.Zone() != "" {
		return resolvedIPPolicy{}, failure.Wrap("read current IP", failure.ServerResponseInvalid, errors.Join(err, errors.New("control returned an invalid current IP")))
	}
	address = address.Unmap()
	currentIP := address.String()
	currentPrefix := netip.PrefixFrom(address, address.BitLen()).String()
	if !seen[currentPrefix] {
		canonical = append(canonical, currentPrefix)
	}
	slices.Sort(canonical)
	return resolvedIPPolicy{prefixes: canonical, current: currentIP}, nil
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
	api := teamAPI(authenticated.Authority)
	identity, err := api.IdentityContext(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	teamSession := teamSession{
		store: publisherState, authenticated: authenticated, api: api, identity: identity,
		projectTeam: selectedTeam,
	}
	current, err := teamSession.currentWithDomains(ctx)
	if err != nil {
		return publisherServices{}, err
	}
	if current.team.PolicyRevision < 0 {
		return publisherServices{}, failure.Wrap("read team policy", failure.ServerResponseInvalid, errors.New("authority returned an invalid team policy revision"))
	}
	hostname, domain, publicURLScope, err := resolvePublishHostname(publicURL, name, selectedDomain, current)
	if err != nil {
		return publisherServices{}, err
	}
	customAvailable := slices.ContainsFunc(current.domains, func(domain authorityv1.Domain) bool {
		return domain.Kind == authorityv1.Claimed && domain.State == authorityv1.DomainStateReady
	})
	return publisherServices{
		domainKind: domain.Kind, customDomainAvailable: customAvailable,
		authenticated:  authenticated,
		state:          publisherState,
		hostname:       hostname,
		namespace:      namespaceForMembership(current.membership, domain),
		teamID:         current.team.Id,
		membershipID:   current.membership.Id,
		domainID:       domain.Id,
		publicURLScope: publicURLScope,
		policyRevision: uint64(current.team.PolicyRevision),
		ephemeral:      ephemeral,
		routes:         authenticated.Control,
	}, nil
}

func resolvePublishHostname(
	publicURL, name, selectedDomain string,
	current teamContext,
) (string, authorityv1.Domain, controlv1.PublicURLScope, error) {
	if publicURL != "" && name != "" {
		return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL options", failure.InvalidTunnelFlags, errors.New("--public-url and --name are mutually exclusive"))
	}
	var domain authorityv1.Domain
	var err error
	hostname := ""
	if publicURL != "" {
		hostname = strings.TrimPrefix(publicURL, "https://")
		canonical, canonicalErr := naming.CanonicalizeHostname(hostname)
		if canonicalErr != nil || canonical != hostname || "https://"+hostname != publicURL {
			return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL", failure.InvalidTunnelFlags, errors.Join(canonicalErr, errors.New("public URL must be an HTTPS origin with a canonical hostname")))
		}
		domain, err = readyDomainForHostname(current.domains, hostname)
	} else {
		domain, err = readyDomain(current, selectedDomain)
	}
	if err != nil {
		return "", authorityv1.Domain{}, "", err
	}
	namespace := namespaceForMembership(current.membership, domain)
	if name != "" {
		canonical, err := naming.CanonicalizeHostname(name)
		if err != nil || canonical != name || strings.Contains(name, ".") {
			return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL name", failure.InvalidTunnelFlags, errors.Join(err, errors.New("name must be one lowercase ASCII DNS label")))
		}
		hostname = name + "." + namespace
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
		return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL hostname", failure.InvalidTunnelFlags, errors.Join(err, errors.New("hostname must use lowercase ASCII DNS labels without a trailing dot")))
	}
	publicURLScope := controlv1.Shared
	if _, within := naming.ChildDepth(hostname, namespace); within {
		publicURLScope = controlv1.Member
	} else if current.membership.Role == authorityv1.TeamRoleMember {
		return "", authorityv1.Domain{}, "", failure.Wrap("authorize shared public URL", failure.ServerDenied, errors.New("shared public URLs require a team administrator or owner"))
	}
	return hostname, domain, publicURLScope, nil
}

func readyDomain(current teamContext, selected string) (authorityv1.Domain, error) {
	if selected == "" {
		return defaultReadyDomain(current)
	}
	canonical, err := naming.CanonicalizeHostname(selected)
	if err != nil || canonical != selected {
		return authorityv1.Domain{}, failure.Wrap("validate domain", failure.InvalidDomainName,
			errors.New("domain must use lowercase ASCII DNS labels without a trailing dot"))
	}
	for _, domain := range current.domains {
		if domain.CanonicalDomain == selected {
			if domain.State != authorityv1.DomainStateReady {
				return authorityv1.Domain{}, failure.Wrap("select domain", failure.DomainNotReady,
					fmt.Errorf("domain %s is not ready", selected))
			}
			return domain, nil
		}
	}
	return authorityv1.Domain{}, failure.Wrap("select domain", failure.DomainNotAvailable,
		fmt.Errorf("domain %s is not available to the selected team", selected))
}

func defaultReadyDomain(current teamContext) (authorityv1.Domain, error) {
	for _, domain := range current.domains {
		if domain.Id == current.team.DefaultDomainId {
			if domain.State != authorityv1.DomainStateReady {
				return authorityv1.Domain{}, failure.Wrap("select default domain", failure.DomainNotReady,
					fmt.Errorf("default domain %s is not ready", domain.CanonicalDomain))
			}
			return domain, nil
		}
	}
	return authorityv1.Domain{}, failure.Wrap("select default domain", failure.DomainNotAvailable,
		errors.New("selected team has no available default domain"))
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
		return authorityv1.Domain{}, failure.Wrap("select domain for hostname", failure.DomainNotAvailable,
			fmt.Errorf("hostname %s is outside the selected team's ready domains", hostname))
	}
	return selected, nil
}

func namespaceForMembership(membership authorityv1.Membership, domain authorityv1.Domain) string {
	label := membership.MemberSlug
	if domain.Kind == authorityv1.Managed {
		label = membership.ManagedLabel
	}
	return label + "." + domain.CanonicalDomain
}

func (flags tunnelFlags) requestLimit() int {
	if flags.RequestLimit != nil {
		return *flags.RequestLimit
	}
	return localproxy.DefaultRequestLimit
}

func (p publisherServices) config(target string, allowedIPPrefixes []string, requestLimit int) publisher.Config {
	relayTransportTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	return publisher.Config{
		Control:           p.routes,
		TeamID:            p.teamID,
		MembershipID:      p.membershipID,
		DomainID:          p.domainID,
		Hostname:          p.hostname,
		PublicURLScope:    p.publicURLScope,
		PolicyRevision:    p.policyRevision,
		Target:            target,
		RequestLimit:      requestLimit,
		AllowedIPPrefixes: allowedIPPrefixes,
		Ephemeral:         p.ephemeral,
		State:             p.state,
		QUICConnector:     muxsession.QUICConnector{TLSConfig: relayTransportTLS},
		TCPConnector:      muxsession.TLSYamuxConnector{TLSConfig: relayTransportTLS},
	}
}
