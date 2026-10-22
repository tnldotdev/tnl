package resolve

import (
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func PublishHostname(publicURL, name, selectedDomain string, current team.Context) (string, authorityv1.Domain, controlv1.PublicURLScope, error) {
	if publicURL != "" && name != "" {
		return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL options", failure.InvalidTunnelFlags, errors.New("--public-url and --name are mutually exclusive"))
	}
	var domain authorityv1.Domain
	var err error
	hostname := ""
	if publicURL != "" {
		hostname, err = naming.ParseExactPublicURL(publicURL)
		if err != nil {
			return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL", failure.InvalidTunnelFlags, err)
		}
		domain, err = team.ReadyDomainForHostname(current.Domains(), hostname)
	} else {
		domain, err = current.ReadyDomain(selectedDomain)
	}
	if err != nil {
		return "", authorityv1.Domain{}, "", err
	}
	namespace, direct := current.Namespace(domain)
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
	depth, within := naming.ChildDepth(hostname, namespace)
	if !direct && within && depth == 0 {
		return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL hostname", failure.InvalidTunnelFlags, errors.New("a member namespace cannot be published as a public URL"))
	}
	if direct && hostname == namespace && domain.Kind == authorityv1.Managed {
		return "", authorityv1.Domain{}, "", failure.Wrap("validate public URL hostname", failure.InvalidTunnelFlags, errors.New("the managed domain itself cannot be published"))
	}
	if !direct && within && depth > 0 {
		publicURLScope = controlv1.Member
	} else if current.Membership().Role == authorityv1.TeamRoleMember {
		return "", authorityv1.Domain{}, "", failure.Wrap("authorize shared public URL", failure.ServerDenied, errors.New("shared public URLs require a team administrator or owner"))
	}
	return hostname, domain, publicURLScope, nil
}
