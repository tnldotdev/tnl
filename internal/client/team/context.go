package team

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// Context contains the selected team and membership, with domains when requested.
type Context struct {
	team       authorityv1.Team
	membership authorityv1.Membership
	domains    []authorityv1.Domain
	mode       naming.ManagedURLMode
}

func NewContext(selected authorityv1.Team, membership authorityv1.Membership, domains []authorityv1.Domain, mode naming.ManagedURLMode) Context {
	return Context{team: selected, membership: membership, domains: domains, mode: mode}
}

func (c Context) Team() authorityv1.Team             { return c.team }
func (c Context) Membership() authorityv1.Membership { return c.membership }
func (c Context) Domains() []authorityv1.Domain      { return c.domains }
func (c Context) Mode() naming.ManagedURLMode        { return c.mode }

func (c Context) Namespace(domain authorityv1.Domain) (string, bool) {
	return naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: domain.CanonicalDomain, Managed: domain.Kind == authorityv1.Managed,
		Mode: c.mode, Personal: c.team.Kind == authorityv1.Personal,
		TeamName: c.team.DisplayName, MemberSlug: c.membership.MemberSlug,
		ManagedLabel: c.membership.ManagedLabel,
	})
}

func (c Context) ReadyDomain(selected string) (authorityv1.Domain, error) {
	if selected == "" {
		return c.defaultReadyDomain()
	}
	canonical, err := naming.CanonicalizeHostname(selected)
	if err != nil || canonical != selected {
		return authorityv1.Domain{}, failure.Wrap("validate domain", failure.InvalidDomainName,
			errors.New("domain must use lowercase ASCII DNS labels without a trailing dot"))
	}
	for _, domain := range c.domains {
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

func (c Context) defaultReadyDomain() (authorityv1.Domain, error) {
	for _, domain := range c.domains {
		if domain.Id == c.team.DefaultDomainId {
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

func ReadyDomainForHostname(domains []authorityv1.Domain, hostname string) (authorityv1.Domain, error) {
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

func (c Context) Domain(value string) (authorityv1.Domain, error) {
	if domain, ok := FindDomain(c.domains, value); ok {
		return domain, nil
	}
	return authorityv1.Domain{}, failure.Wrap("select team domain", failure.DomainNotAvailable,
		fmt.Errorf("domain %q is not available to the selected team", value))
}

func FindDomain(domains []authorityv1.Domain, value string) (authorityv1.Domain, bool) {
	for _, domain := range domains {
		if domain.Id == value || domain.CanonicalDomain == value {
			return domain, true
		}
	}
	return authorityv1.Domain{}, false
}
