package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

// Alias names a saved public URL serving one configured entry service.
// omission of the visitor policy inherits the entry service's policy.
type Alias struct {
	Service     string   `json:"service" yaml:"service"`
	Name        *string  `json:"name,omitempty" yaml:"name,omitempty"`
	Domain      *string  `json:"domain,omitempty" yaml:"domain,omitempty"`
	PublicURL   *string  `json:"public_url,omitempty" yaml:"public_url,omitempty"`
	AllowIP     []string `json:"allow_ip,omitempty" yaml:"allow_ip,omitempty" jsonschema:"uniqueItems=true"`
	AllowAllIPs *bool    `json:"allow_all_ips,omitempty" yaml:"allow_all_ips,omitempty"`
}

func (a Alias) RelativeName(key string) string {
	if a.Name != nil {
		return *a.Name
	}
	return key
}

// DefinitionBytes normalizes equivalent relative names and IP ordering for
// agreement between live worktrees. local targets are not alias declarations.
func (a Alias) DefinitionBytes(key string) ([]byte, [32]byte, error) {
	overrideVisitorPolicy := a.AllowIP != nil || a.AllowAllIPs != nil
	if a.PublicURL == nil {
		name := a.RelativeName(key)
		a.Name = &name
	} else {
		hostname, err := naming.ParseExactPublicURL(*a.PublicURL)
		if err != nil {
			return nil, [32]byte{}, err
		}
		publicURL := "https://" + hostname
		a.PublicURL = &publicURL
	}
	a.AllowIP = slices.Sorted(slices.Values(a.AllowIP))
	encoded, err := json.Marshal(struct {
		Alias
		OverrideVisitorPolicy bool `json:"override_visitor_policy"`
	}{a, overrideVisitorPolicy})
	return encoded, sha256.Sum256(encoded), err
}

// ValidateAliases validates local declarations without resolving a member
// namespace, consulting server policy, or creating public URLs.
func ValidateAliases(config TNL) error {
	if len(config.Aliases) > 32 {
		return errors.New("aliases may contain at most 32 entries")
	}
	hostnames := make(map[string]string, len(config.Aliases))
	for _, key := range slices.Sorted(maps.Keys(config.Aliases)) {
		alias := config.Aliases[key]
		if !naming.ValidServiceName(key) {
			return fmt.Errorf("aliases.%s: key must be one lowercase DNS label beginning with a letter", key)
		}
		service, found := config.Services[alias.Service]
		if !found {
			return fmt.Errorf("aliases.%s: service %q is not configured", key, alias.Service)
		}
		if alias.Name != nil && alias.PublicURL != nil {
			return fmt.Errorf("aliases.%s: name and public_url are mutually exclusive", key)
		}
		// ordinary tunnel validation owns domain, exact URL, and IP policy rules.
		if err := validateServiceValues(&Tunnel{Domain: alias.Domain, PublicURL: alias.PublicURL, AllowIP: alias.AllowIP, AllowAllIPs: alias.AllowAllIPs}, nil); err != nil {
			return fmt.Errorf("aliases.%s: %w", key, err)
		}
		identity := ""
		if alias.PublicURL != nil {
			if alias.Domain != nil {
				return fmt.Errorf("aliases.%s: public_url selects its domain; omit domain", key)
			}
			hostname, _ := naming.ParseExactPublicURL(*alias.PublicURL)
			identity = hostname
		} else {
			name := alias.RelativeName(key)
			canonical, err := naming.CanonicalizeHostname(name)
			if err != nil || name != canonical {
				return fmt.Errorf("aliases.%s: name must use lowercase ASCII DNS labels without a trailing dot", key)
			}
			domain := ""
			for _, value := range []*string{domainOf(config.Tunnel), domainOf(service.Tunnel), alias.Domain} {
				if value != nil {
					domain = *value
				}
			}
			identity = strings.Join([]string{name, domain}, "\x00")
		}
		if previous, found := hostnames[identity]; found {
			return fmt.Errorf("aliases.%s: hostname is also used by alias %s", key, previous)
		}
		hostnames[identity] = key
	}
	return nil
}

func domainOf(tunnel *Tunnel) *string {
	if tunnel == nil {
		return nil
	}
	return tunnel.Domain
}
