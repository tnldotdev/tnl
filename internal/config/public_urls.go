package config

import "github.com/tnldotdev/tnl/internal/naming"

// NormalizePublicURLs gives equivalent exact hostnames one identity after validation.
func NormalizePublicURLs(config *TNL) {
	normalizeTunnelPublicURL(config.Tunnel)
	for _, service := range config.Services {
		normalizeTunnelPublicURL(service.Tunnel)
	}
	for name, alias := range config.Aliases {
		if alias.PublicURL != nil {
			hostname, err := naming.ParseExactPublicURL(*alias.PublicURL)
			if err == nil {
				publicURL := "https://" + hostname
				alias.PublicURL = &publicURL
				config.Aliases[name] = alias
			}
		}
	}
}

func normalizeTunnelPublicURL(tunnel *Tunnel) {
	if tunnel == nil || tunnel.PublicURL == nil {
		return
	}
	hostname, err := naming.ParseExactPublicURL(*tunnel.PublicURL)
	if err == nil {
		*tunnel.PublicURL = "https://" + hostname
	}
}
