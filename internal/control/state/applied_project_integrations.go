package controlstate

import (
	"encoding/json"

	"github.com/tnldotdev/tnl/internal/config"
)

// reuse the app-led webhook validator and definition normal form without
// resolving provider catalogs or executing project source. integration handlers
// remain local app registrations; group assignments contain service config only.
func normalizeAppliedProjectIntegrations(c *ProjectConfiguration) error {
	if len(c.Webhooks) > 32 {
		return ErrProjectConfigurationInvalid
	}
	if c.Webhooks == nil {
		c.Webhooks = map[string]ProjectWebhook{}
	}
	services := config.Services{}
	for name, service := range c.Services {
		protocol := service.Protocol
		publisher := service.Publisher
		declared := config.Service{Protocol: &protocol, Publisher: &publisher, HTTP: service.HTTP}
		if service.PublicURL != nil {
			declared.Tunnel = &config.Tunnel{}
		}
		services[name] = declared
		if service.HTTP != nil {
			for _, mount := range service.HTTP.Paths {
				destination, found := c.Services[mount.Service]
				if !found || mount.Service == name || destination.Protocol != "http" || destination.Publisher != "local" {
					return ErrProjectConfigurationInvalid
				}
			}
		}
	}
	definitions := map[string]config.Webhook{}
	for name, w := range c.Webhooks {
		service, declared := c.Services[w.Service]
		if !declared || service.Protocol != "http" || service.PublicURL == nil || service.Publisher != "local" || len(w.Path) > 2048 || len(w.Methods) > 7 || len(w.SourceIPs) > 256 {
			return ErrProjectConfigurationInvalid
		}
		definitions[name] = config.Webhook{Service: w.Service, Path: w.Path, Provider: w.Provider, Delivery: w.Delivery, Methods: w.Methods, SourceIPs: w.SourceIPs}
	}
	if err := config.ValidateWebhooks(services, definitions); err != nil {
		return ErrProjectConfigurationInvalid
	}
	for name, definition := range definitions {
		encoded, _, err := definition.DefinitionBytes()
		if err != nil {
			return ErrProjectConfigurationInvalid
		}
		var normal ProjectWebhook
		if err = json.Unmarshal(encoded, &normal); err != nil {
			return ErrProjectConfigurationInvalid
		}
		c.Webhooks[name] = normal
	}
	return nil
}
