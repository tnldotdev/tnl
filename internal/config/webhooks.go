package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

// Webhook declares one exact endpoint on the project's stable webhook hostname.
type Webhook struct {
	Service   string   `json:"service" yaml:"service"`
	Path      string   `json:"path" yaml:"path"`
	Provider  string   `json:"provider" yaml:"provider" jsonschema:"enum=amazon-sns,enum=auth0,enum=clerk,enum=custom,enum=discord,enum=github,enum=gitlab,enum=incident-io,enum=lemon-squeezy,enum=linear,enum=loops,enum=paddle,enum=postmark,enum=resend,enum=sendgrid,enum=shopify,enum=slack,enum=stripe,enum=supabase,enum=telegram,enum=twilio,enum=vercel,enum=workos"`
	Delivery  string   `json:"delivery,omitempty" yaml:"delivery,omitempty" jsonschema:"enum=fanout,enum=selected"`
	Methods   []string `json:"methods,omitempty" yaml:"methods,omitempty" jsonschema:"uniqueItems=true"`
	SourceIPs []string `json:"source_ips,omitempty" yaml:"source_ips,omitempty" jsonschema:"uniqueItems=true,minItems=1"`
}

// DeliveryMode resolves the provider default without changing the declaration.
func (w Webhook) DeliveryMode() string {
	if w.Delivery != "" {
		return w.Delivery
	}
	switch w.Provider {
	case "amazon-sns", "discord", "slack", "telegram", "twilio":
		return "selected"
	default:
		return "fanout"
	}
}

// DefinitionBytes gives equivalent declarations the same fingerprint without
// modifying the caller's slices. fingerprints fence local receiver selection.
func (w Webhook) DefinitionBytes() ([]byte, [32]byte, error) {
	w.Delivery = w.DeliveryMode()
	if len(w.Methods) == 0 {
		w.Methods = []string{http.MethodPost}
	}
	w.Methods = slices.Sorted(slices.Values(w.Methods))
	w.SourceIPs = slices.Sorted(slices.Values(w.SourceIPs))
	encoded, err := json.Marshal(w)
	return encoded, sha256.Sum256(encoded), err
}

// ValidateWebhooks checks the declared target and admission policy without
// querying providers or publishing a URL.
func ValidateWebhooks(services Services, definitions map[string]Webhook) error {
	if len(definitions) > 32 {
		return errors.New("webhooks may contain at most 32 entries")
	}
	paths := make(map[string]string, len(definitions))
	names := slices.Sorted(maps.Keys(definitions))
	for _, name := range names {
		endpoint := definitions[name]
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("webhooks.%s: name must be one lowercase DNS label", name)
		}
		if endpoint.Service == "" && len(services) != 0 {
			return fmt.Errorf("webhooks.%s: service is required", name)
		}
		if endpoint.Service != "" {
			if _, ok := services[endpoint.Service]; !ok {
				return fmt.Errorf("webhooks.%s: service %q is not configured", name, endpoint.Service)
			}
		}
		if !localproxy.ValidMountPrefix(endpoint.Path) {
			return fmt.Errorf("webhooks.%s: path must be an exact clean absolute path", name)
		}
		if previous := paths[endpoint.Path]; previous != "" {
			return fmt.Errorf("webhooks.%s: path is also used by %s", name, previous)
		}
		paths[endpoint.Path] = name
		if !webhookips.Valid(endpoint.Provider) {
			return fmt.Errorf("webhooks.%s: provider must be a supported provider", name)
		}
		if endpoint.Delivery != "" && endpoint.Delivery != "fanout" && endpoint.Delivery != "selected" {
			return fmt.Errorf("webhooks.%s: delivery must be fanout or selected", name)
		}
		methods := make(map[string]bool, len(endpoint.Methods))
		for _, method := range endpoint.Methods {
			if !ValidWebhookMethod(method) || methods[method] {
				return fmt.Errorf("webhooks.%s: method %q must be a unique supported HTTP method", name, method)
			}
			methods[method] = true
		}
		if endpoint.SourceIPs != nil && len(endpoint.SourceIPs) == 0 {
			return fmt.Errorf("webhooks.%s: source_ips must not be empty", name)
		}
		ips, err := authorization.CanonicalizeIPPrefixes(endpoint.SourceIPs)
		if err != nil || len(ips) != len(endpoint.SourceIPs) {
			return fmt.Errorf("webhooks.%s: invalid or duplicate IP prefix", name)
		}
		for _, ip := range endpoint.SourceIPs {
			if !canonicalIPText(ip) {
				return fmt.Errorf("webhooks.%s: IP prefix %q must be canonical", name, ip)
			}
		}
	}
	return nil
}

// ValidWebhookMethod restricts configured endpoints to standard HTTP methods.
func ValidWebhookMethod(method string) bool {
	switch method {
	case "POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}
