// Package projectmeta validates and writes browser-safe project metadata.
package projectmeta

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

const Version = 2

// Parse reads the complete local metadata file.
func Parse(data []byte) (Metadata, error) {
	if len(data) > MaxFileBytes {
		return Metadata{}, errors.New("project metadata exceeds size limit")
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return Metadata{}, err
	}
	if err := config.RejectNullValues(fields); err != nil {
		return Metadata{}, err
	}
	for _, key := range []string{"namespace", "dev", "version", "services"} {
		if _, found := fields[key]; !found {
			return Metadata{}, fmt.Errorf("project metadata %s is required", key)
		}
	}
	var metadata Metadata
	if err := json.Unmarshal(data, &metadata, json.RejectUnknownMembers(true)); err != nil {
		return Metadata{}, fmt.Errorf("decode project metadata: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

type Worktree struct {
	Label projectconfig.WorktreeLabel `json:"label"`
}

type Service struct {
	Protocol  string          `json:"protocol"`
	Namespace string          `json:"namespace"`
	Hostname  string          `json:"hostname"`
	URL       string          `json:"url,omitempty"`
	Paths     map[string]Path `json:"paths,omitempty"`
}

func (service *Service) UnmarshalJSON(data []byte) error {
	type object Service
	var value object
	if err := json.Unmarshal(data, &value, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if err := config.RejectNullValues(fields); err != nil {
		return err
	}
	for _, key := range []string{"namespace", "hostname", "protocol"} {
		if _, found := fields[key]; !found {
			return fmt.Errorf("service %s is required", key)
		}
	}
	if _, found := fields["url"]; !found {
		return errors.New("HTTP service url is required")
	}
	*service = Service(value)
	return nil
}

// NewService builds HTTP-only browser metadata. private targets and trust never
// enter this type. managed HTTP endpoints retain their allocated port.
func NewService(namespace, hostname, protocol string, port *int) (Service, error) {
	service := Service{Namespace: namespace, Hostname: hostname, Protocol: protocol, URL: "https://" + hostname}
	if port != nil && *port != 443 {
		if *port < 1024 || *port > 65535 {
			return Service{}, errors.New("managed HTTP port is invalid")
		}
		service.URL = "https://" + net.JoinHostPort(hostname, strconv.Itoa(*port))
	}
	if err := validateServiceAddress(service); err != nil {
		return Service{}, err
	}
	return service, nil
}

func validateServiceAddress(service Service) error {
	if err := canonicalHostname("service namespace", service.Namespace); err != nil {
		return err
	}
	if err := canonicalHostname("service hostname", service.Hostname); err != nil {
		return err
	}
	if service.Protocol != "http" {
		return errors.New("browser metadata contains HTTP public URLs only")
	}
	u, err := url.Parse(service.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() != service.Hostname || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("HTTP service needs its exact HTTPS URL")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1024 || port > 65535 || service.URL != "https://"+net.JoinHostPort(service.Hostname, strconv.Itoa(port)) {
			return errors.New("managed HTTP port is invalid")
		}
	} else if service.URL != "https://"+service.Hostname {
		return errors.New("HTTP service needs its exact HTTPS URL")
	}
	return nil
}

type Path struct {
	Service     string `json:"service"`
	URL         string `json:"url"`
	StripPrefix bool   `json:"stripPrefix"`
}

type IntegrationOrigin struct {
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
}

type Webhook struct {
	Hostname string   `json:"hostname"`
	URL      string   `json:"url"`
	Service  string   `json:"service"`
	Path     string   `json:"path"`
	Methods  []string `json:"methods"`
}

type Alias struct {
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	Service  string `json:"service"`
}

// Metadata is the generated .tnl/local/project.json contract.
type Metadata struct {
	Worktree  *Worktree          `json:"worktree,omitempty"`
	Namespace string             `json:"namespace"`
	Dev       bool               `json:"dev"`
	Services  map[string]Service `json:"services"`
	OAuth     *IntegrationOrigin `json:"oauth,omitempty"`
	Webhooks  map[string]Webhook `json:"webhooks,omitempty"`
	Aliases   map[string]Alias   `json:"aliases,omitempty"`
	Version   int                `json:"version"`
}

// PublicMetadata is the value exposed by @tnldotdev/tnl.
type PublicMetadata struct {
	Worktree  *Worktree          `json:"worktree,omitempty"`
	Namespace string             `json:"namespace"`
	Services  map[string]Service `json:"services"`
	OAuth     *IntegrationOrigin `json:"oauth,omitempty"`
	Webhooks  map[string]Webhook `json:"webhooks,omitempty"`
	Aliases   map[string]Alias   `json:"aliases,omitempty"`
	Dev       bool               `json:"dev"`
}

func (m Metadata) Public(dev bool) PublicMetadata {
	services := make(map[string]Service, len(m.Services))
	for name, service := range m.Services {
		if service.Paths != nil {
			paths := make(map[string]Path, len(service.Paths))
			for prefix, path := range service.Paths {
				paths[prefix] = path
			}
			service.Paths = paths
		}
		services[name] = service
	}
	return PublicMetadata{
		Worktree:  m.Worktree,
		Namespace: m.Namespace, Services: services, OAuth: m.OAuth, Webhooks: m.Webhooks, Aliases: m.Aliases,
		Dev: dev,
	}
}

func (m Metadata) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("project metadata version must be %d", Version)
	}
	if m.Dev {
		return errors.New("generated project metadata cannot be marked as a running app")
	}
	if m.Worktree != nil {
		label := m.Worktree.Label
		parts := []string{label.Project}
		if label.Checkout != "" {
			parts = append(parts, label.Checkout)
		}
		parts = append(parts, label.ID)
		if label.FullLabel != strings.Join(parts, "-") || strings.Contains(label.FullLabel, ".") {
			return errors.New("worktree label components must match fullLabel")
		}
		for _, part := range append(parts, label.FullLabel) {
			if err := canonicalHostname("worktree label", part); err != nil || strings.Contains(part, ".") {
				return errors.New("worktree label components must be lowercase DNS labels")
			}
		}
	}
	if err := canonicalHostname("namespace", m.Namespace); err != nil && (m.Namespace != "" || len(m.Services) != 0 || m.OAuth != nil || len(m.Webhooks) != 0 || len(m.Aliases) != 0) {
		return err
	}
	if m.OAuth != nil {
		if err := validateOrigin("oauth", *m.OAuth); err != nil {
			return err
		}
	}
	if len(m.Services) > 32 {
		return errors.New("project metadata may contain at most 32 services")
	}
	if len(m.Webhooks) > 32 {
		return errors.New("project metadata may contain at most 32 webhooks")
	}
	for name, endpoint := range m.Webhooks {
		if !naming.ValidServiceName(name) || !localproxy.ValidMountPrefix(endpoint.Path) {
			return fmt.Errorf("invalid webhook %q", name)
		}
		if err := canonicalHostname("webhook "+name+" hostname", endpoint.Hostname); err != nil {
			return err
		}
		if endpoint.URL != "https://"+endpoint.Hostname+endpoint.Path {
			return fmt.Errorf("webhook %q URL does not match hostname and path", name)
		}
		if endpoint.Service != "" {
			if service, found := m.Services[endpoint.Service]; !found || service.Protocol != "http" {
				return fmt.Errorf("webhook %q names an unknown service", name)
			}
		} else if len(m.Services) != 0 {
			return fmt.Errorf("webhook %q needs a named service", name)
		}
		if len(endpoint.Methods) == 0 {
			return fmt.Errorf("webhook %q needs a method", name)
		}
		seen := map[string]bool{}
		for _, method := range endpoint.Methods {
			if !config.ValidWebhookMethod(method) || seen[method] {
				return fmt.Errorf("webhook %q has an invalid method", name)
			}
			seen[method] = true
		}
	}
	seenHostnames := make(map[string]string, len(m.Services))
	names := make([]string, 0, len(m.Services))
	for name := range m.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		service := m.Services[name]
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("invalid project metadata service %q", name)
		}
		if err := canonicalHostname("service "+name+" namespace", service.Namespace); err != nil {
			return err
		}
		if err := canonicalHostname("service "+name+" hostname", service.Hostname); err != nil {
			return err
		}
		if previous, found := seenHostnames[service.Hostname]; found {
			return fmt.Errorf("services %q and %q resolve to duplicate hostname %s", previous, name, service.Hostname)
		}
		seenHostnames[service.Hostname] = name
		if err := validateServiceAddress(service); err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
		if len(service.Paths) > 32 {
			return fmt.Errorf("service %q may contain at most 32 path mounts", name)
		}
		prefixes := make([]string, 0, len(service.Paths))
		for prefix := range service.Paths {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
		for _, prefix := range prefixes {
			mount := service.Paths[prefix]
			if !localproxy.ValidMountPrefix(prefix) || mount.Service == name {
				return fmt.Errorf("service %q path mount %q is invalid", name, prefix)
			}
			if !naming.ValidServiceName(mount.Service) {
				return fmt.Errorf("service %q path mount %q has an invalid service name", name, prefix)
			}
			if mount.URL != service.URL+prefix {
				return fmt.Errorf("service %q path mount %q URL must be %s", name, prefix, service.URL+prefix)
			}
		}
	}
	if len(m.Aliases) > 32 {
		return errors.New("project metadata may contain at most 32 aliases")
	}
	for name, alias := range m.Aliases {
		if !naming.ValidServiceName(name) || alias.URL != "https://"+alias.Hostname {
			return fmt.Errorf("invalid alias %q", name)
		}
		if service, found := m.Services[alias.Service]; !found || service.Protocol != "http" {
			return fmt.Errorf("alias %q names an unknown service", name)
		}
		if err := canonicalHostname("alias "+name+" hostname", alias.Hostname); err != nil {
			return err
		}
		if previous, found := seenHostnames[alias.Hostname]; found {
			return fmt.Errorf("alias %q hostname is also used by %s", name, previous)
		}
		seenHostnames[alias.Hostname] = "alias " + name
	}
	return nil
}

func canonicalHostname(kind, value string) error {
	canonical, err := naming.CanonicalizeHostname(value)
	if err != nil || canonical != value {
		return fmt.Errorf("%s must be a canonical hostname", kind)
	}
	return nil
}

func validateOrigin(name string, origin IntegrationOrigin) error {
	if err := canonicalHostname(name+" hostname", origin.Hostname); err != nil {
		return err
	}
	if origin.URL != "https://"+origin.Hostname {
		return fmt.Errorf("%s URL does not match hostname", name)
	}
	return nil
}
