// Package projectmeta validates and writes browser-safe project metadata.
package projectmeta

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
)

const Version = 1

type Service struct {
	Namespace string          `json:"namespace"`
	Hostname  string          `json:"hostname"`
	URL       string          `json:"url"`
	Paths     map[string]Path `json:"paths,omitempty"`
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

// Metadata is the generated .tnl/project.json contract. ServiceDirectories is
// private discovery data and is deliberately omitted from public declarations.
type Metadata struct {
	Namespace          string             `json:"namespace"`
	Dev                bool               `json:"dev"`
	ServiceDirectories map[string]string  `json:"serviceDirectories"`
	Services           map[string]Service `json:"services"`
	OAuth              *IntegrationOrigin `json:"oauth,omitempty"`
	Version            int                `json:"version"`
}

// PublicMetadata is the value exposed by @tnldotdev/tnl.
type PublicMetadata struct {
	Namespace string             `json:"namespace"`
	Services  map[string]Service `json:"services"`
	OAuth     *IntegrationOrigin `json:"oauth,omitempty"`
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
		Namespace: m.Namespace, Services: services, OAuth: m.OAuth,
		Dev: dev,
	}
}

func (m Metadata) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("project metadata version must be %d", Version)
	}
	if m.Dev {
		return errors.New("generated project metadata cannot be marked as running under tnl dev")
	}
	if err := canonicalHostname("namespace", m.Namespace); err != nil {
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
	if len(m.ServiceDirectories) != len(m.Services) {
		return errors.New("project metadata requires one directory for every service")
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
		parsed, err := url.Parse(service.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host != service.Hostname || parsed.Path != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return fmt.Errorf("service %q URL must be exactly https://%s", name, service.Hostname)
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
			if _, found := m.Services[mount.Service]; !found {
				return fmt.Errorf("service %q path mount %q names an unknown service", name, prefix)
			}
			if mount.URL != service.URL+prefix {
				return fmt.Errorf("service %q path mount %q URL must be %s", name, prefix, service.URL+prefix)
			}
		}
		directory, found := m.ServiceDirectories[name]
		if !found || directory == "" || filepath.IsAbs(directory) || strings.ContainsRune(directory, '\x00') {
			return fmt.Errorf("service %q directory must be a non-empty relative path", name)
		}
		clean := filepath.Clean(filepath.FromSlash(directory))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.ToSlash(clean) != directory {
			return fmt.Errorf("service %q directory must be a clean relative path", name)
		}
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
