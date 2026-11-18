package config

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/naming"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

func ValidateDocument(document Document) error {
	if document.Version == nil {
		return errors.New("version is required")
	}
	if *document.Version != DocumentVersion {
		return fmt.Errorf("unsupported configuration version %d", *document.Version)
	}
	if document.TNL != nil {
		if err := ValidateProject(*document.TNL); err != nil {
			return fmt.Errorf("tnl: %w", err)
		}
	}
	return nil
}

func ValidateTNL(config TNL) error {
	if err := ValidateWorkloads(config.Services, config.Workloads); err != nil {
		return err
	}
	if err := ValidateInspection(config.Inspection); err != nil {
		return fmt.Errorf("inspection: %w", err)
	}
	if err := validateServerAndTeam(config.Server, config.Team); err != nil {
		return err
	}
	if config.Name != nil && !naming.ValidServiceName(*config.Name) {
		return errors.New("name must be one lowercase DNS label beginning with a letter")
	}
	if len(config.Services) > 32 {
		return errors.New("services may contain at most 32 entries")
	}
	deployment := SelectedDeployment(config)
	if !naming.ValidServiceName(deployment) {
		return errors.New("selected deployment must be a lowercase DNS label")
	}
	settings := config.DeploymentSettings
	if deployment == "local" && (settings.Description != nil || settings.Domain != nil) {
		return errors.New("local selection has no saved deployment settings")
	}
	if deployment == "local" && len(config.Workloads) != 0 {
		return errors.New("workloads require a remote deployment")
	}
	if deployment != "local" && (config.OAuth || len(config.Webhooks) != 0 || len(config.Aliases) != 0) {
		return errors.New("OAuth, webhooks, and aliases require the local deployment selection")
	}
	if settings.Description != nil && (len(*settings.Description) > 1024 || !utf8.ValidString(*settings.Description)) {
		return errors.New("deployment description must be valid UTF-8 of at most 1024 bytes")
	}
	if settings.Domain != nil {
		domain, err := naming.CanonicalizeHostname(*settings.Domain)
		if err != nil || domain != *settings.Domain {
			return errors.New("deployment domain must be a canonical team domain")
		}
	}
	if err := ValidateWebhooks(config.Services, config.Webhooks); err != nil {
		return err
	}
	if err := ValidateAliases(config); err != nil {
		return err
	}
	names := make([]string, 0, len(config.Services))
	for name := range config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	savedNames := make(map[string]string)
	hostnames := make(map[string]string)
	for _, name := range names {
		service := config.Services[name]
		// access validation normalizes its receiver; project validation owns no
		// caller policy, including when a later field or binding is invalid.
		if service.HTTP != nil && service.HTTP.Access != nil {
			http, access := *service.HTTP, *service.HTTP.Access
			http.Access = &access
			service.HTTP = &http
		}
		if service.Access != nil && !service.Access.Team {
			return fmt.Errorf("services.%s.access requires team: true", name)
		}
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("service name %q must be one lowercase DNS label beginning with a letter", name)
		}
		if err := validateTarget(service); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if deployment != "local" {
			if kind := TargetType(service); kind != "address" && kind != "eks" && kind != "rds" && kind != "app" {
				return fmt.Errorf("services.%s: remote deployments require an address, eks, rds, or app target", name)
			}
			if err := ValidateRemoteHTTP(service.HTTP); err != nil {
				return fmt.Errorf("services.%s.http: %w", name, err)
			}
		}
		savedName := ServiceName(name, service)
		if !naming.ValidServiceName(savedName) {
			return fmt.Errorf("services.%s: name must be one lowercase DNS label beginning with a letter", name)
		}
		if existing := savedNames[savedName]; existing != "" {
			return fmt.Errorf("services.%s: saved name %q is already used by services.%s", name, savedName, existing)
		}
		savedNames[savedName] = name
		if service.HTTP != nil && Protocol(service) != "http" {
			return fmt.Errorf("services.%s: http settings require protocol http", name)
		}
		if service.HTTP != nil {
			if err := ValidateServiceHTTP(service.HTTP); err != nil {
				return fmt.Errorf("services.%s.http: %w", name, err)
			}
			if err := validateReadiness(service.HTTP.Readiness); err != nil {
				return fmt.Errorf("services.%s: %w", name, err)
			}
		}
		if err := ValidateInspection(service.Inspection); err != nil {
			return fmt.Errorf("services.%s.inspection: %w", name, err)
		}
		if err := validateServiceEndpoint(service.Hostname, service.Domain); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if service.Hostname != nil {
			if existing := hostnames[*service.Hostname]; existing != "" {
				return fmt.Errorf("services.%s: hostname is already used by services.%s", name, existing)
			}
			hostnames[*service.Hostname] = name
		}
		if _, err := ResolveTrafficSelection(service.Traffic); err != nil {
			return fmt.Errorf("services.%s.traffic: %w", name, err)
		}
		paths := ServicePaths(service)
		if len(paths) > 32 {
			return fmt.Errorf("services.%s.http.paths may contain at most 32 mounts", name)
		}
		prefixes := make([]string, 0, len(paths))
		for prefix := range paths {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
		for _, prefix := range prefixes {
			mount := paths[prefix]
			if !targetsyntax.ValidMountPrefix(prefix) {
				return fmt.Errorf("services.%s.http.paths: %q must be a clean absolute path outside /__tnl/", name, prefix)
			}
			if destination, found := config.Services[mount.Service]; !found || mount.Service == name || Protocol(destination) != "http" {
				return fmt.Errorf("services.%s.http.paths[%q]: service %q must name another configured HTTP service", name, prefix, mount.Service)
			}
			if deployment != "local" {
				return fmt.Errorf("services.%s.http.paths[%q]: mounted service must use the local publisher", name, prefix)
			}
		}
	}
	return nil
}

// remote HTTP policy cannot add local readiness, path mounts, or browser opening.
func ValidateRemoteHTTP(value *HTTPService) error {
	if value == nil {
		return nil
	}
	if value.Readiness != nil || len(value.Paths) != 0 || value.Open != nil {
		return errors.New("remote deployments do not support readiness, path mounts, or browser opening")
	}
	return ValidateServiceHTTP(value)
}

// validates owned HTTP settings and normalizes their IP policy. read-only project
// validation supplies a detached access value. placement does not change policy.
func ValidateServiceHTTP(value *HTTPService) error {
	if value == nil {
		return nil
	}
	if value.RequestBodyIdleTimeout != nil && value.RequestBodyIdleTimeout.Value() <= 0 {
		return errors.New("http.request_body_idle_timeout must be positive")
	}
	if value.Access != nil {
		if err := value.Access.Validate(); err != nil {
			return err
		}
	}
	return validateWorkLimits(value.Limits)
}

func validateReadiness(value *Readiness) error {
	if value == nil {
		return nil
	}
	if value.Path != "/" && !targetsyntax.ValidMountPrefix(value.Path) {
		return errors.New("readiness.path must be a clean absolute path outside /__tnl/")
	}
	return nil
}

func validateServerAndTeam(server, team *string) error {
	if server != nil && (strings.TrimSpace(*server) == "" || strings.TrimSpace(*server) != *server) {
		return errors.New("server must not be empty or surrounded by whitespace")
	}
	if server != nil {
		if _, err := naming.CanonicalControlURL(*server); err != nil {
			return errors.New("server must be an HTTPS origin")
		}
	}
	if team != nil && (strings.TrimSpace(*team) == "" || strings.TrimSpace(*team) != *team) {
		return errors.New("team must not be empty or surrounded by whitespace")
	}
	return nil
}

func validateServiceEndpoint(hostname, domain *string) error {
	for _, field := range []struct {
		name  string
		value *string
	}{{"hostname", hostname}, {"domain", domain}} {
		if field.value != nil {
			canonical, err := naming.CanonicalizeHostname(*field.value)
			if err != nil || canonical != *field.value {
				return fmt.Errorf("%s must be a canonical DNS hostname", field.name)
			}
		}
	}
	if hostname != nil && domain != nil && *hostname != *domain && !strings.HasSuffix(*hostname, "."+*domain) {
		return errors.New("hostname must belong to domain")
	}
	return nil
}

func canonicalIPText(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && address.Unmap().String() == value
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return false
	}
	return prefix.Masked().String() == value
}

func validateRelativeFilePath(value string) error {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return errors.New("must not be empty or contain NUL")
	}
	if filepath.IsAbs(value) {
		return errors.New("must be relative to the project configuration")
	}
	for _, part := range strings.FieldsFunc(value, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if part == ".." {
			return errors.New("must not contain a parent-directory traversal")
		}
	}
	clean := filepath.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("must not contain a parent-directory traversal")
	}
	return nil
}
