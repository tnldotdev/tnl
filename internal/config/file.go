package config

import (
	"bytes"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"go.yaml.in/yaml/v3"
)

const MaxDocumentBytes = 1 << 20

// LoadDocument strictly loads one versioned static configuration document.
func LoadDocument(path string) (Document, error) {
	data, err := readDocument(path)
	if err != nil {
		return Document{}, err
	}
	if !utf8.Valid(data) {
		return Document{}, fmt.Errorf("load config %s: configuration is not valid UTF-8", path)
	}
	var document Document
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		if err := json.Unmarshal(data, &document, json.RejectUnknownMembers(true)); err != nil {
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
	case ".yml", ".yaml":
		if err := validateYAMLTags(data); err != nil {
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		decoder.KnownFields(true)
		if err := decoder.Decode(&document); err != nil {
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			if err == nil {
				err = errors.New("configuration contains more than one YAML document")
			}
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
	default:
		return Document{}, fmt.Errorf("load config %s: configuration must use .yml, .yaml, or .json", path)
	}
	if err := ValidateDocument(document); err != nil {
		return Document{}, fmt.Errorf("load config %s: %w", path, err)
	}
	if document.TNL != nil {
		NormalizePublicURLs(document.TNL)
	}
	return document, nil
}

func validateYAMLTags(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if err := rejectCustomYAMLTags(&document); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains more than one YAML document")
		}
		return err
	}
	return nil
}

func rejectCustomYAMLTags(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	switch node.Tag {
	case "", "!!null", "!!bool", "!!str", "!!int", "!!float", "!!timestamp", "!!seq", "!!map", "!!binary", "!!merge":
	default:
		return fmt.Errorf("custom YAML tag %q is not supported", node.Tag)
	}
	if err := rejectCustomYAMLTags(node.Alias); err != nil {
		return err
	}
	for _, child := range node.Content {
		if err := rejectCustomYAMLTags(child); err != nil {
			return err
		}
	}
	return nil
}

func readDocument(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("load config %s: configuration exceeds %d bytes", path, MaxDocumentBytes)
	}
	return data, nil
}

func ValidateDocument(document Document) error {
	if document.Version == nil {
		return errors.New("version is required")
	}
	if *document.Version != DocumentVersion {
		return fmt.Errorf("unsupported configuration version %d", *document.Version)
	}
	if document.TNL != nil {
		if err := ValidateTNL(*document.TNL); err != nil {
			return fmt.Errorf("tnl: %w", err)
		}
	}
	return nil
}

func ValidateTNL(config TNL) error {
	if err := validateProjectPublisher(config.Publisher); err != nil {
		return fmt.Errorf("publisher: %w", err)
	}
	if err := validateReadiness(config.Readiness); err != nil {
		return err
	}
	if err := ValidateInspection(config.Inspection); err != nil {
		return fmt.Errorf("inspection: %w", err)
	}
	if err := validateServerAndTeam(config.Server, config.Team); err != nil {
		return err
	}
	if err := validateServiceValues(config.Tunnel, config.Publish); err != nil {
		return err
	}
	if err := validateRatePair(config.Tunnel, nil); err != nil {
		return err
	}
	if len(config.Services) != 0 && config.Tunnel != nil {
		if config.Tunnel.Name != nil || config.Tunnel.PublicURL != nil {
			return errors.New("tunnel.name and tunnel.public_url belong under services.NAME.tunnel when services are configured")
		}
	}
	if len(config.Services) > 32 {
		return errors.New("services may contain at most 32 entries")
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
	for _, name := range names {
		service := config.Services[name]
		if config.Publisher != nil && config.Publisher.Type == "docker" && (service.Target == nil || service.Target.Type == "app") {
			return fmt.Errorf("services.%s: a docker publisher requires an address or docker target; use the local publisher for a host app", name)
		}
		effectivePublish := ServicePublish(config.Publish, service)
		if service.Target != nil {
			if service.Publish != nil {
				return fmt.Errorf("services.%s: target and publish cannot be combined", name)
			}
			switch service.Target.Type {
			case "app":
				if service.Target.Address != nil || service.Target.Service != nil || service.Target.Port != nil || service.Target.TargetTLS != nil || service.Target.TargetTLSName != nil || service.Target.TargetCAFile != nil || ServiceProtocol(effectivePublish) != "http" {
					return fmt.Errorf("services.%s.target: app requires HTTP and no private address or TLS settings", name)
				}
			case "address":
				if service.Target.Address == nil {
					return fmt.Errorf("services.%s.target: address is required", name)
				}
				if service.Target.Service != nil || service.Target.Port != nil {
					return fmt.Errorf("services.%s.target: address cannot select a Compose service or port", name)
				}
			case "docker":
				if service.Target.Address != nil || service.Target.Service == nil || !naming.ValidServiceName(*service.Target.Service) ||
					service.Target.Port == nil || *service.Target.Port < 1 || *service.Target.Port > 65535 {
					return fmt.Errorf("services.%s.target: docker requires a Compose service name and private TCP port from 1 to 65535", name)
				}
			default:
				return fmt.Errorf("services.%s.target: type must be app, address, or docker", name)
			}
		}
		if service.HTTP != nil && (service.Readiness != nil || len(service.Paths) != 0) {
			return fmt.Errorf("services.%s: http cannot be combined with readiness or paths", name)
		}
		if service.HTTP != nil {
			if err := validateReadiness(service.HTTP.Readiness); err != nil {
				return fmt.Errorf("services.%s.http: %w", name, err)
			}
		}
		if err := validateReadiness(service.Readiness); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if err := ValidateInspection(service.Inspection); err != nil {
			return fmt.Errorf("services.%s.inspection: %w", name, err)
		}
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("service name %q must be one lowercase DNS label beginning with a letter", name)
		}
		if err := validateServiceDirectory(service.Directory); err != nil {
			return fmt.Errorf("services.%s.directory: %w", name, err)
		}
		if err := validateServiceValues(service.Tunnel, effectivePublish); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		protocol := ServiceProtocol(effectivePublish)
		if protocol != "http" && service.Target == nil {
			return fmt.Errorf("services.%s.target: TCP services require an address or Docker target", name)
		}
		visitorTLS := (*string)(nil)
		if config.Tunnel != nil {
			visitorTLS = config.Tunnel.VisitorTLS
		}
		if service.Tunnel != nil && service.Tunnel.VisitorTLS != nil {
			visitorTLS = service.Tunnel.VisitorTLS
		}
		if visitorTLS != nil {
			if protocol != "postgres" && protocol != "mysql" {
				return fmt.Errorf("services.%s: tunnel.visitor_tls requires PostgreSQL or MySQL", name)
			}
			if *visitorTLS == "passthrough" && effectivePublish != nil &&
				(effectivePublish.TargetTLS != nil && *effectivePublish.TargetTLS || effectivePublish.TargetTLSName != nil || effectivePublish.TargetCAFile != nil) {
				return fmt.Errorf("services.%s: visitor TLS passthrough cannot use private target TLS settings", name)
			}
		}
		paths := service.Paths
		if service.HTTP != nil {
			paths = service.HTTP.Paths
		}
		if protocol != "http" {
			if service.HTTP != nil || service.Readiness != nil || config.Readiness != nil || len(paths) != 0 ||
				service.Tunnel != nil && service.Tunnel.Open != nil && *service.Tunnel.Open ||
				config.Tunnel != nil && config.Tunnel.Open != nil && *config.Tunnel.Open {
				return fmt.Errorf("services.%s: TCP services cannot use HTTP readiness, path mounts, or browser opening", name)
			}
			selected := MergeInspection(config.Inspection, service.Inspection)
			if protocol == "ssh" && selected != nil && selected.Mode != nil && *selected.Mode != InspectionNone {
				return fmt.Errorf("services.%s: SSH inspection supports none only", name)
			}
			for _, definition := range config.Webhooks {
				if definition.Service == name {
					return fmt.Errorf("services.%s: TCP services cannot receive HTTP webhooks", name)
				}
			}
			for _, definition := range config.Aliases {
				if definition.Service == name {
					return fmt.Errorf("services.%s: TCP services cannot serve HTTP aliases", name)
				}
			}
			for _, sibling := range config.Services {
				siblingPaths := sibling.Paths
				if sibling.HTTP != nil {
					siblingPaths = sibling.HTTP.Paths
				}
				for _, mount := range siblingPaths {
					if mount.Service == name {
						return fmt.Errorf("services.%s: TCP services cannot be used as HTTP path mounts", name)
					}
				}
			}
		}
		if err := validateRatePair(service.Tunnel, config.Tunnel); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if len(paths) > 32 {
			return fmt.Errorf("services.%s.paths may contain at most 32 mounts", name)
		}
		prefixes := make([]string, 0, len(paths))
		for prefix := range paths {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
		for _, prefix := range prefixes {
			mount := paths[prefix]
			if !localproxy.ValidMountPrefix(prefix) {
				return fmt.Errorf("services.%s.paths: %q must be a clean absolute path outside /__tnl/", name, prefix)
			}
			if _, found := config.Services[mount.Service]; !found || mount.Service == name {
				return fmt.Errorf("services.%s.paths[%q]: service %q must name another configured service", name, prefix, mount.Service)
			}
		}
	}
	return nil
}

func validateProjectPublisher(publisher *ProjectPublisher) error {
	if publisher == nil {
		return nil
	}
	if publisher.OwnerCredentialFile != nil {
		file := *publisher.OwnerCredentialFile
		if file == "" || len(file) > 4096 || strings.TrimSpace(file) != file || strings.ContainsRune(file, 0) {
			return errors.New("owner_credential_file must be a nonempty path without surrounding whitespace")
		}
	}
	switch publisher.Type {
	case "local":
		if publisher.URL != nil || publisher.Service != nil || publisher.Port != nil || publisher.OwnerCredentialFile != nil {
			return errors.New("local publisher takes no URL, Compose service, port, or credential file")
		}
	case "url":
		if publisher.URL == nil || publisher.Service != nil || publisher.Port != nil || publisher.OwnerCredentialFile == nil {
			return errors.New("url publisher requires an HTTPS origin and owner_credential_file")
		}
		origin, err := url.Parse(*publisher.URL)
		if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Opaque != "" || origin.Host != strings.ToLower(origin.Host) {
			return errors.New("url publisher must use an exact HTTPS origin")
		}
		hostname, err := naming.CanonicalizeHostname(origin.Hostname())
		if err != nil || hostname != origin.Hostname() {
			return errors.New("url publisher requires a canonical DNS hostname")
		}
		if origin.Host != hostname && origin.Port() == "" {
			return errors.New("url publisher port must be from 1 to 65535")
		}
		if origin.Port() != "" {
			port, err := strconv.Atoi(origin.Port())
			if err != nil || port < 1 || port > 65535 {
				return errors.New("url publisher port must be from 1 to 65535")
			}
		}
	case "docker":
		if publisher.URL != nil || publisher.Service == nil || !naming.ValidServiceName(*publisher.Service) ||
			publisher.Port == nil || *publisher.Port < 1 || *publisher.Port > 65535 || publisher.OwnerCredentialFile == nil {
			return errors.New("docker publisher requires a Compose service, TCP port, and owner_credential_file")
		}
	default:
		return errors.New("type must be local, docker, or url")
	}
	return nil
}

func validateReadiness(value *Readiness) error {
	if value == nil {
		return nil
	}
	if value.Path != "/" && !localproxy.ValidMountPrefix(value.Path) {
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

func validateServiceValues(tunnel *Tunnel, publish *Publish) error {
	if tunnel != nil {
		if tunnel.VisitorTLS != nil && *tunnel.VisitorTLS != "terminate" && *tunnel.VisitorTLS != "passthrough" {
			return errors.New("tunnel.visitor_tls must be terminate or passthrough")
		}
		if limits := tunnel.Limits; limits != nil {
			if limits.Requests != nil && *limits.Requests <= 0 || limits.Concurrency != nil && *limits.Concurrency <= 0 {
				return errors.New("tunnel.limits.requests and tunnel.limits.concurrency must be greater than zero")
			}
			if limits.Rate != nil && (limits.Rate.Requests != nil && *limits.Rate.Requests <= 0 || limits.Rate.Per != nil && limits.Rate.Per.Value() <= 0) {
				return errors.New("tunnel.limits.rate requests and per must be positive")
			}
		}
		if tunnel.Name != nil && tunnel.PublicURL != nil {
			return errors.New("tunnel.name and tunnel.public_url are mutually exclusive")
		}
		if tunnel.Domain != nil {
			canonical, err := naming.CanonicalizeHostname(*tunnel.Domain)
			if err != nil || canonical != *tunnel.Domain {
				return errors.New("tunnel.domain must be a canonical domain name")
			}
		}
		if tunnel.Name != nil {
			canonical, err := naming.CanonicalizeHostname(*tunnel.Name)
			if err != nil || canonical != *tunnel.Name || strings.Contains(*tunnel.Name, ".") {
				return errors.New("tunnel.name must be one lowercase ASCII DNS label")
			}
		}
		if tunnel.PublicURL != nil {
			if _, err := naming.ParseExactPublicURL(*tunnel.PublicURL); err != nil {
				return errors.New("tunnel.public_url must be a canonical hostname or HTTPS public URL without a port, path, query, or fragment")
			}
		}
		if tunnel.AllowAllIPs != nil && *tunnel.AllowAllIPs && tunnel.AllowIP != nil {
			return errors.New("tunnel.allow_all_ips cannot be combined with tunnel.allow_ip")
		}
		seen := make(map[string]struct{}, len(tunnel.AllowIP))
		for _, value := range tunnel.AllowIP {
			canonical, err := authorization.CanonicalizeIPPrefixes([]string{value})
			if err != nil || len(canonical) != 1 || !canonicalIPText(value) {
				return fmt.Errorf("tunnel.allow_ip value %q must be a canonical IP address or prefix", value)
			}
			if _, found := seen[canonical[0]]; found {
				return fmt.Errorf("tunnel.allow_ip value %q is duplicated", value)
			}
			seen[canonical[0]] = struct{}{}
		}
	}
	if publish != nil {
		protocol := ServiceProtocol(publish)
		if !controlv1.PublicURLServiceProtocol(protocol).Valid() {
			return errors.New("publish.protocol must be a supported service protocol")
		}
		if publish.TargetTLS != nil && protocol == "http" {
			return errors.New("publish.target_tls requires a TCP service protocol")
		}
		if publish.Target != nil {
			target := string(*publish.Target)
			if protocol == "http" {
				if _, err := localproxy.NormalizeTarget(target); err != nil {
					return fmt.Errorf("publish.target: %w", err)
				}
			} else if _, err := tcptarget.Normalize(target); err != nil {
				return fmt.Errorf("publish.target: %w", err)
			}
		}
		if publish.TargetTLSName != nil {
			if protocol == "http" || *publish.TargetTLSName == "" || strings.TrimSpace(*publish.TargetTLSName) != *publish.TargetTLSName {
				return errors.New("publish.target_tls_name requires a TCP service protocol and a hostname")
			}
		}
		if protocol != "http" && (publish.TargetTLSName != nil || publish.TargetCAFile != nil) &&
			(publish.TargetTLS == nil || !*publish.TargetTLS) {
			return errors.New("publish.target_tls must be true when target TLS settings are supplied")
		}
		if publish.TargetCAFile != nil && (strings.TrimSpace(*publish.TargetCAFile) != *publish.TargetCAFile || *publish.TargetCAFile == "") {
			return errors.New("publish.target_ca_file must be a nonempty path without surrounding whitespace")
		}
	}
	return nil
}

func validateRatePair(tunnel, base *Tunnel) error {
	if tunnel == nil || tunnel.Limits == nil || tunnel.Limits.Rate == nil {
		return nil
	}
	rate := tunnel.Limits.Rate
	requests, per := rate.Requests, rate.Per
	if base != nil && base.Limits != nil && base.Limits.Rate != nil {
		if requests == nil {
			requests = base.Limits.Rate.Requests
		}
		if per == nil {
			per = base.Limits.Rate.Per
		}
	}
	if requests == nil || per == nil {
		return errors.New("tunnel.limits.rate requires positive requests and per")
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

func validateServiceDirectory(directory *string) error {
	if directory == nil {
		return nil
	}
	if *directory == "" || strings.ContainsRune(*directory, '\x00') {
		return errors.New("must not be empty or contain NUL")
	}
	if filepath.IsAbs(*directory) {
		return errors.New("must be relative to the project configuration")
	}
	for _, part := range strings.FieldsFunc(*directory, func(character rune) bool {
		return character == '/' || character == '\\'
	}) {
		if part == ".." {
			return errors.New("must not contain a parent-directory traversal")
		}
	}
	clean := filepath.Clean(*directory)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("must not contain a parent-directory traversal")
	}
	return nil
}
