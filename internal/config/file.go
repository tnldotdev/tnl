package config

import (
	"bytes"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
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
		var raw any
		if err := json.Unmarshal(data, &raw); err != nil {
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
		if err := RejectNullValues(raw); err != nil {
			return Document{}, fmt.Errorf("load config %s: %w", path, err)
		}
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
	if len(document.Content) == 0 {
		return errors.New("configuration document is required")
	}
	if err := validateYAMLValueTypes(document.Content[0], reflect.TypeOf(Document{}), map[*yaml.Node]bool{}); err != nil {
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
	return checkYAMLTags(node, map[*yaml.Node]bool{})
}

func checkYAMLTags(node *yaml.Node, active map[*yaml.Node]bool) error {
	if node == nil {
		return nil
	}
	if active[node] {
		return errors.New("recursive YAML aliases are not supported")
	}
	active[node] = true
	defer delete(active, node)
	switch node.Tag {
	case "", "!!null", "!!bool", "!!str", "!!int", "!!float", "!!timestamp", "!!seq", "!!map", "!!binary", "!!merge":
	default:
		return fmt.Errorf("custom YAML tag %q is not supported", node.Tag)
	}
	if err := checkYAMLTags(node.Alias, active); err != nil {
		return err
	}
	for _, child := range node.Content {
		if err := checkYAMLTags(child, active); err != nil {
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
	if err := ValidateInspection(config.Inspection); err != nil {
		return fmt.Errorf("inspection: %w", err)
	}
	if err := validateServerAndTeam(config.Server, config.Team); err != nil {
		return err
	}
	if config.Name != nil && !naming.ValidServiceName(*config.Name) {
		return errors.New("name must be one lowercase DNS label beginning with a letter")
	}
	if err := validateTunnel(config.Tunnel); err != nil {
		return err
	}
	if err := validateLimits(tunnelLimits(config.Tunnel), nil, ""); err != nil {
		return err
	}
	if config.Name != nil && config.Tunnel != nil && config.Tunnel.PublicURL != nil {
		return errors.New("name and public_url.hostname are mutually exclusive")
	}
	if len(config.Services) != 0 && (config.Name != nil || config.Tunnel != nil && (config.Tunnel.Name != nil || config.Tunnel.PublicURL != nil)) {
		return errors.New("name and public_url.hostname belong under services.NAME when services are configured")
	}
	if len(config.Services) > 32 {
		return errors.New("services may contain at most 32 entries")
	}
	if len(config.Publishers) > 32 {
		return errors.New("publishers may contain at most 32 entries")
	}
	for name, group := range config.Publishers {
		if group.AWS != nil && (group.AWS.ReplicaCount() < 1 || group.AWS.ReplicaCount() > MaxPublisherReplicas) {
			return fmt.Errorf("publishers.%s.aws.replicas must be between 1 and %d", name, MaxPublisherReplicas)
		}
		if name == "local" || !naming.ValidServiceName(name) {
			return fmt.Errorf("publisher group %q must be a lowercase DNS label other than reserved local", name)
		}
		if group.Description != nil && (len(*group.Description) > 1024 || !utf8.ValidString(*group.Description)) {
			return fmt.Errorf("publishers.%s.description must be valid UTF-8 of at most 1024 bytes", name)
		}
		if group.Domain != nil {
			domain, err := naming.CanonicalizeHostname(*group.Domain)
			if err != nil || domain != *group.Domain {
				return fmt.Errorf("publishers.%s.domain must be a canonical team domain", name)
			}
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
	publicHostnames := make(map[string]string)
	for _, name := range names {
		service := config.Services[name]
		if service.Access != nil && !service.Access.Team {
			return fmt.Errorf("services.%s.access requires team: true", name)
		}
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("service name %q must be one lowercase DNS label beginning with a letter", name)
		}
		if err := validateTarget(service); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if group := PublisherName(service); group != "local" {
			if _, found := config.Publishers[group]; !found {
				return fmt.Errorf("services.%s.publisher: group %q is not configured", name, group)
			}
			if TargetType(service) != "address" {
				return fmt.Errorf("services.%s: remote publisher groups require a reachable address target", name)
			}
			if service.HTTP != nil {
				return fmt.Errorf("services.%s.http: remote publisher assignments do not support HTTP settings; use a local service", name)
			}
		}
		if service.Publisher != nil && *service.Publisher == "" {
			return fmt.Errorf("services.%s.publisher must not be empty", name)
		}
		savedName := ServiceName(name, service)
		if !naming.ValidServiceName(savedName) {
			return fmt.Errorf("services.%s: name must be one lowercase DNS label beginning with a letter", name)
		}
		if existing := savedNames[savedName]; existing != "" {
			return fmt.Errorf("services.%s: saved name %q is already used by services.%s", name, savedName, existing)
		}
		savedNames[savedName] = name
		if service.Name != nil && service.Tunnel != nil && service.Tunnel.PublicURL != nil {
			return fmt.Errorf("services.%s: name and public_url.hostname are mutually exclusive", name)
		}
		if Protocol(service) != "http" {
			if service.Tunnel != nil {
				return fmt.Errorf("services.%s: private services cannot use public_url settings", name)
			}
		}
		if service.HTTP != nil && Protocol(service) != "http" {
			return fmt.Errorf("services.%s: http settings require protocol http", name)
		}
		if service.HTTP != nil {
			if err := validateReadiness(service.HTTP.Readiness); err != nil {
				return fmt.Errorf("services.%s: %w", name, err)
			}
		}
		if err := ValidateInspection(service.Inspection); err != nil {
			return fmt.Errorf("services.%s.inspection: %w", name, err)
		}
		if err := validateTunnel(service.Tunnel); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if service.Tunnel != nil && service.Tunnel.PublicURL != nil {
			hostname, _ := naming.ParseExactPublicURL(*service.Tunnel.PublicURL)
			if existing := publicHostnames[hostname]; existing != "" {
				return fmt.Errorf("services.%s: public_url.hostname is already used by services.%s", name, existing)
			}
			publicHostnames[hostname] = name
		}
		protocol := Protocol(service)
		if IsPublicService(service) {
			if err := validateLimits(tunnelLimits(service.Tunnel), tunnelLimits(config.Tunnel), protocol); err != nil {
				return fmt.Errorf("services.%s: %w", name, err)
			}
		}
		paths := ServicePaths(service)
		if len(paths) != 0 && !IsPublicService(service) {
			return fmt.Errorf("services.%s.http.paths requires an explicit public_url block", name)
		}
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
			if !localproxy.ValidMountPrefix(prefix) {
				return fmt.Errorf("services.%s.http.paths: %q must be a clean absolute path outside /__tnl/", name, prefix)
			}
			if destination, found := config.Services[mount.Service]; !found || mount.Service == name || Protocol(destination) != "http" {
				return fmt.Errorf("services.%s.http.paths[%q]: service %q must name another configured HTTP service", name, prefix, mount.Service)
			}
			if PublisherName(config.Services[mount.Service]) != "local" {
				return fmt.Errorf("services.%s.http.paths[%q]: mounted service must use the local publisher", name, prefix)
			}
		}
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

func validateTunnel(tunnel *Tunnel) error {
	if tunnel != nil {
		if tunnel.Name != nil && tunnel.PublicURL != nil {
			return errors.New("name and public_url.hostname are mutually exclusive")
		}
		if tunnel.Domain != nil {
			canonical, err := naming.CanonicalizeHostname(*tunnel.Domain)
			if err != nil || canonical != *tunnel.Domain {
				return errors.New("public_url.domain must be a canonical domain name")
			}
		}
		if tunnel.Name != nil {
			canonical, err := naming.CanonicalizeHostname(*tunnel.Name)
			if err != nil || canonical != *tunnel.Name || strings.Contains(*tunnel.Name, ".") {
				return errors.New("name must be one lowercase ASCII DNS label")
			}
		}
		if tunnel.PublicURL != nil {
			if _, err := naming.ParseExactPublicURL(*tunnel.PublicURL); err != nil {
				return errors.New("public_url.hostname must be a canonical hostname or HTTPS public URL without a port, path, query, or fragment")
			}
		}
		if tunnel.Access != nil {
			if err := tunnel.Access.Validate(); err != nil {
				return fmt.Errorf("public_url.access: %w", err)
			}
		}
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
