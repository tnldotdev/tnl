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
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/authorization"
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
	if err := validateRequestInspection(config.RequestInspection); err != nil {
		return fmt.Errorf("request_inspection: %w", err)
	}
	if err := validateServerAndTeam(config.Server, config.Team); err != nil {
		return err
	}
	if err := validateServiceValues(config.Tunnel, config.Publish, config.Dev); err != nil {
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
		if err := validateRequestInspection(service.RequestInspection); err != nil {
			return fmt.Errorf("services.%s.request_inspection: %w", name, err)
		}
		if !naming.ValidServiceName(name) {
			return fmt.Errorf("service name %q must be one lowercase DNS label beginning with a letter", name)
		}
		if err := validateServiceDirectory(service.Directory); err != nil {
			return fmt.Errorf("services.%s.directory: %w", name, err)
		}
		if err := validateServiceValues(service.Tunnel, service.Publish, service.Dev); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
		if len(service.Paths) > 32 {
			return fmt.Errorf("services.%s.paths may contain at most 32 mounts", name)
		}
		prefixes := make([]string, 0, len(service.Paths))
		for prefix := range service.Paths {
			prefixes = append(prefixes, prefix)
		}
		slices.Sort(prefixes)
		for _, prefix := range prefixes {
			mount := service.Paths[prefix]
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

func validateRequestInspection(value *RequestInspectionMode) error {
	if value != nil && !value.Valid() {
		return errors.New("must be summary or detailed")
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

func validateServiceValues(tunnel *Tunnel, publish *Publish, dev *Dev) error {
	if tunnel != nil {
		if tunnel.RequestLimit != nil && *tunnel.RequestLimit <= 0 {
			return errors.New("tunnel.request_limit must be greater than zero")
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
			hostname := strings.TrimPrefix(*tunnel.PublicURL, "https://")
			canonical, err := naming.CanonicalizeHostname(hostname)
			if err != nil || canonical != hostname || "https://"+hostname != *tunnel.PublicURL {
				return errors.New("tunnel.public_url must be an HTTPS public URL without a port, path, query, or fragment")
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
	if publish != nil && publish.Target != nil {
		if _, err := localproxy.NormalizeTarget(string(*publish.Target)); err != nil {
			return fmt.Errorf("publish.target: %w", err)
		}
	}
	if dev != nil {
		if dev.Command != nil {
			if len(dev.Command) == 0 {
				return errors.New("dev.command must not be empty")
			}
			for _, argument := range dev.Command {
				if argument == "" {
					return errors.New("dev.command arguments must not be empty")
				}
			}
		}
		if dev.Port != nil && (*dev.Port < 1 || *dev.Port > 65535) {
			return errors.New("dev.port must be between 1 and 65535")
		}
		if dev.StartupTimeout != nil {
			value := dev.StartupTimeout.Value()
			if value <= 0 || value > 10*time.Minute {
				return errors.New("dev.startup_timeout must be greater than zero and at most 10 minutes")
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
