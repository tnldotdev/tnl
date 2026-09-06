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
	if err := validateServiceValues(config.Server, config.Team, config.Tunnel, config.Publish, config.Dev); err != nil {
		return err
	}
	if len(config.Services) > 32 {
		return errors.New("services may contain at most 32 entries")
	}
	names := make([]string, 0, len(config.Services))
	for name := range config.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		service := config.Services[name]
		if !ValidServiceName(name) {
			return fmt.Errorf("service name %q must be one lowercase DNS label beginning with a letter", name)
		}
		if err := validateServiceDirectory(service.Directory); err != nil {
			return fmt.Errorf("services.%s.directory: %w", name, err)
		}
		if err := validateServiceValues(service.Server, service.Team, service.Tunnel, service.Publish, service.Dev); err != nil {
			return fmt.Errorf("services.%s: %w", name, err)
		}
	}
	return nil
}

func validateServiceValues(server, team *string, tunnel *Tunnel, publish *Publish, dev *Dev) error {
	if server != nil && (strings.TrimSpace(*server) == "" || strings.TrimSpace(*server) != *server) {
		return errors.New("server must not be empty or surrounded by whitespace")
	}
	if team != nil && (strings.TrimSpace(*team) == "" || strings.TrimSpace(*team) != *team) {
		return errors.New("team must not be empty or surrounded by whitespace")
	}
	if tunnel != nil {
		if tunnel.Host != nil && tunnel.Subdomain != nil {
			return errors.New("tunnel.host and tunnel.subdomain are mutually exclusive")
		}
		if tunnel.Public != nil && *tunnel.Public && tunnel.AllowIP != nil {
			return errors.New("tunnel.public and tunnel.allow_ip are mutually exclusive")
		}
		if len(tunnel.AllowIP) > 63 {
			return errors.New("tunnel.allow_ip may contain at most 63 entries")
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

// ServiceDirectory resolves a service's existing directory and rejects
// symlink traversal outside projectRoot.
func (config TNL) ServiceDirectory(projectRoot, name string) (string, string, error) {
	value := "."
	if name != "" {
		service, found := config.Services[name]
		if !found {
			return "", "", fmt.Errorf("service %q is not configured", name)
		}
		if service.Directory != nil {
			value = *service.Directory
		}
	}
	if err := validateServiceDirectory(&value); err != nil {
		return "", "", err
	}
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	relative := filepath.Clean(value)
	path := filepath.Join(root, relative)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve service directory %q: %w", value, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("inspect service directory %q: %w", value, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("service directory %q is not a directory", value)
	}
	inside, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("service directory %q resolves outside the project root", value)
	}
	return filepath.Clean(path), filepath.ToSlash(relative), nil
}

// EffectiveService merges one named service over the root defaults.
func (config TNL) EffectiveService(name string) (TNL, error) {
	result := TNL{
		Server: config.Server, Team: config.Team,
		Tunnel: cloneTunnel(config.Tunnel), Publish: clonePublish(config.Publish), Dev: cloneDev(config.Dev),
	}
	if name == "" {
		return result, nil
	}
	service, found := config.Services[name]
	if !found {
		return TNL{}, fmt.Errorf("service %q is not configured", name)
	}
	if service.Server != nil {
		result.Server = service.Server
	}
	if service.Team != nil {
		result.Team = service.Team
	}
	result.Tunnel = mergeTunnel(result.Tunnel, service.Tunnel)
	result.Publish = mergePublish(result.Publish, service.Publish)
	result.Dev = mergeDev(result.Dev, service.Dev)
	return result, nil
}

func mergeTunnel(base, override *Tunnel) *Tunnel {
	result := cloneTunnel(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &Tunnel{}
	}
	if override.Host != nil {
		result.Host, result.Subdomain = override.Host, nil
	}
	if override.Subdomain != nil {
		result.Subdomain, result.Host = override.Subdomain, nil
	}
	if override.AllowIP != nil {
		result.AllowIP = slices.Clone(override.AllowIP)
		result.Public = nil
	}
	if override.Public != nil {
		result.Public = override.Public
		if *override.Public {
			result.AllowIP = nil
		}
	}
	if override.Ephemeral != nil {
		result.Ephemeral = override.Ephemeral
	}
	return result
}

func mergePublish(base, override *Publish) *Publish {
	result := clonePublish(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &Publish{}
	}
	if override.Target != nil {
		result.Target = override.Target
	}
	return result
}

func mergeDev(base, override *Dev) *Dev {
	result := cloneDev(base)
	if override == nil {
		return result
	}
	if result == nil {
		result = &Dev{}
	}
	if override.Command != nil {
		result.Command = slices.Clone(override.Command)
	}
	if override.Port != nil {
		result.Port = override.Port
	}
	if override.StartupTimeout != nil {
		result.StartupTimeout = override.StartupTimeout
	}
	return result
}

func cloneTunnel(value *Tunnel) *Tunnel {
	if value == nil {
		return nil
	}
	result := *value
	result.AllowIP = slices.Clone(value.AllowIP)
	return &result
}

func clonePublish(value *Publish) *Publish {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneDev(value *Dev) *Dev {
	if value == nil {
		return nil
	}
	result := *value
	result.Command = slices.Clone(value.Command)
	return &result
}
