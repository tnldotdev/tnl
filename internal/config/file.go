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
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
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
	if err := validateRatePairs(config.Tunnel, nil); err != nil {
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
		if service.Protocol != nil && *service.Protocol != "http" && service.Target == nil && service.Publish == nil {
			return fmt.Errorf("services.%s: TCP service requires an address or Docker target", name)
		}
		if config.Publisher != nil && config.Publisher.Type == "url" && service.Target != nil && service.Target.Type == "docker" {
			return fmt.Errorf("services.%s: a url publisher cannot use a host Docker mapping; select an address it can reach", name)
		}
		effectivePublish := ServicePublish(config.Publish, service)
		if service.Target != nil {
			if service.Target.TLS != nil {
				if service.Target.TLS.ServerName != nil && (*service.Target.TLS.ServerName == "" || strings.TrimSpace(*service.Target.TLS.ServerName) != *service.Target.TLS.ServerName) {
					return fmt.Errorf("services.%s.target.tls.server_name must be a hostname", name)
				}
				if service.Target.TLS.CAFile != nil && (*service.Target.TLS.CAFile == "" || strings.TrimSpace(*service.Target.TLS.CAFile) != *service.Target.TLS.CAFile) {
					return fmt.Errorf("services.%s.target.tls.ca_file must be a nonempty path", name)
				}
			}
			if service.Publish != nil {
				return fmt.Errorf("services.%s: target and publish cannot be combined", name)
			}
			switch service.Target.Type {
			case "app":
				if service.Target.Address != nil || !emptyDockerSelection(service.Target.DockerSelection) || service.Target.TLS != nil || ServiceProtocol(effectivePublish) != "http" {
					return fmt.Errorf("services.%s.target: app requires HTTP and no private address or TLS settings", name)
				}
			case "address":
				if service.Target.Address == nil {
					return fmt.Errorf("services.%s.target: address is required", name)
				}
				if !emptyDockerSelection(service.Target.DockerSelection) {
					return fmt.Errorf("services.%s.target: address cannot select a Compose service or port", name)
				}
			case "docker":
				if service.Target.Address != nil {
					return fmt.Errorf("services.%s.target: docker cannot use address", name)
				}
				if err := validateDockerSelection(service.Target.DockerSelection); err != nil {
					return fmt.Errorf("services.%s.target: %w", name, err)
				}
			default:
				return fmt.Errorf("services.%s.target: type must be app, address, or docker", name)
			}
		}
		if service.HTTP != nil && len(service.Paths) != 0 {
			return fmt.Errorf("services.%s: http.paths cannot be combined with paths", name)
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
		if protocol != "http" && service.HTTP != nil {
			return fmt.Errorf("services.%s: http settings require an HTTP service protocol", name)
		}
		if service.Tunnel != nil && service.Tunnel.Limits != nil &&
			(protocol == "http" && service.Tunnel.Limits.TCP != nil || protocol != "http" && service.Tunnel.Limits.HTTP != nil) {
			return fmt.Errorf("services.%s.tunnel.limits: select only the service protocol's limits", name)
		}
		paths := service.Paths
		if service.HTTP != nil {
			paths = service.HTTP.Paths
		}
		if protocol != "http" {
			if service.HTTP != nil || service.Readiness != nil || len(paths) != 0 {
				return fmt.Errorf("services.%s: TCP services cannot use HTTP readiness, path mounts, or browser opening", name)
			}
			selected := MergeInspection(config.Inspection, service.Inspection)
			if selected != nil && selected.Mode != nil && *selected.Mode == InspectionDetailed &&
				protocol != "mysql" && protocol != "postgres" {
				return fmt.Errorf("services.%s: detailed inspection requires HTTP, PostgreSQL, or MySQL", name)
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
		if err := validateRatePairs(service.Tunnel, config.Tunnel); err != nil {
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
	switch publisher.Type {
	case "local":
		if !emptyDockerSelection(publisher.DockerSelection) {
			return errors.New("local publisher takes no Docker selection")
		}
	case "docker":
		if err := validateDockerSelection(publisher.DockerSelection); err != nil {
			return fmt.Errorf("docker publisher: %w", err)
		}
	default:
		return errors.New("type must be local or docker")
	}
	return nil
}

func emptyDockerSelection(selection DockerSelection) bool {
	return selection.Container == nil && len(selection.Labels) == 0 && selection.Compose == nil && selection.ContainerPort == nil
}

func validateDockerSelection(selection DockerSelection) error {
	if selection.ContainerPort == nil || *selection.ContainerPort < 1 || *selection.ContainerPort > 65535 {
		return errors.New("docker requires container_port from 1 to 65535")
	}
	count := 0
	if selection.Container != nil {
		count++
		if !validDockerContainer(*selection.Container) {
			return errors.New("docker container must be an explicit container name or ID")
		}
	}
	if len(selection.Labels) != 0 {
		count++
		if len(selection.Labels) > 8 {
			return errors.New("docker accepts at most eight exact labels")
		}
		for key, value := range selection.Labels {
			if key == "" || value == "" || len(key) > 128 || len(value) > 256 || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value ||
				strings.ContainsAny(key+value, "\x00\n\r") {
				return errors.New("docker labels must be nonempty exact key/value pairs")
			}
		}
	}
	if selection.Compose != nil {
		count++
		value := selection.Compose
		if !validComposeFile(value.File) || !validComposeProject(value.Project) || !naming.ValidServiceName(value.Service) {
			return errors.New("docker compose requires a relative file, worktree project label, and service name")
		}
	}
	if count != 1 {
		return errors.New("docker requires exactly one container, labels, or compose selector")
	}
	return nil
}

func validDockerContainer(value string) bool {
	if len(value) < 1 || len(value) > 128 || (value[0] < 'a' || value[0] > 'z') && (value[0] < 'A' || value[0] > 'Z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validComposeFile(value string) bool {
	if value == "" || len(value) > 512 || strings.TrimSpace(value) != value || strings.ContainsRune(value, 0) || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(value)
	return clean == value && clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) &&
		(filepath.Ext(clean) == ".yaml" || filepath.Ext(clean) == ".yml")
}

func validComposeProject(value string) bool {
	if value == "" || len(value) > 63 || strings.Contains(value, ".") {
		return false
	}
	canonical, err := naming.CanonicalizeHostname(value)
	return err == nil && canonical == value
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
		if limits := tunnel.Limits; limits != nil {
			if traffic := limits.Traffic; traffic != nil {
				if traffic.Connections != nil && *traffic.Connections <= 0 ||
					traffic.Rate != nil && (traffic.Rate.Count != nil && *traffic.Rate.Count <= 0 ||
						traffic.Rate.Per != nil && traffic.Rate.Per.Value() <= 0 ||
						traffic.Rate.Burst != nil && *traffic.Rate.Burst <= 0) {
					return errors.New("tunnel.limits.traffic connections and rate values must be positive")
				}
				if traffic.Bandwidth != nil {
					for _, value := range []*ByteRate{traffic.Bandwidth.Upload, traffic.Bandwidth.Download} {
						if value != nil {
							if _, err := trafficlimits.ParseByteRate(string(*value)); err != nil {
								return fmt.Errorf("tunnel.limits.traffic.bandwidth: %w", err)
							}
						}
					}
				}
			}
			for _, selected := range []struct {
				name string
				work *WorkLimits
			}{{"http", limits.HTTP}, {"tcp", limits.TCP}} {
				if selected.work == nil {
					continue
				}
				if selected.work.Total != nil && *selected.work.Total <= 0 || selected.work.Concurrency != nil && *selected.work.Concurrency <= 0 {
					return fmt.Errorf("tunnel.limits.%s total and concurrency must be positive", selected.name)
				}
				if rate := selected.work.Rate; rate != nil &&
					(rate.Count != nil && *rate.Count <= 0 || rate.Per != nil && rate.Per.Value() <= 0 || rate.Burst != nil && *rate.Burst <= 0) {
					return fmt.Errorf("tunnel.limits.%s.rate count, per, and burst must be positive", selected.name)
				}
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

func validateRatePairs(tunnel, base *Tunnel) error {
	if tunnel == nil || tunnel.Limits == nil {
		return nil
	}
	for _, selected := range []struct {
		name string
		work *WorkLimits
		base *WorkLimits
	}{{name: "http", work: tunnel.Limits.HTTP}, {name: "tcp", work: tunnel.Limits.TCP}} {
		if selected.work == nil || selected.work.Rate == nil {
			continue
		}
		if base != nil && base.Limits != nil {
			if selected.name == "http" {
				selected.base = base.Limits.HTTP
			} else {
				selected.base = base.Limits.TCP
			}
		}
		count, per := selected.work.Rate.Count, selected.work.Rate.Per
		if selected.base != nil && selected.base.Rate != nil {
			if count == nil {
				count = selected.base.Rate.Count
			}
			if per == nil {
				per = selected.base.Rate.Per
			}
		}
		if count == nil || per == nil {
			return fmt.Errorf("tunnel.limits.%s.rate requires positive count and per", selected.name)
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
