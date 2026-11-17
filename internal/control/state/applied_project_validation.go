package state

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

var appliedDiscoveryName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// descriptors are local desired metadata, never commands or discovery inputs
// evaluated by control. an explicit prefix cannot fall back to an address.
func appliedLocalTargetDescriptor(target, protocol string) (bool, error) {
	if target == "app" {
		if protocol != "http" {
			return true, ErrProjectConfigurationInvalid
		}
		return true, nil
	}
	if !strings.HasPrefix(target, "compose:") && !strings.HasPrefix(target, "docker:") {
		return false, nil
	}
	parts := strings.Split(target, ":")
	// a literal host named docker or compose is still a valid TCP address.
	if len(parts) == 2 {
		port, err := strconv.Atoi(parts[1])
		if err == nil && port > 0 && port <= 65535 && strconv.Itoa(port) == parts[1] {
			return false, nil
		}
	}
	if len(parts) != 3 || !appliedDiscoveryName.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." {
		return true, ErrProjectConfigurationInvalid
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != parts[2] {
		return true, ErrProjectConfigurationInvalid
	}
	return true, nil
}

func normalizeAppliedProjectService(key string, s *ProjectServiceConfiguration, local bool) error {
	if !serviceName.MatchString(key) {
		return ErrProjectConfigurationInvalid
	}
	if s.Name == "" {
		s.Name = key
	}
	if !serviceName.MatchString(s.Name) {
		return ErrProjectConfigurationInvalid
	}
	if s.Protocol == "" {
		s.Protocol = "http"
	}
	if (ServiceMetadata{Protocol: s.Protocol}).Validate() != nil || s.Access != nil && !s.Access.Team || (len(s.Target) == 0 && s.TargetDiscovery == nil) || len(s.Target) > 8192 || strings.ContainsAny(s.Target, "\x00\r\n") {
		return ErrProjectConfigurationInvalid
	}
	if s.Ephemeral && !local {
		return ErrProjectConfigurationInvalid
	}
	if s.HTTP != nil {
		// remote publishers do not run local readiness checks or path mounts.
		if s.Protocol != "http" {
			return ErrProjectConfigurationInvalid
		}
		if !local {
			if config.ValidateRemoteHTTP(s.HTTP) != nil {
				return ErrProjectConfigurationInvalid
			}
		}
		if config.ValidateServiceHTTP(s.HTTP) != nil {
			return ErrProjectConfigurationInvalid
		}
		if s.HTTP.Access != nil {
			s.HTTP.Access.Mode = s.HTTP.Access.VisitorMode()
		}
		if r := s.HTTP.Readiness; r != nil && r.Path != "/" && !targetsyntax.ValidMountPrefix(r.Path) {
			return ErrProjectConfigurationInvalid
		}
		if len(s.HTTP.Paths) > 32 {
			return ErrProjectConfigurationInvalid
		}
		for prefix, mount := range s.HTTP.Paths {
			if !targetsyntax.ValidMountPrefix(prefix) || !serviceName.MatchString(mount.Service) || mount.Service == key {
				return ErrProjectConfigurationInvalid
			}
		}
	}
	descriptor := s.TargetDiscovery != nil
	var err error
	if descriptor {
		if s.Target != "" || s.TargetTLS != nil || local {
			return ErrProjectConfigurationInvalid
		}
		s.TargetDiscovery, err = s.TargetDiscovery.Normalize(s.Protocol)
		if err != nil {
			return err
		}
	} else {
		descriptor, err = appliedLocalTargetDescriptor(s.Target, s.Protocol)
	}
	if err != nil || descriptor && s.TargetDiscovery == nil && !local && s.Target != "app" {
		return ErrProjectConfigurationInvalid
	}
	if !descriptor {
		if s.Protocol == "http" && strings.Contains(s.Target, "://") {
			// reachability does not change the origin syntax accepted by config
			// and the publisher. validate before converting to a dial address.
			origin, err := targetsyntax.NormalizeTarget(s.Target)
			if err != nil || s.TargetTLS == nil && strings.HasPrefix(origin, "https://") ||
				s.TargetTLS != nil && strings.HasPrefix(origin, "http://") {
				return ErrProjectConfigurationInvalid
			}
		}
		address, err := normalizeAppliedPrivateAddress(s.Target, s.Protocol)
		if err != nil {
			return err
		}
		s.Target = address
	}
	if s.TargetTLS != nil {
		t := s.TargetTLS
		declaration, err := targettrust.NewDeclaration(t.Hostname, []byte(t.CAPEM))
		if err != nil || t.Digest != "" && t.Digest != declaration.Digest {
			return ErrProjectConfigurationInvalid
		}
		t.Digest = declaration.Digest
	}
	if s.Hostname != "" {
		host, err := naming.CanonicalizeHostname(s.Hostname)
		if err != nil || host != s.Hostname {
			return ErrProjectConfigurationInvalid
		}
	}
	if s.DomainID != "" && !opaqueid.Valid(s.DomainID, opaqueid.DomainPrefix) {
		return ErrProjectConfigurationInvalid
	}
	return normalizeAppliedTraffic(s)
}

func parseAppliedHTTPOrigin(target string) (*url.URL, error) {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery || u.Path != "" && u.Path != "/" || u.RawPath != "" || strings.ContainsAny(u.Hostname(), " \t\\/") || strings.HasSuffix(u.Host, ":") {
		return nil, ErrProjectConfigurationInvalid
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrProjectConfigurationInvalid
		}
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && ip.Zone() != "" {
		return nil, ErrProjectConfigurationInvalid
	}
	return u, nil
}

// private targets are dial addresses. HTTP schemes are address shorthand;
// the separate target_tls snapshot selects publisher-to-target negotiation.
func normalizeAppliedPrivateAddress(target, protocol string) (string, error) {
	if strings.Contains(target, "://") {
		if protocol != "http" {
			return "", ErrProjectConfigurationInvalid
		}
		u, err := parseAppliedHTTPOrigin(target)
		if err != nil {
			return "", err
		}
		port := u.Port()
		if port == "" {
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		target = net.JoinHostPort(u.Hostname(), port)
	}
	host, port, err := net.SplitHostPort(target)
	number, portErr := strconv.Atoi(port)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\\t\r\n\x00@?#") || portErr != nil || number < 1 || number > 65535 {
		return "", ErrProjectConfigurationInvalid
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", ErrProjectConfigurationInvalid
		}
		host = ip.Unmap().String()
	}
	return net.JoinHostPort(host, strconv.Itoa(number)), nil
}

func normalizeAppliedTraffic(s *ProjectServiceConfiguration) error {
	if t := s.Traffic; t != nil {
		if t.Validate() != nil {
			return ErrProjectConfigurationInvalid
		}
		for _, n := range []*int64{t.TotalConnections, t.TotalUploadBytes, t.TotalDownloadBytes} {
			if n != nil && *n > config.MaxConfigInteger {
				return ErrProjectConfigurationInvalid
			}
		}
		if t.RatePer != nil {
			period, _ := time.ParseDuration(*t.RatePer)
			value := period.String()
			t.RatePer = &value
		}
		if *t == (trafficlimits.Selection{}) {
			s.Traffic = nil
		}
	}
	return nil
}
