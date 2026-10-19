package controlstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/applicationlimits"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const maximumAppliedInteger = 1<<53 - 1

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

func normalizeAppliedProjectService(s *ProjectServiceConfiguration) error {
	if s.HTTP != nil {
		// remote readiness and path mounts have no group-worker execution contract.
		// reject them before storing a declaration instead of dropping settings.
		if s.Protocol != "http" || s.Publisher != "local" {
			return ErrProjectConfigurationInvalid
		}
		if r := s.HTTP.Readiness; r != nil && r.Path != "/" && !localproxy.ValidMountPrefix(r.Path) {
			return ErrProjectConfigurationInvalid
		}
		if len(s.HTTP.Paths) > 32 || len(s.HTTP.Paths) > 0 && s.PublicURL == nil {
			return ErrProjectConfigurationInvalid
		}
		for prefix := range s.HTTP.Paths {
			if !localproxy.ValidMountPrefix(prefix) {
				return ErrProjectConfigurationInvalid
			}
		}
	}
	descriptor, err := appliedLocalTargetDescriptor(s.Target, s.Protocol)
	if err != nil || descriptor && s.Publisher != "local" {
		return ErrProjectConfigurationInvalid
	}
	if s.PublicURL != nil && s.Protocol != "http" {
		return ErrProjectConfigurationInvalid
	}
	if !descriptor {
		if s.PublicURL != nil && s.Publisher == "local" {
			canonical, err := localproxy.NormalizeTarget(s.Target)
			if err != nil {
				return ErrProjectConfigurationInvalid
			}
			s.Target = canonical
			if s.TargetTLS != nil && !strings.HasPrefix(canonical, "https://") {
				return ErrProjectConfigurationInvalid
			}
		} else {
			if s.Protocol == "http" && s.TargetTLS == nil && strings.HasPrefix(s.Target, "https://") {
				return ErrProjectConfigurationInvalid
			}
			if s.Protocol == "http" && s.TargetTLS != nil && strings.HasPrefix(s.Target, "http://") {
				return ErrProjectConfigurationInvalid
			}
			address, err := normalizeAppliedPrivateAddress(s.Target, s.Protocol)
			if err != nil {
				return err
			}
			s.Target = address
		}
	}
	if s.TargetTLS != nil {
		t := s.TargetTLS
		digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + t.Hostname + "\x00" + t.CAPEM))
		if t.Digest != hex.EncodeToString(digest[:]) {
			return ErrProjectConfigurationInvalid
		}
		if validateServiceTrustRoots(t.Hostname, t.CAPEM, t.CAPEM == "") != nil {
			return ErrProjectConfigurationInvalid
		}
	}
	if p := s.PublicURL; p != nil {
		if p.Hostname != "" {
			host, err := naming.CanonicalizeHostname(p.Hostname)
			if err != nil || host != p.Hostname {
				return ErrProjectConfigurationInvalid
			}
		}
		if p.DomainID != "" && !opaqueid.Valid(p.DomainID, opaqueid.DomainPrefix) {
			return ErrProjectConfigurationInvalid
		}
		// a named group's endpoint and reachability belong to the group. the
		// HTTP block may narrow visitor IPs, never create a second public URL or
		// enable anonymous access. unsupported endpoint/limit overrides fail.
		if s.Publisher != "local" && (p.DomainID != "" || p.Hostname != "" || p.Ephemeral || p.Limits != nil && p.Limits.Traffic != nil) {
			return ErrProjectConfigurationInvalid
		}
		if p.Access == nil {
			p.Access = &ProjectPublicAccess{}
		}
		if p.Access.Mode == "" {
			p.Access.Mode = "restricted"
		}
		if s.Publisher != "local" && p.Access.Mode != "restricted" {
			return ErrProjectConfigurationInvalid
		}
		if !VisitorAccessMode(p.Access.Mode).Valid() || len(p.Access.IP) > 256 {
			return ErrProjectConfigurationInvalid
		}
		prefixes, err := authorization.CanonicalizeIPPrefixes(p.Access.IP)
		if err != nil {
			return ErrProjectConfigurationInvalid
		}
		p.Access.IP = prefixes
		if err = normalizeAppliedLimits(p); err != nil {
			return err
		}
	}
	return nil
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

func normalizeAppliedLimits(p *ProjectServicePublicURL) error {
	l := p.Limits
	if l == nil {
		return nil
	}
	if h := l.HTTP; h != nil {
		v := applicationlimits.Limits{}
		for _, n := range []*int{h.Total, h.Concurrency} {
			if n != nil && (*n < 1 || *n > maximumAppliedInteger) {
				return ErrProjectConfigurationInvalid
			}
		}
		if h.Total != nil {
			v.Requests = *h.Total
		}
		if h.Concurrency != nil {
			v.Concurrency = *h.Concurrency
		}
		if r := h.Rate; r != nil {
			period, err := time.ParseDuration(r.Per)
			if err != nil || period <= 0 || len(r.Per) > 64 || r.Count < 1 || r.Count > maximumAppliedInteger || r.Burst != nil && (*r.Burst < 1 || *r.Burst > maximumAppliedInteger) {
				return ErrProjectConfigurationInvalid
			}
			r.Per = period.String()
			v.RateRequests, v.RatePer = r.Count, period
			if r.Burst != nil {
				v.RateBurst = *r.Burst
			}
		}
		if !v.Valid() {
			return ErrProjectConfigurationInvalid
		}
		if h.Total == nil && h.Concurrency == nil && h.Rate == nil {
			l.HTTP = nil
		}
	}
	if t := l.Traffic; t != nil {
		if t.Validate() != nil {
			return ErrProjectConfigurationInvalid
		}
		for _, n := range []*int{t.Connections, t.Rate, t.Burst} {
			if n != nil && (*n < 1 || *n > maximumAppliedInteger) {
				return ErrProjectConfigurationInvalid
			}
		}
		for _, n := range []*int64{t.UploadBytes, t.DownloadBytes} {
			if n != nil && (*n < 1 || *n > maximumAppliedInteger) {
				return ErrProjectConfigurationInvalid
			}
		}
		for _, n := range []*int64{t.TotalConnections, t.TotalUploadBytes, t.TotalDownloadBytes} {
			if n != nil && (*n < 0 || *n > maximumAppliedInteger) {
				return ErrProjectConfigurationInvalid
			}
		}
		if t.RatePer != nil {
			period, _ := time.ParseDuration(*t.RatePer)
			value := period.String()
			t.RatePer = &value
		}
		encoded, _ := json.Marshal(t)
		if string(encoded) == "{}" {
			l.Traffic = nil
		}
	}
	if l.HTTP == nil && l.Traffic == nil {
		p.Limits = nil
	}
	return nil
}
