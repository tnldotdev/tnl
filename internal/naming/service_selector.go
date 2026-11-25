package naming

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

type SelectorKind uint8

const (
	SelectorOmitted SelectorKind = iota
	SelectorID
	SelectorName
	SelectorAddress
)

// ServiceSelector is a parsed command argument, not proof that a service
// exists or that its address can be reached.
type ServiceSelector struct {
	Kind SelectorKind
	ID   string
	Name string
	Host string

	// scheme is the URL scheme; protocol is the service protocol.
	Scheme   string
	Protocol string
	// port includes a URL scheme's default; zero means unconstrained.
	Port         int
	ExplicitPort bool

	// resource marks a non-root path or any query. whole-service lookups
	// reject it before considering any candidates.
	Resource bool
	// these fields preserve the HTTP request suffix, not database URI options.
	EscapedPath string
	RawQuery    string
	ForceQuery  bool
}

// ParseServiceSelector separates names, exact IDs, and addresses. It neither
// resolves names nor interprets non-HTTP URL paths or queries.
func ParseServiceSelector(value string) (ServiceSelector, error) {
	switch {
	case value == "":
		return ServiceSelector{Kind: SelectorOmitted}, nil
	case strings.Contains(value, "://"):
		return parseServiceSelectorURL(value)
	case strings.HasPrefix(value, opaqueid.ServicePrefix):
		if !opaqueid.Valid(value, opaqueid.ServicePrefix) {
			return ServiceSelector{}, errors.New("invalid service ID")
		}
		return ServiceSelector{Kind: SelectorID, ID: value}, nil
	case ValidServiceName(value):
		return ServiceSelector{Kind: SelectorName, Name: value}, nil
	default:
		host, port, err := parseSelectorAuthority(value, true)
		if err != nil {
			return ServiceSelector{}, err
		}
		return ServiceSelector{Kind: SelectorAddress, Host: host, Port: port, ExplicitPort: port != 0}, nil
	}
}

// MatchesEndpoint compares only address facts. The caller owns candidate
// scope, name fallback, and whether resource suffixes are allowed.
func (s ServiceSelector) MatchesEndpoint(protocol, hostname string, port int) bool {
	if s.Kind != SelectorAddress || (s.Protocol != "" && s.Protocol != protocol) || (s.Port != 0 && s.Port != port) {
		return false
	}
	host, err := canonicalSelectorHost(hostname)
	return err == nil && s.Host == host
}

// WholeAddress returns an address without resource paths, queries, or user
// information. it is suitable for guidance, not a replacement probe URL.
func (s ServiceSelector) WholeAddress() string {
	host := s.Host
	if s.ExplicitPort {
		host = net.JoinHostPort(host, strconv.Itoa(s.Port))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if s.Scheme != "" {
		return s.Scheme + "://" + host
	}
	return host
}

func parseServiceSelectorURL(value string) (ServiceSelector, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" {
		// url.Parse errors may contain credentials or query values.
		return ServiceSelector{}, errors.New("invalid service URL")
	}
	if parsed.User != nil || strings.Contains(value, "#") {
		return ServiceSelector{}, errors.New("service URLs cannot contain user information or fragments")
	}

	s := ServiceSelector{Kind: SelectorAddress, Scheme: parsed.Scheme}
	switch s.Scheme {
	case "http":
		s.Protocol, s.Port = "http", 80
	case "https":
		s.Protocol, s.Port = "http", 443
	case "postgres", "postgresql":
		s.Protocol, s.Port = "postgres", 5432
	case "mysql":
		s.Protocol, s.Port = "mysql", 3306
	case "kubernetes":
		s.Protocol, s.Port = "kubernetes", 6443
	case "tcp":
		s.Protocol = "tcp"
	default:
		return ServiceSelector{}, errors.New("unsupported service URL scheme")
	}

	host, port, err := parseSelectorAuthority(parsed.Host, false)
	if err != nil {
		return ServiceSelector{}, err
	}
	s.Host = host
	if port != 0 {
		s.Port, s.ExplicitPort = port, true
	}
	if s.Port == 0 {
		return ServiceSelector{}, errors.New("TCP URL requires a port")
	}

	path := parsed.EscapedPath()
	s.Resource = (path != "" && path != "/") || parsed.ForceQuery || parsed.RawQuery != ""
	if s.Protocol == "http" {
		s.EscapedPath, s.RawQuery, s.ForceQuery = path, parsed.RawQuery, parsed.ForceQuery
	}
	return s, nil
}

func parseSelectorAuthority(value string, allowBareIPv6 bool) (string, int, error) {
	var host, rawPort string
	var hasPort bool
	switch {
	case strings.HasPrefix(value, "["):
		literal, rest, ok := strings.Cut(value[1:], "]")
		if !ok || !strings.Contains(literal, ":") {
			return "", 0, errors.New("invalid IPv6 address")
		}
		host = literal
		if rest != "" {
			rawPort, hasPort = strings.CutPrefix(rest, ":")
			if !hasPort {
				return "", 0, errors.New("invalid address after IPv6 literal")
			}
		}
	case allowBareIPv6 && strings.Count(value, ":") > 1:
		host = value
	case strings.Contains(value, ":"):
		var err error
		host, rawPort, err = net.SplitHostPort(value)
		if err != nil {
			return "", 0, errors.New("invalid service address; bracket an IPv6 address before adding a port")
		}
		hasPort = true
	default:
		host = value
	}

	var port int
	if hasPort {
		n, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || !tcpport.ValidNetwork(int(n)) {
			return "", 0, errors.New("invalid service port; expected 1–65535")
		}
		port = int(n)
	}
	host, err := canonicalSelectorHost(host)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func canonicalSelectorHost(value string) (string, error) {
	if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" {
		return ip.String(), nil
	}
	host, err := CanonicalizeHostname(value)
	if err != nil {
		return "", errors.New("invalid service hostname or IP address")
	}
	return host, nil
}
