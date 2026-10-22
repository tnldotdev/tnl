// package target validates target origins and path prefixes without network I/O.
package target

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcpport"
)

// NormalizeTarget returns a canonical HTTP or HTTPS origin.
func NormalizeTarget(target string) (string, error) {
	if target == "" || strings.ContainsFunc(target, unicode.IsSpace) {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP or HTTPS origin"))
	}
	barePort := true
	for i := 0; i < len(target); i++ {
		if target[i] < '0' || target[i] > '9' {
			barePort = false
			break
		}
	}
	hostname, portText, scheme := "127.0.0.1", target, "http"
	localhostName, localhostPort, localhostTarget := strings.Cut(target, ":")
	if !barePort && localhostTarget && strings.EqualFold(localhostName, "localhost") && !strings.Contains(localhostPort, ":") {
		portText = localhostPort
	} else if !barePort {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.Opaque != "" || parsed.ForceQuery || parsed.RawQuery != "" || strings.Contains(target, "#") ||
			!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target must be a port, localhost:<port>, or an HTTP or HTTPS origin"))
		}
		scheme = strings.ToLower(parsed.Scheme)
		hostname, portText = parsed.Hostname(), parsed.Port()
		if portText == "" && !strings.HasSuffix(parsed.Host, ":") {
			portText = "80"
			if scheme == "https" {
				portText = "443"
			}
		}
		if scheme == "http" && strings.EqualFold(hostname, "localhost") {
			hostname = "127.0.0.1"
		}
	}
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.Zone() != "" {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target host must not have an IP zone"))
		}
		hostname = address.String()
	} else {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != strings.ToLower(hostname) {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target requires a DNS name or IP address"))
		}
		hostname = canonical
	}
	port, err := strconv.Atoi(portText)
	if err != nil || !tcpport.ValidNetwork(port) {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("localproxy: target requires a valid port"))
	}
	return scheme + "://" + net.JoinHostPort(hostname, strconv.Itoa(port)), nil
}

// ParseCanonicalTarget accepts only an already-normalized HTTP or HTTPS origin.
func ParseCanonicalTarget(target string) (*url.URL, error) {
	normalized, err := NormalizeTarget(target)
	if err != nil {
		return nil, err
	}
	if normalized != target {
		return nil, diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("target must be a canonical HTTP or HTTPS origin"))
	}
	return url.Parse(normalized)
}

// ValidMountPrefix accepts unescaped absolute paths of whole, clean segments.
func ValidMountPrefix(prefix string) bool {
	if len(prefix) < 2 || len(prefix) > 256 || prefix[0] != '/' || prefix[len(prefix)-1] == '/' ||
		prefix == "/__tnl" || strings.HasPrefix(prefix, "/__tnl/") {
		return false
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == '~') {
				return false
			}
		}
	}
	return true
}
