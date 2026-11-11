package naming

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

var ErrInvalidControlURL = errors.New("naming: control URL must be an HTTPS origin or loopback HTTP origin")
var ErrInvalidControlPort = errors.New("naming: control URL port must be between 1 and 65535")

// CanonicalControlURL validates a control origin; HTTP is limited to loopback.
func CanonicalControlURL(value string) (string, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" && !IsLoopbackHTTP(value) || origin.Host == "" || origin.User != nil ||
		origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" {
		return "", ErrInvalidControlURL
	}
	hostname := strings.ToLower(origin.Hostname())
	if hostname == "" {
		return "", ErrInvalidControlURL
	}
	port := origin.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || !tcpport.ValidNetwork(number) {
			return "", ErrInvalidControlPort
		}
	}
	if port == "" || origin.Scheme == "https" && port == "443" || origin.Scheme == "http" && port == "80" {
		if strings.Contains(hostname, ":") {
			origin.Host = "[" + hostname + "]"
		} else {
			origin.Host = hostname
		}
	} else {
		origin.Host = net.JoinHostPort(hostname, port)
	}
	origin.Path = ""
	return origin.String(), nil
}

// IsLoopbackHTTP never resolves DNS: only localhost and literal loopback IPs qualify.
func IsLoopbackHTTP(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Hostname(), "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.Zone() == "" && ip.IsLoopback()
}
