package naming

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrInvalidControlURL = errors.New("naming: control URL must be an HTTPS origin")
var ErrInvalidControlPort = errors.New("naming: control URL port must be between 1 and 65535")

// CanonicalControlURL validates and normalizes a control API HTTPS origin.
func CanonicalControlURL(value string) (string, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil ||
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
		if err != nil || number < 1 || number > 65535 {
			return "", ErrInvalidControlPort
		}
	}
	if port == "" || port == "443" {
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
