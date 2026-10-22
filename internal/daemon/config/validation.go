package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func validatePostgresURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" ||
		parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return errors.New("pooled PostgreSQL database URL is required")
	}
	if strings.TrimSpace(value) != value || parsed.Fragment != "" {
		return errors.New("pooled PostgreSQL database URL is invalid")
	}
	return nil
}

func validateControlHostname(value string) error {
	if err := validateCanonicalHostname(value, "control hostname"); err != nil {
		return err
	}
	if strings.ContainsAny(value, ":/") {
		return errors.New("control hostname must not contain a scheme, path, or port")
	}
	return nil
}

func validateCanonicalHostname(value, name string) error {
	canonical, err := naming.CanonicalizeHostname(value)
	if err != nil || canonical != value {
		return fmt.Errorf("%s must be canonical", name)
	}
	return nil
}

func validateHTTPSOrigin(value, name string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Hostname() != strings.ToLower(parsed.Hostname()) || parsed.Port() == "443" {
		return fmt.Errorf("%s must be a canonical HTTPS origin", name)
	}
	return nil
}

func validateListenAddress(value string) error {
	if value == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || strings.TrimSpace(host) != host {
		return errors.New("must be a canonical host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || !tcpport.ValidNetwork(number) || strconv.Itoa(number) != port {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func validateDialAddress(value string) error {
	host, _, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.TrimSpace(host) != host {
		return errors.New("must be a canonical host and port")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.String() != host {
			return errors.New("must use a canonical IP address")
		}
	} else if canonical, err := naming.CanonicalizeHostname(host); err != nil || canonical != host {
		return errors.New("must use a canonical hostname")
	}
	return validateListenAddress(value)
}

func validateRelayAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("relay address must be a canonical hostname and port")
	}
	canonical, err := naming.CanonicalizeHostname(host)
	if err != nil || canonical != host {
		return errors.New("relay address must use a canonical hostname")
	}
	number, err := strconv.Atoi(port)
	if err != nil || !tcpport.ValidNetwork(number) || strconv.Itoa(number) != port {
		return errors.New("relay address port must be between 1 and 65535")
	}
	return nil
}

func validProcessID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func validDNSLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || (value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
