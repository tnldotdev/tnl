package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
)

var composeProject = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
var composeService = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var dockerIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var tlsHostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// ValidDockerIdentifier accepts one exact container name or ID, never a filter,
// path, option, or shell expression. runtime discovery must still verify labels.
func ValidDockerIdentifier(value string) bool { return dockerIdentifier.MatchString(value) }

// MatchesDockerIdentifier rejects Docker's implicit ID-prefix lookup. discovery
// must additionally check the container's worktree label before dialing it.
func MatchesDockerIdentifier(identifier, id, name string) bool {
	if !ValidDockerIdentifier(identifier) {
		return false
	}
	return identifier == strings.TrimPrefix(name, "/") || identifier == id
}

// ValidProtocol accepts project service labels. a private label selects client
// guidance, not a public URL or a different tunnel transport.
func ValidProtocol(protocol string) bool {
	switch protocol {
	case "http", "tcp", "mysql", "postgres", "kubernetes":
		return true
	}
	return false
}

// PrivateProtocol identifies non-HTTP labels. HTTP services can also be private;
// use IsPublicService to decide whether a declaration enables public HTTPS.
func PrivateProtocol(protocol string) bool {
	return protocol == "tcp" || protocol == "mysql" || protocol == "postgres" || protocol == "kubernetes"
}

// ResolveServiceTarget turns a configured address or a discovered private
// listener into native publication settings. compose/docker discovery supplies
// host:port; an app supplies its reported HTTP origin. no public address is used.
func ResolveServiceTarget(service Service, discovered string) (*Publish, error) {
	if err := validateTarget(service); err != nil {
		return nil, err
	}
	result := ServicePublish(service)
	value := discovered
	if TargetType(service) == "address" {
		value = string(*service.Target.Address)
	}
	if value == "" {
		return nil, errors.New("private target has not been discovered")
	}
	var normalized string
	var err error
	if Protocol(service) == "http" || Protocol(service) == "kubernetes" {
		if TargetType(service) == "compose" || TargetType(service) == "docker" {
			value, err = tcptarget.Normalize(value)
			if err != nil {
				return nil, err
			}
			scheme := "http://"
			if service.Target.TLS != nil {
				scheme = "https://"
			}
			value = scheme + value
		}
		normalized, err = NormalizeHTTPServiceTarget(service, value)
	} else {
		normalized, err = tcptarget.Normalize(value)
	}
	if err != nil {
		return nil, err
	}
	if protocol := Protocol(service); protocol == "http" && service.Target != nil && service.Target.TLS != nil && !strings.HasPrefix(normalized, "https://") {
		return nil, errors.New("target.tls requires an HTTPS listener")
	}
	if Protocol(service) == "http" && !IsPublicService(service) && strings.HasPrefix(normalized, "https://") && (service.Target == nil || service.Target.TLS == nil) {
		return nil, errors.New("private HTTPS listeners require target.tls")
	}
	target := Target(normalized)
	result.Target = &target
	return result, nil
}

// NormalizeHTTPServiceTarget retains listener origins for local app ownership.
// a private host:port is an opaque dial target, represented locally as an HTTP
// origin without selecting who, if anyone, negotiates TLS on its bytes.
func NormalizeHTTPServiceTarget(service Service, value string) (string, error) {
	normalized, err := targetsyntax.NormalizeTarget(value)
	if err == nil || IsPublicService(service) || strings.Contains(value, "://") {
		return normalized, err
	}
	address, addressErr := tcptarget.Normalize(value)
	if addressErr != nil {
		return "", err
	}
	return "http://" + address, nil
}

func validateTarget(service Service) error {
	protocol := Protocol(service)
	if !ValidProtocol(protocol) {
		return errors.New("protocol must be http, tcp, mysql, postgres, or kubernetes; use tcp for an existing sshd")
	}
	target := service.Target
	if target != nil {
		cloud := target.Region != nil || target.Cluster != nil || target.Instance != nil || target.Endpoint != nil
		if target.Type != "eks" && target.Type != "rds" && cloud {
			return errors.New("region, cluster, instance, and endpoint require an eks or rds target")
		}
		if target.Type == "eks" || target.Type == "rds" {
			return ValidateCloudTarget(protocol, *target)
		}
	}
	if target == nil || target.Type == "app" {
		if protocol != "http" {
			return errors.New("target.type app requires protocol http")
		}
		if target != nil && (target.Address != nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil) {
			return errors.New("target.type app accepts only optional tls")
		}
		if target == nil {
			return nil
		}
	}
	if protocol == "kubernetes" && (target.Type != "address" || target.TLS == nil) {
		return errors.New("kubernetes requires an HTTPS address with target.tls, or an eks target")
	}
	switch target.Type {
	case "app":
	case "address":
		if target.Address == nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil {
			return errors.New("target.type address requires only address and optional tls")
		}
		value := string(*target.Address)
		if protocol == "http" || protocol == "kubernetes" {
			normalized, err := NormalizeHTTPServiceTarget(service, value)
			if err != nil {
				return fmt.Errorf("target.address: %w", err)
			}
			if protocol == "kubernetes" && !strings.HasPrefix(normalized, "https://") {
				return errors.New("kubernetes requires an HTTPS target address")
			}
			if target.TLS != nil && !strings.HasPrefix(normalized, "https://") {
				return errors.New("target.tls requires an HTTPS address")
			}
			if !IsPublicService(service) && target.TLS == nil && strings.HasPrefix(normalized, "https://") {
				return errors.New("private HTTPS addresses require target.tls")
			}
		} else if _, err := tcptarget.Normalize(value); err != nil {
			return fmt.Errorf("target.address: %w", err)
		}
	case "compose":
		if target.Address != nil || target.Container != nil || target.Project != nil && !composeProject.MatchString(*target.Project) || target.Service == nil || !composeService.MatchString(*target.Service) || target.Port == nil {
			return errors.New("target.type compose requires service, port, and optional project, file, tls")
		}
		if target.File != nil {
			if err := validateProjectRelativeFile(*target.File); err != nil {
				return fmt.Errorf("target.file: %w", err)
			}
		}
	case "docker":
		if target.Address != nil || target.Project != nil || target.File != nil || target.Service != nil || target.Container == nil || !ValidDockerIdentifier(*target.Container) || target.Port == nil {
			return errors.New("target.type docker requires an exact container identifier, port, and optional tls")
		}
	default:
		return errors.New("target.type must be app, address, compose, docker, eks, or rds")
	}
	if target.Port != nil && (*target.Port < 1 || *target.Port > 65535) {
		return errors.New("target.port must be between 1 and 65535")
	}
	if tls := target.TLS; tls != nil {
		if tls.ServerName != nil {
			value := *tls.ServerName
			if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/\\@ \t\r\n\x00") {
				return errors.New("target.tls.server_name must be a hostname or IP address")
			}
			if net.ParseIP(value) == nil && !validTLSHostname(value) {
				return errors.New("target.tls.server_name must be a hostname or IP address")
			}
			if addr, err := netip.ParseAddr(value); err == nil && addr.Zone() != "" {
				return errors.New("target.tls.server_name cannot have an IP zone")
			}
		}
		if tls.CAFile != nil && (*tls.CAFile == "" || strings.TrimSpace(*tls.CAFile) != *tls.CAFile || strings.ContainsRune(*tls.CAFile, 0)) {
			return errors.New("target.tls.ca_file must be a nonempty path without surrounding whitespace or NUL")
		}
		if tls.CAFile != nil && validateProjectRelativeFile(*tls.CAFile) != nil {
			return errors.New("target.tls.ca_file must be a project-relative CA-only PEM file")
		}
	}
	return nil
}

func validTLSHostname(value string) bool {
	if len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !tlsHostnameLabel.MatchString(label) {
			return false
		}
	}
	if strings.Contains(strings.ToLower(value), "xn--") {
		if _, err := naming.CanonicalizeHostname(strings.ToLower(value)); err != nil {
			return false
		}
	}
	return true
}

// ValidTLSIdentity accepts a certificate DNS hostname or an unzoned IP address.
func ValidTLSIdentity(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	return validTLSHostname(value)
}

// CAURLError preserves URL parser failures without putting source URLs or
// query credentials in the diagnostic text.
type CAURLError struct{ cause error }

func (e *CAURLError) Error() string {
	return "ca must be system, a project-relative PEM file, or an HTTPS CA-bundle URL"
}
func (e *CAURLError) Unwrap() error    { return e.cause }
func (e *CAURLError) GoString() string { return e.Error() }

func validateCAURL(value string) error {
	location, err := url.Parse(value)
	if err != nil {
		return &CAURLError{cause: err}
	}
	if location.Scheme != "https" || !ValidTLSIdentity(location.Hostname()) || location.User != nil ||
		location.Fragment != "" || location.Opaque != "" || location.Host == "" || strings.ContainsAny(value, "\\ \t\r\n\x00") {
		return &CAURLError{cause: errors.New("CA URL needs an HTTPS hostname without credentials, fragments, or whitespace")}
	}
	if port := location.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			if err == nil {
				err = errors.New("CA URL port must be between 1 and 65535")
			}
			return &CAURLError{cause: err}
		}
	} else if strings.HasSuffix(location.Host, ":") {
		return &CAURLError{cause: errors.New("CA URL port must not be empty")}
	}
	return nil
}

func ValidateTrustSource(value TrustSource) error {
	if value.Hostname != nil {
		name := *value.Hostname
		if !ValidTLSIdentity(name) {
			return errors.New("hostname must be a hostname or IP address")
		}
		if address, err := netip.ParseAddr(name); err == nil && address.Zone() != "" {
			return errors.New("hostname cannot have an IP zone")
		}
	}
	if value.CA == "system" {
		return nil
	}
	if strings.HasPrefix(value.CA, "https://") {
		return validateCAURL(value.CA)
	}
	if strings.Contains(value.CA, "://") || validateProjectRelativeFile(value.CA) != nil {
		return errors.New("ca must be system, a project-relative PEM file, or an HTTPS CA-bundle URL")
	}
	return nil
}

func validateProjectRelativeFile(value string) error {
	if err := validateRelativeFilePath(value); err != nil {
		return err
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\\r\n\t") {
		return errors.New("must be a project-relative file path")
	}
	return nil
}
