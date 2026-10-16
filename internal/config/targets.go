package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/tcptarget"
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

// ValidProtocol includes managed SSH for saved public URL metadata and native
// policy selection. project targets have a narrower boundary in validateTarget.
func ValidProtocol(protocol string) bool {
	switch protocol {
	case "http", "postgres", "mysql", "redis", "ssh":
		return true
	}
	return false
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
	if Protocol(service) == "http" {
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
		normalized, err = localproxy.NormalizeTarget(value)
	} else {
		normalized, err = tcptarget.Normalize(value)
	}
	if err != nil {
		return nil, err
	}
	target := Target(normalized)
	result.Target = &target
	return result, nil
}

func validateTarget(service Service) error {
	protocol := Protocol(service)
	if protocol == "ssh" {
		return errors.New("SSH cannot use a project service target; run tnl ssh enable --name HOST --user ACCOUNT to install managed SSH")
	}
	if !ValidProtocol(protocol) {
		return errors.New("protocol must be http, postgres, mysql, or redis")
	}
	target := service.Target
	if target == nil || target.Type == "app" {
		if protocol != "http" {
			return errors.New("target.type app requires protocol http")
		}
		if target != nil && (target.Address != nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil || target.TLS != nil) {
			return errors.New("target.type app accepts no address, discovery, or TLS fields")
		}
		return nil
	}
	switch target.Type {
	case "address":
		if target.Address == nil || target.Project != nil || target.File != nil || target.Service != nil || target.Port != nil || target.Container != nil {
			return errors.New("target.type address requires only address and optional tls")
		}
		value := string(*target.Address)
		if protocol == "http" {
			normalized, err := localproxy.NormalizeTarget(value)
			if err != nil {
				return fmt.Errorf("target.address: %w", err)
			}
			if target.TLS != nil && !strings.HasPrefix(normalized, "https://") {
				return errors.New("target.tls requires an HTTPS address")
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
		return errors.New("target.type must be app, address, compose, or docker")
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
	return true
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
