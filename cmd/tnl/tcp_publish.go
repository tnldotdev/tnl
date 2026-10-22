package main

import (
	"errors"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publishProtocol(value string) (controlv1.PublicURLServiceProtocol, error) {
	if value == "" {
		return controlv1.Http, nil
	}
	protocol := controlv1.PublicURLServiceProtocol(value)
	if value != "http" && value != "tcp" && value != "mysql" && value != "postgres" {
		return "", failure.Wrap("select service protocol", failure.InvalidTunnelFlags,
			errors.New("protocol must be http, tcp, mysql, or postgres; publish an existing sshd as tcp"))
	}
	return protocol, nil
}

func privatePublishProtocol(value string) (controlv1.PrivateServiceProtocol, error) {
	if value == "" {
		value = "http"
	}
	protocol := controlv1.PrivateServiceProtocol(value)
	if !protocol.Valid() {
		return "", publisherCLIError("private protocol must be http, tcp, mysql, or postgres")
	}
	return protocol, nil
}

func normalizePrivatePublishTarget(target string, protocol controlv1.PrivateServiceProtocol) (string, error) {
	if protocol == "http" {
		return config.NormalizeHTTPServiceTarget(config.Service{}, target)
	}
	canonical, err := tcptarget.Normalize(target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func normalizePublishTarget(target string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return targetsyntax.NormalizeTarget(target)
	}
	canonical, err := tcptarget.Normalize(target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	if route.ServiceProtocol != controlv1.Http {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid,
			errors.New("control returned a public URL with an unknown service protocol"))
	}
	return "https://" + route.CanonicalHostname, nil
}

func validateTCPPublishOptions[P ~string](flags publishCommand, protocol P) error {
	if flags.privateService && (flags.Anonymous || len(flags.IP) != 0 || flags.PublicURL != "" || flags.Ephemeral || flags.Open) {
		return publisherCLIError("this configured service is private; add an explicit publicURL block to enable public HTTPS")
	}
	if flags.TargetTLS != nil && !*flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "" || strings.HasPrefix(flags.Target, "https://")) {
		return publisherCLIError("target TLS cannot be disabled while target trust is configured")
	}
	if protocol == "http" {
		if flags.TargetTLSName != "" || flags.TargetCAFile != "" || flags.TargetTLS != nil && *flags.TargetTLS {
			target, err := targetsyntax.NormalizeTarget(flags.Target)
			if err != nil || !strings.HasPrefix(target, "https://") {
				return failure.Wrap("validate HTTPS target", failure.InvalidTunnelFlags, errors.New("--target-tls-name requires an HTTPS target"))
			}
		}
		return nil
	}
	if flags.Open {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("TCP publications do not support --open"))
	}
	if flags.Ephemeral {
		return failure.Wrap("validate TCP publication", failure.InvalidTunnelFlags, errors.New("private services are saved; --ephemeral requires HTTP"))
	}
	if flags.Anonymous || len(flags.IP) != 0 || flags.PublicURL != "" {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("public URL and visitor access flags require HTTP"))
	}
	if flags.Requests != nil && *flags.Requests != 0 || flags.RateRequests != nil && *flags.RateRequests != 0 || flags.RatePer != "" || flags.RateBurst != nil && *flags.RateBurst != 0 {
		return failure.Wrap("validate private publication limits", failure.InvalidTunnelFlags, errors.New("request totals and rates require HTTP; private services support --concurrency"))
	}
	if flags.Concurrency != nil && (*flags.Concurrency < 1 || *flags.Concurrency > 4096) {
		return failure.Wrap("validate private stream capacity", failure.InvalidTunnelFlags, errors.New("private service concurrency must be between 1 and 4096"))
	}
	return nil
}

func selectPublishInspection(_ *publishCommand, _ controlv1.PublicURLServiceProtocol) error {
	return nil
}
