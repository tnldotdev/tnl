package main

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/tcpport"
	"github.com/tnldotdev/tnl/internal/tcptarget"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publishProtocol(value string) (controlv1.PublicURLServiceProtocol, error) {
	if value == "" {
		return controlv1.Http, nil
	}
	protocol := controlv1.PublicURLServiceProtocol(value)
	if !protocol.Valid() {
		return "", failure.Wrap("select service protocol", failure.InvalidTunnelFlags,
			errors.New("unsupported service protocol"))
	}
	return protocol, nil
}

func normalizePublishTarget(target string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return localproxy.NormalizeTarget(target)
	}
	canonical, err := tcptarget.Normalize(target)
	if err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return canonical, nil
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	if !route.ServiceProtocol.Valid() {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid,
			errors.New("control returned a public URL with an unknown service protocol"))
	}
	if route.ServiceProtocol != controlv1.Http {
		if route.PublicPort == nil || !tcpport.Valid(*route.PublicPort) {
			return "", failure.Wrap("read TCP public URL", failure.ServerResponseInvalid,
				errors.New("control returned a TCP public URL without a public port"))
		}
		return net.JoinHostPort(route.CanonicalHostname, strconv.Itoa(*route.PublicPort)), nil
	}
	if route.PublicPort != nil {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid,
			errors.New("control returned an HTTP public URL with a public TCP port"))
	}
	return "https://" + route.CanonicalHostname, nil
}

func validateTCPPublishOptions(flags publishCommand, protocol controlv1.PublicURLServiceProtocol) error {
	if protocol == controlv1.Http {
		if flags.TargetTLS {
			return failure.Wrap("validate publish options", failure.InvalidTunnelFlags,
				errors.New("target TLS options require a TCP service protocol"))
		}
		if flags.TargetTLSName != "" {
			target, err := localproxy.NormalizeTarget(flags.Target)
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
		return failure.Wrap("validate TCP publication", failure.InvalidTunnelFlags, errors.New("TCP publication requires a saved public URL"))
	}
	if !flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return failure.Wrap("validate TCP publish options", failure.InvalidTunnelFlags,
			errors.New("--target-tls-name and --target-ca-file require --target-tls"))
	}
	return nil
}

func selectPublishInspection(flags *publishCommand, protocol controlv1.PublicURLServiceProtocol) error {
	if protocol != controlv1.Ssh {
		return nil
	}
	if flags.InspectionMode == config.InspectionSummary && !flags.inspectionModeFromCLI && !flags.inspectionModeFromConfig {
		flags.InspectionMode = config.InspectionNone
	}
	if flags.InspectionMode != config.InspectionNone {
		return failure.Wrap("validate SSH inspection", failure.InvalidTunnelFlags,
			errors.New("SSH supports --inspection-mode=none only"))
	}
	return nil
}
