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
	"github.com/tnldotdev/tnl/internal/mongosrv"
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
	if protocol == controlv1.Mongodb && strings.HasPrefix(target, mongosrv.Prefix) {
		seed, err := mongosrv.Parse(target)
		if err != nil {
			return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
		}
		return mongosrv.Prefix + seed, nil
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
			return "", failure.Wrap("read private TCP public URL", failure.ServerResponseInvalid,
				errors.New("control returned a private TCP public URL without a public port"))
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
		if flags.TargetTLSName != "" || flags.TargetTLS {
			return failure.Wrap("validate publish options", failure.InvalidTunnelFlags,
				errors.New("private target TLS options require a private TCP protocol"))
		}
		return nil
	}
	if flags.Open || flags.RequestInspection == config.RequestInspectionDetailed {
		return failure.Wrap("validate private TCP publish options", failure.InvalidTunnelFlags,
			errors.New("private TCP publications do not support --open or HTTP request capture"))
	}
	if !flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return failure.Wrap("validate private TCP publish options", failure.InvalidTunnelFlags,
			errors.New("--target-tls-name and --target-ca-file require --target-tls"))
	}
	if protocol == controlv1.Mongodb && strings.HasPrefix(flags.Target, mongosrv.Prefix) &&
		(!flags.TargetTLS || flags.TargetTLSName != "") {
		return failure.Wrap("validate mongodb SRV target", failure.InvalidTunnelFlags,
			errors.New("mongodb SRV targets require --target-tls and do not accept --target-tls-name; each discovered host must verify its own certificate"))
	}
	return nil
}
