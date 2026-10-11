package main

import (
	"errors"
	"net"
	"strconv"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/databasetarget"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/tcpport"
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
	if _, err := databasetarget.Host(target); err != nil {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, err)
	}
	return target, nil
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	if !route.ServiceProtocol.Valid() {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid,
			errors.New("control returned a public URL with an unknown service protocol"))
	}
	if route.ServiceProtocol != controlv1.Http {
		if route.PublicPort == nil || !tcpport.Valid(*route.PublicPort) {
			return "", failure.Wrap("read database public URL", failure.ServerResponseInvalid,
				errors.New("control returned a database public URL without a public port"))
		}
		return net.JoinHostPort(route.CanonicalHostname, strconv.Itoa(*route.PublicPort)), nil
	}
	if route.PublicPort != nil {
		return "", failure.Wrap("read public URL protocol", failure.ServerResponseInvalid,
			errors.New("control returned an HTTP public URL with a public TCP port"))
	}
	return "https://" + route.CanonicalHostname, nil
}

func validateDatabasePublishOptions(flags publishCommand, protocol controlv1.PublicURLServiceProtocol) error {
	if protocol == controlv1.Http {
		if flags.TargetTLSName != "" || flags.DatabasePassthrough {
			return failure.Wrap("validate publish options", failure.InvalidTunnelFlags,
				errors.New("database TLS options require a database protocol"))
		}
		return nil
	}
	if flags.Open || flags.RequestInspection == config.RequestInspectionDetailed {
		return failure.Wrap("validate database publish options", failure.InvalidTunnelFlags,
			errors.New("database publications do not support --open or HTTP request capture"))
	}
	if flags.DatabasePassthrough && (flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return failure.Wrap("validate database publish options", failure.InvalidTunnelFlags,
			errors.New("the database client verifies the target certificate in TLS passthrough mode; omit target TLS options"))
	}
	return nil
}
