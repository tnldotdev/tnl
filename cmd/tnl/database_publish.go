package main

import (
	"errors"
	"net"
	"strconv"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publishProtocol(value string) (controlv1.PublicURLServiceProtocol, error) {
	if value == "" {
		return controlv1.Http, nil
	}
	protocol := controlv1.PublicURLServiceProtocol(value)
	if !protocol.Valid() {
		return "", failure.Wrap("select service protocol", failure.InvalidTunnelFlags,
			errors.New("protocol must be http, postgres, or mysql"))
	}
	return protocol, nil
}

func normalizePublishTarget(target string, protocol controlv1.PublicURLServiceProtocol) (string, error) {
	if protocol == controlv1.Http {
		return localproxy.NormalizeTarget(target)
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("database target must be a host and port"))
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", diagnostic.Wrap(diagnostic.TargetInvalid, errors.New("database target port is invalid"))
	}
	return target, nil
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	if route.ServiceProtocol == controlv1.Postgres || route.ServiceProtocol == controlv1.Mysql {
		if route.PublicPort == nil || *route.PublicPort < 1024 || *route.PublicPort > 65535 {
			return "", failure.Wrap("read database public URL", failure.ServerResponseInvalid,
				errors.New("control returned a database public URL without a public port"))
		}
		return net.JoinHostPort(route.CanonicalHostname, strconv.Itoa(*route.PublicPort)), nil
	}
	return "https://" + route.CanonicalHostname, nil
}

func validateDatabasePublishOptions(flags publishCommand, protocol controlv1.PublicURLServiceProtocol) error {
	if protocol == controlv1.Http {
		if flags.TargetTLSName != "" || flags.DatabasePassthrough {
			return failure.Wrap("validate publish options", failure.InvalidTunnelFlags,
				errors.New("database TLS options require --protocol postgres or --protocol mysql"))
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
