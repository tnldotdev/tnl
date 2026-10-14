package main

import (
	"errors"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/localpublisher"
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
	return localpublisher.NormalizeTarget(target, protocol)
}

func savedPublicAddress(route controlv1.PublicURL) (string, error) {
	return localpublisher.SavedPublicAddress(route)
}

func validateTCPPublishOptions(flags publishCommand, protocol controlv1.PublicURLServiceProtocol) error {
	if protocol == controlv1.Http {
		if flags.TargetTLSName != "" || flags.TargetTLS {
			return failure.Wrap("validate publish options", failure.InvalidTunnelFlags,
				errors.New("private target TLS options require a private TCP protocol"))
		}
		return nil
	}
	if flags.Open {
		return failure.Wrap("validate private TCP publish options", failure.InvalidTunnelFlags,
			errors.New("private TCP publications do not support --open"))
	}
	if flags.InspectionMode == config.InspectionDetailed &&
		protocol != controlv1.Mysql && protocol != controlv1.Postgres {
		return failure.Wrap("validate private TCP publish options", failure.InvalidTunnelFlags,
			errors.New("detailed inspection requires PostgreSQL or MySQL"))
	}
	if !flags.TargetTLS && (flags.TargetTLSName != "" || flags.TargetCAFile != "") {
		return failure.Wrap("validate private TCP publish options", failure.InvalidTunnelFlags,
			errors.New("--target-tls-name and --target-ca-file require --target-tls"))
	}
	return nil
}
