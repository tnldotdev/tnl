package invocation

import (
	"errors"
	"io"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func privatePublishProtocol(value string) (controlv1.ServiceProtocol, error) {
	if value == "" {
		value = "http"
	}
	protocol := controlv1.ServiceProtocol(value)
	if !protocol.Valid() {
		return "", publisherCLIError("private protocol must be http, tcp, mysql, or postgres")
	}
	return protocol, nil
}

func EnrollmentKeyInput(value string, input io.Reader) (string, error) {
	if value == "-" {
		b, err := io.ReadAll(io.LimitReader(input, 257))
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(b))
	}
	if len(value) == 0 || len(value) > 256 || strings.ContainsAny(value, " \t\r\n") {
		return "", failure.Wrap("read enrollment key", failure.PublisherEnrollmentInput, errors.New("invalid enrollment input"))
	}
	return value, nil
}

func randomIdempotencyKey() (string, error) { return opaqueid.New(opaqueid.IdempotencyPrefix) }

func validateProfileService(service controlv1.Service) error {
	if !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || !config.ProtocolName(service.Protocol).Valid() || service.Endpoint == nil || !service.Enabled {
		return publisherCLIError("service has no managed TLS endpoint; refresh its applied configuration")
	}
	endpoint := service.Endpoint
	hostname, err := naming.CanonicalizeHostname(endpoint.Hostname)
	if err != nil || hostname != endpoint.Hostname || endpoint.Port < 1024 || endpoint.Port > 65535 {
		return publisherCLIError("service returned an invalid managed TLS endpoint")
	}
	return nil
}
