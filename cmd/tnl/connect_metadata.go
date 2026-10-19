package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func validateProfileService(service controlv1.PrivateService) error {
	if !opaqueid.Valid(service.Id, opaqueid.PrivateServicePrefix) || !config.ProtocolName(service.Protocol).Valid() || service.ManagedTls == nil || !service.Enabled {
		return publisherCLIError("service has no managed TLS endpoint; refresh its applied configuration")
	}
	endpoint := service.ManagedTls
	hostname, err := naming.CanonicalizeHostname(endpoint.Hostname)
	if err != nil || hostname != endpoint.Hostname || endpoint.Port < 1024 || endpoint.Port > 65535 {
		return publisherCLIError("service returned an invalid managed TLS endpoint")
	}
	return nil
}

func ensureConnectCertificate(ctx context.Context, session *teamSession, service string) (clientstate.ServiceClientMaterial, error) {
	identity := session.identity.Identity.Id
	device, err := session.store.EnsureEnrolledVisitorDevice(ctx, identity, session.authenticated.Control.EnrollVisitorDevice)
	if err != nil {
		return clientstate.ServiceClientMaterial{}, err
	}
	return session.store.EnsureServiceClientCertificate(ctx, identity, service, device.ID, func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		return session.authenticated.Control.IssueServiceClientCertificate(ctx, service, device.ID, csr)
	})
}
