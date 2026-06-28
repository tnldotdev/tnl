package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayResponseErrorHandlesTypedNil(t *testing.T) {
	t.Parallel()
	var response *relayv1.RegisterRelayResponse
	err := relayResponseError("register relay", response)
	var problem *ControlProblem
	if !errors.As(err, &problem) || problem.Operation != "register relay" || problem.Status != 0 || problem.Problem != nil {
		t.Fatalf("error = %#v", err)
	}
}

func TestControllerInstallsCertificateBeforeReady(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	lease := relayv1.RelayLease{
		RelayServiceId: "relay-a", RelayId: "relay-a-1", RelayRunId: "relay-run-1", RelayLeaseRevision: 3,
		ProtocolVersion: 1, RelayAddress: "relay-a.example.test:443", TlsServerName: "relay-a.example.test",
		InternalRelayAddress: "relay-a.internal:9445", InternalNetworks: []string{},
		ConnectionCapacity: 10, StreamCapacity: 100, ReportedConnections: 0, ReportedStreams: 0,
		RegisteredAt: now, RenewedAt: now, LeaseExpiresAt: now.Add(time.Minute),
	}
	client := &relayCertificateControlStub{lease: lease, certificate: relayv1.RelayServiceCertificate{
		RelayServiceId: lease.RelayServiceId, TlsServerName: lease.TlsServerName,
		CertificatePem: "certificate", PrivateKeyPem: "private-key", NotAfter: now.Add(48 * time.Hour),
	}}
	installed := make(chan relayv1.RelayServiceCertificate, 1)
	controller, err := NewController(ControllerConfig{
		Client: client,
		Registration: relayv1.RelayRegistration{
			RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId,
			ProtocolVersion: 1, RelayAddress: lease.RelayAddress, TlsServerName: lease.TlsServerName,
			InternalRelayAddress: lease.InternalRelayAddress, InternalNetworks: []string{},
			ConnectionCapacity: 10, StreamCapacity: 100,
		},
		RenewalInterval: time.Hour, RetryInterval: time.Second, Now: func() time.Time { return now },
		CertificateChanged: func(certificate relayv1.RelayServiceCertificate) error {
			installed <- certificate
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	select {
	case certificate := <-installed:
		if certificate.RelayServiceId != lease.RelayServiceId {
			t.Fatalf("installed certificate = %#v", certificate)
		}
	case <-time.After(time.Second):
		t.Fatal("relay certificate was not installed")
	}
	if !controller.Ready(now) {
		t.Fatal("controller is not ready after installing its certificate")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type relayCertificateControlStub struct {
	ControlClient
	lease       relayv1.RelayLease
	certificate relayv1.RelayServiceCertificate
}

func (s *relayCertificateControlStub) RegisterRelayWithResponse(
	context.Context,
	relayv1.RegisterRelayJSONRequestBody,
	...relayv1.RequestEditorFn,
) (*relayv1.RegisterRelayResponse, error) {
	return &relayv1.RegisterRelayResponse{JSON200: &s.lease}, nil
}

func (s *relayCertificateControlStub) GetRelayServiceCertificateWithResponse(
	_ context.Context,
	relayServiceID relayv1.RelayServiceID,
	params *relayv1.GetRelayServiceCertificateParams,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.GetRelayServiceCertificateResponse, error) {
	if relayServiceID != s.lease.RelayServiceId || params == nil || params.RelayId != s.lease.RelayId ||
		params.RelayRunId != s.lease.RelayRunId || params.RelayLeaseRevision != s.lease.RelayLeaseRevision {
		return nil, errors.New("unexpected certificate lease identity")
	}
	return &relayv1.GetRelayServiceCertificateResponse{JSON200: &s.certificate}, nil
}
