package relay

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/relayapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRelayResponseErrorHandlesTypedNil(t *testing.T) {
	t.Parallel()
	var response *relayv1.RegisterRelayResponse
	err := relayResponseError("register relay", response)
	var problem *ControlProblemError
	if !errors.As(err, &problem) || problem.Operation != "register relay" || problem.Status != 0 || problem.Problem != nil {
		t.Fatalf("error = %#v", err)
	}
}

func TestDirectClaimProblemsPreserveProtocolCodesAndClearStaleLease(t *testing.T) {
	credential, _, err := credentials.NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		failure error
		code    tunnelv1.ErrorCode
	}{
		{controlstate.ErrPublisherConnectionCredential, tunnelv1.Unauthenticated},
		{controlstate.ErrPublisherConnectionAlreadyClaimed, tunnelv1.DuplicatePublisherConnection},
		{controlstate.ErrConnectionAssignmentStale, tunnelv1.StaleConnectionAssignment},
		{controlstate.ErrRelayLeaseStale, tunnelv1.StaleConnectionAssignment},
		{controlstate.ErrRelayDraining, tunnelv1.DrainingPublisherConnection},
		{controlstate.ErrRelayConnectionCapacity, tunnelv1.CapacityExceeded},
	} {
		client, err := relayapi.NewDirectClient(directClaimStore{failure: test.failure}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.ClaimPublisherConnectionWithResponse(t.Context(), "connection-1", relayv1.PublisherConnectionClaim{
			RouteSessionId: "session-1", RouteId: "route-1", PublisherConnectionId: "connection-1",
			RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", ClaimId: "claim-1",
			RouteVersion: 1, ConnectionSlot: 0, ConnectionAssignmentRevision: 1, RelayLeaseRevision: 1,
			PublisherConnectionCredential: credential.String(),
		})
		if err != nil {
			t.Fatalf("store error escaped direct adapter: %v", err)
		}
		cleared := false
		controller := &Controller{lease: relayv1.RelayLease{RelayLeaseRevision: 1}, leaseChanged: func(previous, current relayv1.RelayLease) {
			cleared = previous.RelayLeaseRevision == 1 && current.RelayLeaseRevision == 0
		}}
		if code := ControlErrorCode(controller.responseError("claim", response)); code != test.code {
			t.Fatalf("%v: code = %s, want %s", test.failure, code, test.code)
		}
		if want := errors.Is(test.failure, controlstate.ErrRelayLeaseStale); cleared != want || (controller.lease.RelayLeaseRevision == 0) != want {
			t.Fatalf("%v: cleared=%v, lease=%#v", test.failure, cleared, controller.lease)
		}
	}
}

type directClaimStore struct {
	relayapi.Store
	failure error
}

func (s directClaimStore) ClaimPublisherConnection(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error) {
	return controlstate.ClaimedPublisherConnection{}, s.failure
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

func TestControllerDoesNotRegisterAgainAfterAcknowledgingDrain(t *testing.T) {
	now := time.Now().UTC()
	deadline := now.Add(time.Minute)
	lease := relayv1.RelayLease{
		RelayServiceId: "relay-a", RelayId: "relay-a-1", RelayRunId: "relay-run-1", RelayLeaseRevision: 3,
		ProtocolVersion: 1, RelayAddress: "relay-a.example.test:443", TlsServerName: "relay-a.example.test",
		InternalRelayAddress: "relay-a.internal:9445", InternalNetworks: []string{},
		ConnectionCapacity: 10, StreamCapacity: 100, RegisteredAt: now, RenewedAt: now,
		LeaseExpiresAt: now.Add(time.Minute),
	}
	client := &relayDrainControlStub{lease: lease, secondRenewal: make(chan struct{})}
	controller, err := NewController(ControllerConfig{
		Client: client,
		Registration: relayv1.RelayRegistration{
			RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId, RelayRunId: lease.RelayRunId,
			ProtocolVersion: 1, RelayAddress: lease.RelayAddress, TlsServerName: lease.TlsServerName,
			InternalRelayAddress: lease.InternalRelayAddress, InternalNetworks: []string{},
			ConnectionCapacity: 10, StreamCapacity: 100,
		},
		RenewalInterval: 5 * time.Millisecond, RetryInterval: 5 * time.Millisecond,
		Report: func(error) {},
		Now: func() time.Time {
			if client.renewals.Load() >= 2 {
				return deadline
			}
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.draining = lease
	client.draining.Draining = true
	client.draining.DrainDeadline = &deadline
	client.draining.LeaseExpiresAt = deadline
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	select {
	case <-client.secondRenewal:
	case <-time.After(time.Second):
		t.Fatal("controller did not observe the draining lease")
	}
	time.Sleep(25 * time.Millisecond)
	if calls := client.registrations.Load(); calls != 1 {
		t.Fatalf("relay registrations = %d, want 1", calls)
	}
	if controller.Ready(deadline) || !controller.Lease().Draining {
		t.Fatalf("controller lease = %#v", controller.Lease())
	}
	select {
	case err := <-done:
		t.Fatalf("drained controller stopped before cancellation: %v", err)
	default:
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

type relayDrainControlStub struct {
	ControlClient
	lease         relayv1.RelayLease
	draining      relayv1.RelayLease
	registrations atomic.Int32
	renewals      atomic.Int32
	secondRenewal chan struct{}
}

func (s *relayDrainControlStub) RegisterRelayWithResponse(
	context.Context,
	relayv1.RegisterRelayJSONRequestBody,
	...relayv1.RequestEditorFn,
) (*relayv1.RegisterRelayResponse, error) {
	s.registrations.Add(1)
	return &relayv1.RegisterRelayResponse{JSON200: &s.lease}, nil
}

func (s *relayDrainControlStub) RenewRelayWithResponse(
	context.Context,
	relayv1.RelayID,
	relayv1.RenewRelayJSONRequestBody,
	...relayv1.RequestEditorFn,
) (*relayv1.RenewRelayResponse, error) {
	calls := s.renewals.Add(1)
	if calls == 1 {
		return &relayv1.RenewRelayResponse{JSON200: &s.draining}, nil
	}
	if calls == 2 {
		close(s.secondRenewal)
	}
	return &relayv1.RenewRelayResponse{
		HTTPResponse: &http.Response{StatusCode: http.StatusConflict},
		ApplicationproblemJSONDefault: &relayv1.Problem{
			Type: "https://tnl.dev/problems/relay_lease_stale",
		},
	}, nil
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
