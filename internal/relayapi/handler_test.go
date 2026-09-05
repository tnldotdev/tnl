package relayapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestHandlerRequiresVerifiedRelayCertificate(t *testing.T) {
	h := testRelayHandler(t, &relayStoreStub{}, time.Now(), nil)
	tests := []struct {
		name string
		tls  *tls.ConnectionState
	}{
		{name: "no TLS"},
		{name: "unverified certificate", tls: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{DNSNames: []string{"relay-1"}}},
		}},
		{name: "wrong service role", tls: verifiedCertificate("ingress-1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/internal/v1/relays/register", nil)
			request.TLS = test.tls
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusUnauthorized, response.Body.String())
			}
			assertRelayProblemType(t, response, "https://tnl.dev/problems/unauthenticated")
		})
	}
}

func TestRegisterRelayAuthorizesAndConvertsRequest(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	var got controlstate.RelayRegistration
	var gotNow time.Time
	var gotDuration time.Duration
	store := &relayStoreStub{registerRelay: func(
		_ context.Context,
		registration controlstate.RelayRegistration,
		registeredAt time.Time,
		leaseDuration time.Duration,
	) (controlstate.RelayLease, error) {
		got, gotNow, gotDuration = registration, registeredAt, leaseDuration
		return controlstate.RelayLease{
			RelayLeaseIdentity: controlstate.RelayLeaseIdentity{
				RelayServiceID: registration.RelayServiceID, RelayID: registration.RelayID,
				RelayRunID: registration.RelayRunID, RelayLeaseRevision: 7,
			},
			ProtocolVersion: registration.ProtocolVersion, RelayAddress: registration.RelayAddress,
			TLSServerName: registration.TLSServerName, InternalRelayAddress: registration.InternalRelayAddress,
			InternalNetworks: registration.InternalNetworks, ConnectionCapacity: registration.ConnectionCapacity,
			StreamCapacity: registration.StreamCapacity, RegisteredAt: registeredAt,
			RenewedAt: registeredAt, LeaseExpiresAt: registeredAt.Add(leaseDuration),
		}, nil
	}}
	body := relayv1.RelayRegistration{
		RelayServiceId: "relay-service-1", RelayId: "relay-1", RelayRunId: "run-1", ProtocolVersion: 1,
		RelayAddress: "relay.example:443", TlsServerName: "relay.example",
		InternalRelayAddress: "10.0.0.10:8443", InternalNetworks: []string{"10.0.0.0/24", "2001:db8::/64"},
		ConnectionCapacity: 100, StreamCapacity: 1000,
	}
	response := serveRelayJSON(t, testRelayHandler(t, store, now, nil), http.MethodPost, "/internal/v1/relays/register", body, "relay-1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got.RelayServiceID != body.RelayServiceId || got.RelayID != body.RelayId || got.RelayRunID != body.RelayRunId ||
		got.ProtocolVersion != 1 || got.ConnectionCapacity != 100 || got.StreamCapacity != 1000 {
		t.Fatalf("registration = %#v", got)
	}
	wantNetworks := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/64")}
	if len(got.InternalNetworks) != len(wantNetworks) {
		t.Fatalf("internal networks = %v, want %v", got.InternalNetworks, wantNetworks)
	}
	for index := range wantNetworks {
		if got.InternalNetworks[index] != wantNetworks[index] {
			t.Fatalf("internal networks = %v, want %v", got.InternalNetworks, wantNetworks)
		}
	}
	if !gotNow.Equal(now) || gotDuration != 30*time.Second {
		t.Fatalf("register timing = %v, %v", gotNow, gotDuration)
	}
	var lease relayv1.RelayLease
	decodeRelayResponse(t, response, &lease)
	if lease.RelayId != "relay-1" || lease.RelayLeaseRevision != 7 || len(lease.InternalNetworks) != 2 {
		t.Fatalf("lease = %#v", lease)
	}
}

func TestRegisterRelayRejectsCertificateIdentityMismatch(t *testing.T) {
	called := false
	store := &relayStoreStub{registerRelay: func(
		context.Context, controlstate.RelayRegistration, time.Time, time.Duration,
	) (controlstate.RelayLease, error) {
		called = true
		return controlstate.RelayLease{}, nil
	}}
	body := relayv1.RelayRegistration{
		RelayServiceId: "relay-service-2", RelayId: "relay-2", RelayRunId: "run-1", ProtocolVersion: 1,
		RelayAddress: "relay.example:443", TlsServerName: "relay.example",
		InternalRelayAddress: "10.0.0.10:8443", InternalNetworks: []string{},
		ConnectionCapacity: 100, StreamCapacity: 1000,
	}
	response := serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost, "/internal/v1/relays/register", body, "relay-1")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if called {
		t.Fatal("registration reached the store")
	}
	assertRelayProblemType(t, response, "https://tnl.dev/problems/relay_identity_mismatch")
}

func TestClaimPublisherConnectionParsesCredentialAndExactIdentity(t *testing.T) {
	credential, wantDigest, err := credentials.NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	var got controlstate.PublisherConnectionClaimRequest
	store := &relayStoreStub{claimPublisherConnection: func(
		_ context.Context,
		request controlstate.PublisherConnectionClaimRequest,
		_ time.Time,
	) (controlstate.ClaimedPublisherConnection, error) {
		got = request
		return controlstate.ClaimedPublisherConnection{
			ConnectionAssignmentIdentity: request.ConnectionAssignmentIdentity,
			RelayLeaseIdentity:           request.RelayLeaseIdentity, ClaimID: request.ClaimID,
			RelayAddress: "relay.example:443", TLSServerName: "relay.example", State: "connected",
			PublisherConnectionCredentialExpiresAt: time.Now().Add(time.Minute), ConnectedAt: time.Now(),
		}, nil
	}}
	body := relayv1.PublisherConnectionClaim{
		RouteSessionId: "session-1", RouteId: "route-1", RouteVersion: 3,
		PublisherConnectionId: "connection-1", ConnectionSlot: 1, ConnectionAssignmentRevision: 2,
		RelayServiceId: "relay-service-1", RelayId: "relay-1", RelayRunId: "run-1",
		RelayLeaseRevision: 4, ClaimId: "claim-1", PublisherConnectionCredential: credential.String(),
	}
	target := "/internal/v1/publisher-connections/connection-1/claim"
	response := serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost, target, body, "relay-1")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if got.RouteSessionID != "session-1" || got.RouteID != "route-1" || got.RouteVersion != 3 ||
		got.PublisherConnectionID != "connection-1" || got.ConnectionSlot != 1 ||
		got.ConnectionAssignmentRevision != 2 || got.ConnectionAssignmentIdentity.RelayServiceID != "relay-service-1" ||
		got.RelayID != "relay-1" || got.RelayRunID != "run-1" || got.RelayLeaseRevision != 4 ||
		got.ClaimID != "claim-1" || got.CredentialDigest != [32]byte(wantDigest) {
		t.Fatalf("claim request = %#v", got)
	}
	body.PublisherConnectionId = "connection-2"
	response = serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost, target, body, "relay-1")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatched path status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
}

func TestRelayStoreErrorsHaveStableProblems(t *testing.T) {
	credential, _, err := credentials.NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		err         error
		status      int
		problemType string
	}{
		{name: "relay lease stale", err: controlstate.ErrRelayLeaseStale, status: http.StatusConflict, problemType: "relay_lease_stale"},
		{name: "stale assignment", err: controlstate.ErrConnectionAssignmentStale, status: http.StatusConflict, problemType: "stale_connection_assignment"},
		{name: "duplicate connection", err: controlstate.ErrPublisherConnectionAlreadyClaimed, status: http.StatusConflict, problemType: "publisher_connection_already_claimed"},
		{name: "credential", err: controlstate.ErrPublisherConnectionCredential, status: http.StatusUnauthorized, problemType: "invalid_publisher_connection_credential"},
		{name: "draining", err: controlstate.ErrRelayDraining, status: http.StatusServiceUnavailable, problemType: "relay_draining"},
		{name: "capacity", err: controlstate.ErrRelayConnectionCapacity, status: http.StatusServiceUnavailable, problemType: "relay_connection_capacity_exhausted"},
		{name: "unavailable", err: controlstate.ErrPublisherConnectionUnavailable, status: http.StatusConflict, problemType: "publisher_connection_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &relayStoreStub{claimPublisherConnection: func(
				context.Context, controlstate.PublisherConnectionClaimRequest, time.Time,
			) (controlstate.ClaimedPublisherConnection, error) {
				return controlstate.ClaimedPublisherConnection{}, test.err
			}}
			body := relayv1.PublisherConnectionClaim{
				RouteSessionId: "session-1", RouteId: "route-1", RouteVersion: 1,
				PublisherConnectionId: "connection-1", ConnectionSlot: 0, ConnectionAssignmentRevision: 1,
				RelayServiceId: "relay-service-1", RelayId: "relay-1", RelayRunId: "run-1",
				RelayLeaseRevision: 1, ClaimId: "claim-1", PublisherConnectionCredential: credential.String(),
			}
			response := serveRelayJSON(
				t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost,
				"/internal/v1/publisher-connections/connection-1/claim", body, "relay-1",
			)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			assertRelayProblemType(t, response, "https://tnl.dev/problems/"+test.problemType)
		})
	}
}

func testRelayHandler(t *testing.T, store Store, now time.Time, report func(error)) http.Handler {
	t.Helper()
	h, err := NewHandler(Config{
		Store: store, RelayIdentity: relayCertificateIdentity, LeaseDuration: 30 * time.Second,
		Now: func() time.Time { return now }, Report: report,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func relayCertificateIdentity(certificate *x509.Certificate) (RelayIdentity, error) {
	if len(certificate.DNSNames) != 1 || !strings.HasPrefix(certificate.DNSNames[0], "relay-") {
		return RelayIdentity{}, errors.New("test certificate has no relay identity")
	}
	return RelayIdentity{RelayServiceID: "relay-service-1", RelayID: certificate.DNSNames[0]}, nil
}

func serveRelayJSON(
	t *testing.T,
	h http.Handler,
	method, target string,
	body any,
	relayID string,
) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, target, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = verifiedCertificate(relayID)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func verifiedCertificate(identity string) *tls.ConnectionState {
	certificate := &x509.Certificate{DNSNames: []string{identity}}
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}
}

func decodeRelayResponse(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatal(err)
	}
}

func assertRelayProblemType(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	var problem relayv1.Problem
	decodeRelayResponse(t, response, &problem)
	if problem.Type != want {
		t.Fatalf("problem type = %q, want %q", problem.Type, want)
	}
}

type relayStoreStub struct {
	registerRelay                 func(context.Context, controlstate.RelayRegistration, time.Time, time.Duration) (controlstate.RelayLease, error)
	renewRelay                    func(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error)
	beginRelayDrain               func(context.Context, controlstate.RelayLeaseIdentity, time.Time, time.Time) (controlstate.RelayLease, error)
	claimPublisherConnection      func(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error)
	markPublisherConnectionReady  func(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error)
	disconnectPublisherConnection func(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time, bool) (controlstate.ClaimedPublisherConnection, error)
}

func (s *relayStoreStub) RegisterRelay(
	ctx context.Context, registration controlstate.RelayRegistration, now time.Time, duration time.Duration,
) (controlstate.RelayLease, error) {
	return s.registerRelay(ctx, registration, now, duration)
}

func (s *relayStoreStub) RenewRelay(
	ctx context.Context, renewal controlstate.RelayRenewal, now time.Time, duration time.Duration,
) (controlstate.RelayLease, error) {
	return s.renewRelay(ctx, renewal, now, duration)
}

func (s *relayStoreStub) BeginRelayDrain(
	ctx context.Context, identity controlstate.RelayLeaseIdentity, now, deadline time.Time,
) (controlstate.RelayLease, error) {
	return s.beginRelayDrain(ctx, identity, now, deadline)
}

func (s *relayStoreStub) ClaimPublisherConnection(
	ctx context.Context, request controlstate.PublisherConnectionClaimRequest, now time.Time,
) (controlstate.ClaimedPublisherConnection, error) {
	return s.claimPublisherConnection(ctx, request, now)
}

func (s *relayStoreStub) MarkPublisherConnectionReady(
	ctx context.Context, request controlstate.PublisherConnectionClaimRequest, now time.Time,
) (controlstate.ClaimedPublisherConnection, error) {
	return s.markPublisherConnectionReady(ctx, request, now)
}

func (s *relayStoreStub) DisconnectPublisherConnection(
	ctx context.Context, request controlstate.PublisherConnectionClaimRequest, now time.Time, unexpected bool,
) (controlstate.ClaimedPublisherConnection, error) {
	return s.disconnectPublisherConnection(ctx, request, now, unexpected)
}
