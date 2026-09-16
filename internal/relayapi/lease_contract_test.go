package relayapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestRelayLeaseMutationContracts(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(20 * time.Second)
	wantIdentity := controlstate.RelayLeaseIdentity{RelayServiceID: "service-1", RelayID: "relay-1", RelayRunID: "run-1", RelayLeaseRevision: 7}
	// The store result deliberately differs from the submitted identity and counters.
	lease := controlstate.RelayLease{
		RelayLeaseIdentity: controlstate.RelayLeaseIdentity{RelayServiceID: "service-result", RelayID: "relay-result", RelayRunID: "run-result", RelayLeaseRevision: 9},
		ProtocolVersion:    1, RelayAddress: "relay.example.test:443", TLSServerName: "relay.example.test", InternalRelayAddress: "10.0.0.10:8443",
		InternalNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, ConnectionCapacity: 100, StreamCapacity: 200,
		ReportedConnections: 11, ReportedStreams: 12, RegisteredAt: now.Add(-time.Minute), RenewedAt: now,
		LeaseExpiresAt: now.Add(30 * time.Second), Draining: true, DrainDeadline: &deadline,
	}
	wantLease := relayv1.RelayLease{
		RelayServiceId: "service-result", RelayId: "relay-result", RelayRunId: "run-result", RelayLeaseRevision: 9,
		ProtocolVersion: 1, RelayAddress: "relay.example.test:443", TlsServerName: "relay.example.test", InternalRelayAddress: "10.0.0.10:8443",
		InternalNetworks: []string{"10.0.0.0/24"}, ConnectionCapacity: 100, StreamCapacity: 200, ReportedConnections: 11, ReportedStreams: 12,
		RegisteredAt: now.Add(-time.Minute), RenewedAt: now, LeaseExpiresAt: now.Add(30 * time.Second), Draining: true, DrainDeadline: &deadline,
	}
	for _, operation := range []string{"renew", "drain"} {
		for _, transport := range []string{"direct", "HTTP"} {
			t.Run(operation+"/"+transport, func(t *testing.T) {
				var renewal controlstate.RelayRenewal
				var identity controlstate.RelayLeaseIdentity
				var calledAt, drainAt time.Time
				var duration time.Duration
				var calls []string
				store := &relayStoreStub{
					renewRelay: func(_ context.Context, input controlstate.RelayRenewal, at time.Time, leaseDuration time.Duration) (controlstate.RelayLease, error) {
						calls = append(calls, "renew")
						renewal, calledAt, duration = input, at, leaseDuration
						return lease, nil
					},
					beginRelayDrain: func(_ context.Context, input controlstate.RelayLeaseIdentity, at, until time.Time) (controlstate.RelayLease, error) {
						calls = append(calls, "drain")
						identity, calledAt, drainAt = input, at, until
						return lease, nil
					},
				}
				client, err := NewDirectClient(DirectConfig{
					Store: store, LeaseDuration: 30 * time.Second, Now: func() time.Time { return now },
				})
				if err != nil {
					t.Fatal(err)
				}
				var result *relayv1.RelayLease
				var status int
				if operation == "renew" {
					body := relayv1.RelayRenewal{RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 7, ReportedConnections: 3, ReportedStreams: 4}
					if transport == "direct" {
						lease, directErr := client.RenewRelay(t.Context(), "relay-1", body)
						err = directErr
						result, status = &lease, http.StatusOK
					} else {
						wire := serveRelayJSON(t, testRelayHandler(t, store, now, nil), http.MethodPost, "/internal/v1/relays/relay-1/renew", body)
						response, parseErr := relayv1.ParseRenewRelayResponse(wire.Result())
						err = parseErr
						result, status = response.JSON200, response.StatusCode()
					}
					if err != nil {
						t.Fatal(err)
					}
					if renewal != (controlstate.RelayRenewal{RelayLeaseIdentity: wantIdentity, ReportedConnections: 3, ReportedStreams: 4}) || duration != 30*time.Second {
						t.Fatalf("renewal = %#v, duration %v", renewal, duration)
					}
				} else {
					body := relayv1.RelayDrainRequest{RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 7, Deadline: deadline}
					if transport == "direct" {
						lease, directErr := client.DrainRelay(t.Context(), "relay-1", body)
						err = directErr
						result, status = &lease, http.StatusOK
					} else {
						wire := serveRelayJSON(t, testRelayHandler(t, store, now, nil), http.MethodPost, "/internal/v1/relays/relay-1/drain", body)
						response, parseErr := relayv1.ParseDrainRelayResponse(wire.Result())
						err = parseErr
						result, status = response.JSON200, response.StatusCode()
					}
					if err != nil {
						t.Fatal(err)
					}
					if identity != wantIdentity || !drainAt.Equal(deadline) {
						t.Fatalf("drain = %#v, deadline %v", identity, drainAt)
					}
				}
				if !reflect.DeepEqual(calls, []string{operation}) || !calledAt.Equal(now) || status != http.StatusOK || !reflect.DeepEqual(result, &wantLease) {
					t.Fatalf("calls = %v at %v; response = %d %#v, want %#v", calls, calledAt, status, result, wantLease)
				}
			})
		}
	}
}

func TestDirectRenewRejectsMismatchedPathBeforeStore(t *testing.T) {
	calls := 0
	client, err := NewDirectClient(DirectConfig{Store: &relayStoreStub{renewRelay: func(_ context.Context, input controlstate.RelayRenewal, _ time.Time, _ time.Duration) (controlstate.RelayLease, error) {
		calls++
		return controlstate.RelayLease{}, nil
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RenewRelay(t.Context(), "path-relay", relayv1.RelayRenewal{
		RelayServiceId: "service-1", RelayId: "body-relay", RelayRunId: "run-1", RelayLeaseRevision: 7,
	})
	var problem *serviceapi.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || calls != 0 {
		t.Fatalf("error = %v; store calls %d", err, calls)
	}
}

func TestHTTPRenewRejectsMismatchedPathBeforeStore(t *testing.T) {
	calls := 0
	store := &relayStoreStub{renewRelay: func(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error) {
		calls++
		return controlstate.RelayLease{}, nil
	}}
	response := serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost, "/internal/v1/relays/path-relay/renew", relayv1.RelayRenewal{
		RelayServiceId: "service-1", RelayId: "body-relay", RelayRunId: "run-1", RelayLeaseRevision: 7,
	})
	if response.Code != http.StatusBadRequest || calls != 0 {
		t.Fatalf("response = %d: %s; calls %d", response.Code, response.Body.String(), calls)
	}
}
