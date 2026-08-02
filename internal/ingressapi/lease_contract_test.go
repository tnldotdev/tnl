package ingressapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func TestIngressLeaseMutationContracts(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(20 * time.Second)
	date := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	var currentKey, nextKey [32]byte
	for i := range currentKey {
		currentKey[i], nextKey[i] = 1, 2
	}
	wantIdentity := controlstate.IngressLeaseIdentity{IngressID: "ingress-1", IngressRunID: "run-1", IngressLeaseRevision: 7}
	lease := controlstate.IngressLease{
		IngressLeaseIdentity: controlstate.IngressLeaseIdentity{IngressID: "ingress-result", IngressRunID: "run-result", IngressLeaseRevision: 9},
		ProtocolVersion:      1, ConnectionCapacity: 100, ReportedConnections: 11, RoutingTableRevision: 19,
		RegisteredAt: now.Add(-time.Minute), RenewedAt: now, LeaseExpiresAt: now.Add(30 * time.Second), Draining: true, DrainDeadline: &deadline,
		VisitorNetworkHashKeys: [2]controlstate.VisitorNetworkHashKey{{UTCDate: date, Key: currentKey}, {UTCDate: date.Add(24 * time.Hour), Key: nextKey}},
	}
	wantLease := ingressv1.IngressLease{
		IngressId: "ingress-result", IngressRunId: "run-result", IngressLeaseRevision: 9, ProtocolVersion: 1,
		ConnectionCapacity: 100, ReportedConnections: 11, RoutingTableRevision: 19,
		RegisteredAt: now.Add(-time.Minute), RenewedAt: now, LeaseExpiresAt: now.Add(30 * time.Second), Draining: true, DrainDeadline: &deadline,
		VisitorNetworkHashKeys: []ingressv1.VisitorNetworkHashKey{
			{UtcDate: openapi_types.Date{Time: date}, Key: bytes.Repeat([]byte{1}, 32)},
			{UtcDate: openapi_types.Date{Time: date.Add(24 * time.Hour)}, Key: bytes.Repeat([]byte{2}, 32)},
		},
	}
	for _, operation := range []string{"renew", "drain"} {
		for _, transport := range []string{"direct", "HTTP"} {
			t.Run(operation+"/"+transport, func(t *testing.T) {
				var renewal controlstate.IngressRenewal
				var identity controlstate.IngressLeaseIdentity
				var calledAt, drainAt time.Time
				var duration time.Duration
				var calls []string
				store := &ingressStoreStub{
					renewIngress: func(_ context.Context, input controlstate.IngressRenewal, at time.Time, leaseDuration time.Duration) (controlstate.IngressLease, error) {
						calls = append(calls, "renew")
						renewal, calledAt, duration = input, at, leaseDuration
						return lease, nil
					},
					beginIngressDrain: func(_ context.Context, input controlstate.IngressLeaseIdentity, at, until time.Time) (controlstate.IngressLease, error) {
						calls = append(calls, "drain")
						identity, calledAt, drainAt = input, at, until
						return lease, nil
					},
				}
				client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: 30 * time.Second, Now: func() time.Time { return now }})
				if err != nil {
					t.Fatal(err)
				}
				var result *ingressv1.IngressLease
				var status int
				if operation == "renew" {
					body := ingressv1.IngressRenewal{IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7, ReportedConnections: 3, RoutingTableRevision: 17}
					if transport == "direct" {
						lease, directErr := client.RenewIngress(t.Context(), "ingress-1", body)
						err = directErr
						result, status = &lease, http.StatusOK
					} else {
						wire := serveIngressJSON(t, testIngressHandler(t, store, now, nil), http.MethodPost, "/internal/v1/ingresses/ingress-1/renew", body)
						response, parseErr := ingressv1.ParseRenewIngressResponse(wire.Result())
						err = parseErr
						result, status = response.JSON200, response.StatusCode()
					}
					if err != nil {
						t.Fatal(err)
					}
					if renewal != (controlstate.IngressRenewal{IngressLeaseIdentity: wantIdentity, ReportedConnections: 3, RoutingTableRevision: 17}) || duration != 30*time.Second {
						t.Fatalf("renewal = %#v, duration %v", renewal, duration)
					}
				} else {
					body := ingressv1.IngressDrainRequest{IngressId: "ingress-1", IngressRunId: "run-1", IngressLeaseRevision: 7, Deadline: deadline}
					if transport == "direct" {
						lease, directErr := client.DrainIngress(t.Context(), "ingress-1", body)
						err = directErr
						result, status = &lease, http.StatusOK
					} else {
						wire := serveIngressJSON(t, testIngressHandler(t, store, now, nil), http.MethodPost, "/internal/v1/ingresses/ingress-1/drain", body)
						response, parseErr := ingressv1.ParseDrainIngressResponse(wire.Result())
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
	client, err := NewDirectClient(DirectConfig{Store: &ingressStoreStub{renewIngress: func(_ context.Context, input controlstate.IngressRenewal, _ time.Time, _ time.Duration) (controlstate.IngressLease, error) {
		calls++
		return controlstate.IngressLease{}, nil
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.RenewIngress(t.Context(), "path-ingress", ingressv1.IngressRenewal{
		IngressId: "body-ingress", IngressRunId: "run-1", IngressLeaseRevision: 7,
	})
	var problem *serviceapi.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusBadRequest || calls != 0 {
		t.Fatalf("error = %v; store calls %d", err, calls)
	}
}

func TestHTTPRenewRejectsMismatchedPathBeforeStore(t *testing.T) {
	calls := 0
	store := &ingressStoreStub{renewIngress: func(context.Context, controlstate.IngressRenewal, time.Time, time.Duration) (controlstate.IngressLease, error) {
		calls++
		return controlstate.IngressLease{}, nil
	}}
	response := serveIngressJSON(t, testIngressHandler(t, store, time.Now(), nil), http.MethodPost, "/internal/v1/ingresses/path-ingress/renew", ingressv1.IngressRenewal{
		IngressId: "body-ingress", IngressRunId: "run-1", IngressLeaseRevision: 7,
	})
	if response.Code != http.StatusBadRequest || calls != 0 {
		t.Fatalf("response = %d: %s; calls %d", response.Code, response.Body.String(), calls)
	}
}
