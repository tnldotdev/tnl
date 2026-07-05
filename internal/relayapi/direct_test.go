package relayapi

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestDirectClaimRejectsMalformedCredentialWithoutStoreCall(t *testing.T) {
	client, err := NewDirectClient(&relayStoreStub{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body := relayv1.PublisherConnectionClaim{
		RouteSessionId: "session-1", RouteId: "route-1", RouteVersion: 1,
		PublisherConnectionId: "connection-1", ConnectionSlot: 0, ConnectionAssignmentRevision: 1,
		RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 1,
		ClaimId: "claim-1", PublisherConnectionCredential: "malformed",
	}
	response, err := client.ClaimPublisherConnectionWithResponse(t.Context(), "connection-1", body)
	if err != nil || response.StatusCode() != http.StatusUnauthorized || response.ApplicationproblemJSONDefault == nil || response.ApplicationproblemJSONDefault.Type != "https://tnl.dev/problems/invalid_publisher_connection_credential" {
		t.Fatalf("response = %#v, %v", response, err)
	}
}

func TestDirectRenewStatusAndCancellation(t *testing.T) {
	var failure error
	client, err := NewDirectClient(&relayStoreStub{renewRelay: func(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error) {
		return controlstate.RelayLease{}, failure
	}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	body := relayv1.RelayRenewal{RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 1}
	response, err := client.RenewRelayWithResponse(t.Context(), "relay-1", body)
	if err != nil || response.StatusCode() != http.StatusOK || response.JSON200 == nil {
		t.Fatalf("success = %#v, %v", response, err)
	}
	failure = controlstate.ErrRelayLeaseStale
	response, err = client.RenewRelayWithResponse(t.Context(), "relay-1", body)
	if err != nil || response.StatusCode() != http.StatusConflict || response.ApplicationproblemJSONDefault.Type != "https://tnl.dev/problems/relay_lease_stale" {
		t.Fatalf("stale lease = %#v, %v", response, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	failure = ctx.Err()
	response, err = client.RenewRelayWithResponse(ctx, "relay-1", body)
	if response != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %#v, %v", response, err)
	}
}
