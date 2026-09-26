package relayapi

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

func TestClaimRejectsMalformedCredentialWithoutStoreCall(t *testing.T) {
	for _, transport := range []string{"direct", "HTTP"} {
		t.Run(transport, func(t *testing.T) {
			calls := 0
			store := &relayStoreStub{claimPublisherConnection: func(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error) {
				calls++
				return controlstate.ClaimedPublisherConnection{}, nil
			}}
			client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			body := relayv1.PublisherConnectionClaim{
				PublishRunId: "session-1", PublicUrlId: "route-1", PublishRunNumber: 1,
				PublisherConnectionId: "connection-1", ConnectionSlot: 0, ConnectionAssignmentRevision: 1,
				RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 1,
				ClaimId: "claim-1", PublisherConnectionCredential: "malformed",
			}
			var status int
			var problemType string
			if transport == "direct" {
				_, err = client.ClaimPublisherConnection(t.Context(), "connection-1", body)
				var problem *serviceapi.ProblemError
				if !errors.As(err, &problem) {
					t.Fatalf("direct error = %v", err)
				}
				status, problemType = problem.Status, problem.Type
			} else {
				wire := serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost, "/internal/v1/publisher-connections/connection-1/claim", body)
				response, parseErr := relayv1.ParseClaimPublisherConnectionResponse(wire.Result())
				if parseErr != nil {
					t.Fatal(parseErr)
				}
				status = response.StatusCode()
				if response.ApplicationproblemJSONDefault != nil {
					problemType = response.ApplicationproblemJSONDefault.Type
				}
			}
			if status != http.StatusUnauthorized || problemType != "https://tnl.dev/problems/invalid_publisher_connection_credential" || calls != 0 {
				t.Fatalf("response = %d %s, %v", status, problemType, err)
			}
		})
	}
}

func TestDirectRenewStatus(t *testing.T) {
	var failure error
	client, err := NewDirectClient(DirectConfig{Store: &relayStoreStub{renewRelay: func(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error) {
		return controlstate.RelayLease{}, failure
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	body := relayv1.RelayRenewal{RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 1}
	lease, err := client.RenewRelay(t.Context(), "relay-1", body)
	if err != nil {
		t.Fatalf("success = %#v, %v", lease, err)
	}
	failure = controlstate.ErrRelayLeaseStale
	_, err = client.RenewRelay(t.Context(), "relay-1", body)
	var problem *serviceapi.ProblemError
	if !errors.As(err, &problem) || problem.Status != http.StatusConflict || problem.Type != "https://tnl.dev/problems/relay_lease_stale" {
		t.Fatalf("stale lease = %#v, %v", problem, err)
	}
}

func TestDirectRenewCancellation(t *testing.T) {
	client, err := NewDirectClient(DirectConfig{Store: &relayStoreStub{renewRelay: func(ctx context.Context, _ controlstate.RelayRenewal, _ time.Time, _ time.Duration) (controlstate.RelayLease, error) {
		return controlstate.RelayLease{}, ctx.Err()
	}}, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	body := relayv1.RelayRenewal{RelayServiceId: "service-1", RelayId: "relay-1", RelayRunId: "run-1", RelayLeaseRevision: 1}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	lease, err := client.RenewRelay(ctx, "relay-1", body)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %#v, %v", lease, err)
	}
}
