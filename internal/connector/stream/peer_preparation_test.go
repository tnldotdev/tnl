package stream

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type installationObservation struct {
	Control
	pair     controlv1.ConnectorPeerPair
	requests chan controlv1.ConnectorPeerPairRequest
}

func (c installationObservation) PrepareConnectorPeerPair(_ context.Context, _ string, request controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	select {
	case c.requests <- request:
	default:
	}
	return c.pair, nil
}

func TestConnectorPreparationWaitsForPublisherInstallationWithoutResigning(t *testing.T) {
	now := time.Now()
	identity, device := "ident_"+strings.Repeat("A", 22), "vdev_"+strings.Repeat("B", 22)
	pair := controlv1.ConnectorPeerPair{PairId: "cpp_" + strings.Repeat("C", 22), DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
		ServiceId: "svc_" + strings.Repeat("D", 22), ServiceRunId: "srun_" + strings.Repeat("E", 22), RunNumber: 1,
		PublisherIdentityId: "pub_" + strings.Repeat("F", 22), Subject: controlv1.VisitorSubject{Kind: "human_device", IdentityId: &identity, DeviceId: &device},
		Key: "already-checked-key", Relays: []controlv1.ConnectorPeerPairRelay{{PublisherConnectionId: "first"}, {PublisherConnectionId: "second"}}, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
	request := controlv1.ConnectorPeerPairRequest{Action: "create", IdempotencyKey: "original-owner", RequestedAt: now, Signature: "original-signed-proof"}
	t.Run("uninstalled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		control := installationObservation{pair: pair, requests: make(chan controlv1.ConnectorPeerPairRequest, 8)}
		done := make(chan error, 1)
		go func() { _, err := awaitConnectorPublisher(ctx, control, pair.ServiceId, request, pair); done <- err }()
		for range 2 {
			select {
			case observed := <-control.requests:
				if !reflect.DeepEqual(observed, request) {
					t.Fatal("installation wait changed or re-signed the owner request")
				}
			case err := <-done:
				t.Fatal("uninstalled publisher passed the startup barrier", err)
			case <-ctx.Done():
				t.Fatal("installation observation did not run")
			}
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("installation wait lost the original setup cancellation", err)
			}
		case <-time.After(time.Second):
			t.Fatal("installation wait reset the original setup budget")
		}
	})
	for _, name := range []string{"installed", "different pair", "different relay", "different subject", "extended report"} {
		t.Run(name, func(t *testing.T) {
			response := pair
			response.Relays = append([]controlv1.ConnectorPeerPairRelay(nil), pair.Relays...)
			response.PublisherPreparedUntil = new(pair.ExpiresAt)
			switch name {
			case "different pair":
				response.PairId = "cpp_" + strings.Repeat("Z", 22)
			case "different relay":
				response.Relays[0].AssignmentRevision++
			case "different subject":
				response.Subject.DeviceId = new("vdev_" + strings.Repeat("Z", 22))
			case "extended report":
				response.PublisherPreparedUntil = new(pair.ExpiresAt.Add(time.Second))
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, err := awaitConnectorPublisher(ctx, installationObservation{pair: response}, pair.ServiceId, request, pair)
			if name == "installed" && err != nil || name != "installed" && !errors.Is(err, ErrServiceConnection) {
				t.Fatal("installation observation lost its exact binding", err)
			}
			if name == "installed" && (!until.After(time.Now()) || until.After(time.Now().Add(time.Minute))) {
				t.Fatal("installation observation lost its conservative bound")
			}
		})
	}
}
