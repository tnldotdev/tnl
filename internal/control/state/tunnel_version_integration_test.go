package state

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationTunnelVersionPlacementRejectsPreviousVersion(t *testing.T) {
	t.Run("relays", func(t *testing.T) {
		d, now, request, _ := newPublishRunPrerequisites(t)
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET protocol_version=$1`, tunnelv1.Version-1); err != nil {
			t.Fatal(err)
		}
		if _, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
			t.Fatal("placement selected previous-wire relays", err)
		}
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET protocol_version=$1`, tunnelv1.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := d.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute); err != nil {
			t.Fatal("placement did not select current-wire relays", err)
		}
	})
	t.Run("ingress", func(t *testing.T) {
		d, now := newControlStateIntegrationDatabase(t, "tunnel_version_ingress")
		for index := range 2 {
			_, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("version-%d", index), IngressRunID: fmt.Sprintf("process-%d", index),
				ProtocolVersion: tunnelv1.Version - 1, ConnectionCapacity: 10, IngressPoolID: PrimaryIngressPoolID,
				ConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 9400+index), ConnectorTLSServerName: "private.example.test"}, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
		}
		check := func(want error) {
			t.Helper()
			tx, err := d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context())
			selected, err := privateIngressPlacements(t.Context(), tx, now, 2, "", nil)
			if !errors.Is(err, want) || err == nil && len(selected) != 2 {
				t.Fatal("ingress placement did not enforce the current wire version", err)
			}
		}
		check(ErrInsufficientPrivateIngresses)
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.ingress_leases SET protocol_version=$1`, tunnelv1.Version); err != nil {
			t.Fatal(err)
		}
		check(nil)
	})
}
