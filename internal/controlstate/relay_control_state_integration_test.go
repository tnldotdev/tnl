package controlstate

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationRelayControlState(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "relay_control_state")
	testRelayControlState(t, database)
}

func TestIntegrationRelayDrainRejectsExpiredRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "relay_drain_expiry")
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 10, StreamCapacity: 20,
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(30 * time.Second)
	if _, err := database.BeginRelayDrain(t.Context(), lease.RelayLeaseIdentity, now.Add(time.Second), deadline); err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{deadline, deadline.Add(time.Second)} {
		if _, err := database.RenewRelay(t.Context(), RelayRenewal{
			RelayLeaseIdentity: lease.RelayLeaseIdentity,
		}, at, time.Minute); !errors.Is(err, ErrRelayLeaseStale) {
			t.Fatalf("renew drained run at %s: %v", at, err)
		}
		if _, err := database.RegisterRelay(t.Context(), registration, at, time.Minute); !errors.Is(err, ErrRelayRegistrationConflict) {
			t.Fatalf("re-register drained run at %s: %v", at, err)
		}
	}
	registration.RelayRunID = "run_restarted"
	restarted, err := database.RegisterRelay(t.Context(), registration, deadline.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Draining || restarted.DrainDeadline != nil || restarted.RelayRunID != registration.RelayRunID ||
		restarted.RelayLeaseRevision != lease.RelayLeaseRevision+1 {
		t.Fatalf("restarted relay lease = %#v", restarted)
	}
	// Ordinary lease expiry still permits recovery by a run that has not drained.
	recovered, err := database.RegisterRelay(t.Context(), registration, restarted.LeaseExpiresAt, time.Minute)
	if err != nil || recovered.Draining || recovered.RelayLeaseRevision != restarted.RelayLeaseRevision+1 {
		t.Fatalf("recovered relay lease = %#v, %v", recovered, err)
	}
}
