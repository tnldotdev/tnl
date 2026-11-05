package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationExpiredIngressRunRequiresNewRun(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "expired_ingress")
	registration := IngressRegistration{IngressID: "ingress-expired", IngressRunID: "old-run", ProtocolVersion: 1, ConnectionCapacity: 10}
	lease, err := database.RegisterIngress(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// retries preserve the original lease identity, including after renewal.
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, now.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	replayed, err := database.RegisterIngress(t.Context(), registration, now.Add(2*time.Second), time.Minute)
	if err != nil || replayed.IngressLeaseIdentity != lease.IngressLeaseIdentity {
		t.Fatalf("live retry = %+v, %v", replayed, err)
	}
	expired := now.Add(2 * time.Minute)
	for range 2 {
		if _, err := database.RegisterIngress(t.Context(), registration, expired, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatalf("same-run registration = %v", err)
		}
	}
	registration.IngressRunID = "new-run"
	restarted, err := database.RegisterIngress(t.Context(), registration, expired, time.Minute)
	if err != nil || restarted.IngressLeaseRevision != lease.IngressLeaseRevision+1 {
		t.Fatalf("new-run registration = %+v, %v", restarted, err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: restarted.IngressLeaseIdentity}, expired.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, expired.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("old-run renewal = %v", err)
	}
	var oldRevision int64
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_lease_revision FROM control.ingress_run_fences WHERE ingress_id=$1 AND ingress_run_id='old-run'`, registration.IngressID).Scan(&oldRevision); err != nil || oldRevision != int64(lease.IngressLeaseRevision) {
		t.Fatalf("old process fence = %d, %v", oldRevision, err)
	}
	// removing the runtime row cannot revive a retired process or reuse a revision.
	if _, err := database.pool.Exec(t.Context(), `DELETE FROM control.ingress_leases WHERE ingress_id=$1`, registration.IngressID); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"old-run", "new-run"} {
		registration.IngressRunID = runID
		if _, err := database.RegisterIngress(t.Context(), registration, expired.Add(2*time.Minute), time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
			t.Fatalf("retired %s registration = %v", runID, err)
		}
	}
	registration.IngressRunID = "third-run"
	third, err := database.RegisterIngress(t.Context(), registration, expired.Add(2*time.Minute), time.Minute)
	if err != nil || third.IngressLeaseRevision != restarted.IngressLeaseRevision+1 {
		t.Fatalf("registration after runtime removal = %+v, %v", third, err)
	}
}
