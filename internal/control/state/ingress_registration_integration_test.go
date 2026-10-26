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
	expired := now.Add(time.Minute)
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
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, expired.Add(time.Second), time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("retired process renewed the replacement lease: %v", err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: restarted.IngressLeaseIdentity}, expired.Add(time.Second), time.Minute); err != nil {
		t.Fatal(err)
	}
}
