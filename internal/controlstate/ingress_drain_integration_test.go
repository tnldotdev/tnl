package controlstate

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationIngressDrainRetainsExpiration(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_drain_expiration")
	registration := IngressRegistration{
		IngressID: "draining-ingress", IngressRunID: "first-run",
		ProtocolVersion: 1, ConnectionCapacity: 10,
	}
	lease, err := database.RegisterIngress(t.Context(), registration, now, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(40 * time.Second)
	draining, err := database.BeginIngressDrain(t.Context(), lease.IngressLeaseIdentity, now.Add(time.Second), deadline)
	if err != nil {
		t.Fatal(err)
	}
	assertDraining := func(step string, current IngressLease) {
		t.Helper()
		if !current.Draining || current.DrainDeadline == nil || !current.DrainDeadline.Equal(deadline) ||
			!current.LeaseExpiresAt.Equal(deadline) || current.IngressLeaseRevision != lease.IngressLeaseRevision {
			t.Fatalf("%s changed the drain boundary: %+v", step, current)
		}
	}
	assertDraining("begin drain", draining)

	// A short renewal must not expire the lease before its drain deadline, and
	// a longer one or a repeated registration must not extend it afterward.
	short, err := database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: lease.IngressLeaseIdentity,
	}, now.Add(2*time.Second), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	assertDraining("short renewal", short)
	repeated, err := database.RegisterIngress(t.Context(), registration, now.Add(3*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertDraining("repeated registration", repeated)
	long, err := database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: lease.IngressLeaseIdentity,
	}, now.Add(4*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertDraining("long renewal", long)

	if _, err := database.RenewIngress(t.Context(), IngressRenewal{
		IngressLeaseIdentity: lease.IngressLeaseIdentity,
	}, deadline, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("renew draining run after deadline: %v", err)
	}
	if _, err := database.RegisterIngress(t.Context(), registration, deadline, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("re-register expired draining run: %v", err)
	}
	registration.IngressRunID = "new-run"
	restarted, err := database.RegisterIngress(t.Context(), registration, deadline.Add(time.Second), time.Minute)
	if err != nil || restarted.Draining || restarted.IngressLeaseRevision != lease.IngressLeaseRevision+1 {
		t.Fatalf("restarted ingress = %+v, %v", restarted, err)
	}
}

func TestIntegrationIngressRoutingAcknowledgementNeverRegresses(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_acknowledgement")
	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "routing-ingress", IngressRunID: "first-run", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []uint64{5, 3} {
		lease, err = database.RenewIngress(t.Context(), IngressRenewal{
			IngressLeaseIdentity: lease.IngressLeaseIdentity, RoutingTableRevision: revision,
		}, now.Add(time.Second), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	if lease.RoutingTableRevision != 5 {
		t.Fatalf("older renewal regressed the routing acknowledgement to %d", lease.RoutingTableRevision)
	}
}
