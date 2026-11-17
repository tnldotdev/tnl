package state

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
			!current.LeaseExpiresAt.Equal(deadline) || current.IngressLeaseIdentity != lease.IngressLeaseIdentity ||
			!current.ServingUntil.Equal(lease.ServingUntil) || !current.RegisteredAt.Equal(lease.RegisteredAt) {
			t.Fatalf("%s changed the drain boundary: %+v", step, current)
		}
	}
	assertDraining("begin drain", draining)

	// a short renewal must not expire the lease before its drain deadline, and
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

	before := ingressDrainSnapshot(t, database, registration.IngressID)
	for _, boundary := range []struct {
		name string
		at   time.Time
	}{
		{"deadline", deadline},
		{"one microsecond after", deadline.Add(time.Microsecond)},
	} {
		// independent subtests keep a failed renewal from hiding registration
		// revival. every refused write must preserve the entire lease and fence.
		t.Run("renew/"+boundary.name, func(t *testing.T) {
			if _, err := database.RenewIngress(t.Context(), IngressRenewal{
				IngressLeaseIdentity: lease.IngressLeaseIdentity,
			}, boundary.at, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
				t.Errorf("renew draining run after deadline: %v", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("refused drain renewal changed serving authority or the process fence")
			}
		})
		t.Run("register/"+boundary.name, func(t *testing.T) {
			if _, err := database.RegisterIngress(t.Context(), registration, boundary.at, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
				t.Errorf("re-register expired draining run: %v", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("refused drain registration changed serving authority or the process fence")
			}
		})
		t.Run("changed configuration/"+boundary.name, func(t *testing.T) {
			conflict := registration
			conflict.HTTPS = true
			if _, err := database.RegisterIngress(t.Context(), conflict, boundary.at, time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
				t.Errorf("expired drain replaced the configuration conflict classification: %v", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("conflicting drain registration changed serving authority or the process fence")
			}
		})
	}
	registration.IngressRunID = "new-run"
	restarted, err := database.RegisterIngress(t.Context(), registration, deadline.Add(time.Second), time.Minute)
	if err != nil || restarted.Draining || restarted.DrainDeadline != nil ||
		restarted.IngressRunID != registration.IngressRunID || restarted.IngressLeaseRevision != lease.IngressLeaseRevision+1 {
		t.Fatalf("restarted ingress = %+v, %v", restarted, err)
	}
}

func ingressDrainSnapshot(t *testing.T, database *Database, ingressID string) string {
	t.Helper()
	var saved string
	if err := database.pool.QueryRow(t.Context(), `SELECT jsonb_build_array(
	    (SELECT to_jsonb(lease) FROM control.ingress_leases lease WHERE ingress_id=$1),
	    (SELECT jsonb_agg(to_jsonb(fence) ORDER BY ingress_run_id) FROM control.ingress_run_fences fence WHERE ingress_id=$1))::text`,
		ingressID).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestIntegrationIngressDrainRetainsEarlierDeadline(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_drain_earlier")
	registration := IngressRegistration{
		IngressID: "earlier-drain", IngressRunID: "first-run",
		ProtocolVersion: 1, ConnectionCapacity: 10,
	}
	lease, err := database.RegisterIngress(t.Context(), registration, now, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(5 * time.Second)
	draining, err := database.BeginIngressDrain(t.Context(), lease.IngressLeaseIdentity, now.Add(time.Second), deadline)
	if err != nil || draining.DrainDeadline == nil || !draining.DrainDeadline.Equal(deadline) ||
		!draining.LeaseExpiresAt.Equal(lease.LeaseExpiresAt) || !draining.ServingUntil.Equal(lease.ServingUntil) {
		t.Fatal("begin drain lost its earlier deadline or changed the existing lease authority", draining, err)
	}
	before := ingressDrainSnapshot(t, database, registration.IngressID)
	for index, at := range []time.Time{deadline, deadline.Add(time.Microsecond)} {
		name := []string{"deadline", "one microsecond after"}[index]
		t.Run("renew/"+name, func(t *testing.T) {
			if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, at, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
				t.Error("later lease expiry bypassed the original drain deadline", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("renewal extended an earlier drain or its serving authority")
			}
		})
		t.Run("register/"+name, func(t *testing.T) {
			if _, err := database.RegisterIngress(t.Context(), registration, at, time.Minute); !errors.Is(err, ErrIngressLeaseStale) {
				t.Error("registration bypassed the original earlier drain deadline", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("registration extended an earlier drain or its serving authority")
			}
		})
	}
}

func TestIntegrationIngressLivenessRecoveryRetainsServingAuthority(t *testing.T) {
	for _, operation := range []string{"renew", "register"} {
		t.Run(operation, func(t *testing.T) {
			database, now := newControlStateIntegrationDatabase(t, "ingress_liveness_recovery")
			registration := IngressRegistration{
				IngressID: "recovering-ingress", IngressRunID: "same-run",
				ProtocolVersion: 1, ConnectionCapacity: 10,
			}
			lease, err := database.RegisterIngress(t.Context(), registration, now, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			at := lease.LeaseExpiresAt
			if !lease.ServingUntil.After(at) {
				t.Fatal("fixture did not separate ingress liveness from serving authority")
			}
			var recovered IngressLease
			if operation == "renew" {
				recovered, err = database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: lease.IngressLeaseIdentity}, at, 10*time.Second)
			} else {
				recovered, err = database.RegisterIngress(t.Context(), registration, at, 10*time.Second)
			}
			if err != nil || recovered.Draining || recovered.IngressLeaseIdentity != lease.IngressLeaseIdentity ||
				!recovered.RegisteredAt.Equal(lease.RegisteredAt) || !recovered.RenewedAt.Equal(at) ||
				!recovered.LeaseExpiresAt.Equal(at.Add(10*time.Second)) ||
				!recovered.ServingUntil.Equal(at.Add(database.servingTolerance())) {
				t.Fatal("nondraining liveness recovery lost the existing process or its separate authority", recovered, err)
			}
			before := ingressDrainSnapshot(t, database, registration.IngressID)
			if operation == "renew" {
				_, err = database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: recovered.IngressLeaseIdentity}, recovered.ServingUntil, 10*time.Second)
			} else {
				_, err = database.RegisterIngress(t.Context(), registration, recovered.ServingUntil, 10*time.Second)
			}
			if !errors.Is(err, ErrIngressLeaseStale) {
				t.Error("actual ingress serving expiry revived the same process", err)
			}
			if ingressDrainSnapshot(t, database, registration.IngressID) != before {
				t.Error("refused expired recovery changed serving authority or the process fence")
			}
		})
	}
}
