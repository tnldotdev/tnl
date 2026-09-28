package controlstate

import (
	"testing"
	"time"
)

func TestIntegrationExpiredTLSChallengeCanBeClaimedWithoutIngress(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "expired_tls_challenge_claim")
	seedACMERoutingBarrierOrder(t, database, now)
	// The publisher continues heartbeating while ingress is unavailable. Keep
	// the publish run alive beyond the authorization's one-hour deadline.
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_expires_at = $1 WHERE id = 'session_acme_barrier'`, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A presented challenge without a forwarding projection must not be sent to
	// the CA. Its worker still needs a claim after expiry to retire the order.
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "before-expiry", now, time.Minute); err != nil || found {
		t.Fatalf("claim before routing is ready: found=%t error=%v", found, err)
	}
	for _, at := range []time.Time{now.Add(time.Hour + time.Second), now.Add(90 * time.Minute)} {
		work, found, err := database.ClaimACMEOrderWork(t.Context(), "expired-worker", at, time.Minute)
		if err != nil || !found || work.ID != "issuance_acme_barrier" || work.Authorizations[0].State != "presented" {
			t.Fatalf("expired challenge at %s cannot be retired: found=%t issuance=%q error=%v", at, found, work.ID, err)
		}
		if _, err := database.SaveACMEOrderWork(t.Context(), work, at); err != nil {
			t.Fatal(err)
		}
	}
}
