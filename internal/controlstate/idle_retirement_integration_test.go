package controlstate

import (
	"testing"
	"time"
)

func TestIntegrationSavedURLIdleRecoveryAndKeep(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "idle_recovery")
	seedControlPublicURL(t, database, now, "idle_recovery")
	const routeID = "public_url_idle_recovery"
	get := func() PublicURL {
		t.Helper()
		route, err := database.GetPublicURL(t.Context(), "identity_idle_recovery", routeID)
		if err != nil {
			t.Fatal(err)
		}
		return route
	}
	for _, at := range []time.Time{now.Add(179 * 24 * time.Hour), now.Add(180 * 24 * time.Hour)} {
		if _, err := database.RetireIdlePublicURLs(t.Context(), at); err != nil {
			t.Fatal(err)
		}
	}
	route := get()
	if route.IdleRecoveryUntil == nil || !route.IdleRecoveryUntil.Equal(now.Add(210*24*time.Hour)) {
		t.Fatalf("recovery deadline = %+v", route.IdleRecoveryUntil)
	}
	kept := true
	route, err := database.UpdateAuthorizedPublicURL(t.Context(), AuthorizedPublicURLUpdateRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: "identity_idle_recovery",
		Target: route.Target, AllowedIPPrefixes: []string{}, PolicyRevision: 1, ExpectedMutationRevision: route.MutationRevision,
		Kept: &kept,
	}, now.Add(181*24*time.Hour))
	if err != nil || !route.Kept || route.IdleRecoveryUntil != nil {
		t.Fatalf("kept public URL = %+v, %v", route, err)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(360*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("kept public URL retired: %d, %v", count, err)
	}
	kept = false
	route, err = database.UpdateAuthorizedPublicURL(t.Context(), AuthorizedPublicURLUpdateRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: "identity_idle_recovery",
		Target: route.Target, AllowedIPPrefixes: []string{}, PolicyRevision: 1, ExpectedMutationRevision: route.MutationRevision,
		Kept: &kept,
	}, now.Add(361*24*time.Hour))
	if err != nil || route.Kept {
		t.Fatalf("automatic retirement = %+v, %v", route, err)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(362*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("recovery restart = %d, %v", count, err)
	}
	if route = get(); route.IdleRecoveryUntil == nil || !route.IdleRecoveryUntil.Equal(now.Add(392*24*time.Hour)) {
		t.Fatalf("fresh recovery deadline = %+v", route.IdleRecoveryUntil)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(391*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("early retirement = %d, %v", count, err)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(392*24*time.Hour)); err != nil || count != 1 {
		t.Fatalf("completed retirement = %d, %v", count, err)
	}
	var state, dns string
	if err := database.pool.QueryRow(t.Context(), `SELECT lifecycle_state, dns_state FROM control.public_urls WHERE id = $1`, routeID).Scan(&state, &dns); err != nil || state != "deleted" || dns != "removing" {
		t.Fatalf("retired public URL state = %q, DNS %q, err %v", state, dns, err)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(393*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("repeated retirement = %d, %v", count, err)
	}
}

func TestIntegrationPublishingResetsIdleRecovery(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "idle_resume")
	seedControlPublicURL(t, database, now, "idle_resume")
	const routeID = "public_url_idle_resume"
	if _, err := database.RetireIdlePublicURLs(t.Context(), now.Add(savedURLIdlePeriod)); err != nil {
		t.Fatal(err)
	}
	insertTestPublishRun(t, database, testPublishRun{
		ID: "publish_run_idle_resume", PublicURLID: routeID,
		TeamID: "team_idle_resume", ActingIdentityID: "identity_idle_resume",
		CertificateCacheKey: "route-idle-resume.example.test", CertificateScope: "route-idle-resume.example.test",
		CertificateIdentifiers: []string{"route-idle-resume.example.test"}, ChallengeMethod: "tls-alpn-01",
		CreatedAt: now.Add(181 * 24 * time.Hour), ExpiresAt: now.Add(220 * 24 * time.Hour),
	})
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(211*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("unclosed publish run retired: %d, %v", count, err)
	}
	closedAt := now.Add(212 * 24 * time.Hour)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs
SET state = 'closed', closed_at = $1, close_reason = 'publisher_closed'
WHERE id = 'publish_run_idle_resume'`, closedAt); err != nil {
		t.Fatal(err)
	}
	if count, err := database.RetireIdlePublicURLs(t.Context(), now.Add(213*24*time.Hour)); err != nil || count != 0 {
		t.Fatalf("resumed public URL retired: %d, %v", count, err)
	}
	route, err := database.GetPublicURL(t.Context(), "identity_idle_resume", routeID)
	if err != nil || route.IdleRecoveryUntil != nil || route.LifecycleState != PublicURLLifecycleEnabled {
		t.Fatalf("resumed public URL = %+v, %v", route, err)
	}
	if _, err := database.RetireIdlePublicURLs(t.Context(), closedAt.Add(savedURLIdlePeriod)); err != nil {
		t.Fatal(err)
	}
	route, err = database.GetPublicURL(t.Context(), "identity_idle_resume", routeID)
	if err != nil || route.IdleRecoveryUntil == nil || !route.IdleRecoveryUntil.Equal(closedAt.Add(savedURLIdlePeriod+savedURLRecoveryPeriod)) {
		t.Fatalf("second idle period = %+v, %v", route, err)
	}
}

func TestIntegrationIdleDatabaseURLQuarantinesPort(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "idle_database")
	request := builtinRouteRequest(t, database, now)
	if err := database.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", []int32{5432}, now); err != nil {
		t.Fatal(err)
	}
	request.Target, request.ServiceProtocol = "", PublicURLServicePostgres
	route, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || route.PublicPort == nil {
		t.Fatalf("saved database public URL = %+v, %v", route, err)
	}
	for _, at := range []time.Time{now.Add(savedURLIdlePeriod), now.Add(savedURLIdlePeriod + savedURLRecoveryPeriod)} {
		if _, err := database.RetireIdlePublicURLs(t.Context(), at); err != nil {
			t.Fatal(err)
		}
	}
	capacities, err := database.TCPPortPoolCapacities(t.Context())
	if err != nil || len(capacities) != 1 || capacities[0].ClaimedPorts != 0 || capacities[0].QuarantinedPorts != 1 {
		t.Fatalf("retired database port capacity = %+v, %v", capacities, err)
	}
}
