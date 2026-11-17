package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationControlOutageRunServingDeadlineIsDurableAndIndependent(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	if err := d.ConfigureControlOutageTolerance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, f.prepared, f.run, now, time.Hour)
	f.readyConnections(t, now)
	first, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	if !first.ServingUntil.Equal(now.Add(2*time.Minute)) || !first.ObservedAt.Equal(now) ||
		first.ExpiresAt.After(now.Add(45*time.Second)) {
		t.Fatal("serving allowance changed heartbeat detection", first)
	}
	var observed, saved time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT serving_observed_at,serving_until FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&observed, &saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Equal(first.ServingUntil) || !observed.Equal(first.ObservedAt) {
		t.Fatal("issued serving deadline was not persisted")
	}
	if count, err := d.ExpireServiceRuns(t.Context(), now.Add(50*time.Second)); err != nil || count != 0 {
		t.Fatal("liveness expiry destroyed existing serving authority", count, err)
	}
	policy, err := d.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		f.run.RunID, f.run.RunNumber, f.run.Token, 0, now.Add(50*time.Second))
	if err != nil || !policy.Policy.ValidUntil.Equal(first.ServingUntil) {
		t.Fatal("policy refresh still required the shorter publisher liveness", policy.Policy.ValidUntil, err)
	}
	recovered, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now.Add(time.Minute),
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || recovered.RunID != first.RunID || recovered.RunNumber != first.RunNumber ||
		!recovered.ServingUntil.Equal(now.Add(3*time.Minute)) {
		t.Fatal("recovery inside the allowance replaced or failed to renew the run", recovered, err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now.Add(3*time.Minute),
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired run authority was resurrected", err)
	}
}

func TestIntegrationControlOutageSettingChangesOnlyFutureConfirmations(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, f.prepared, f.run, now)
	f.readyConnections(t, now)
	if err := d.ConfigureControlOutageTolerance(8 * time.Second); err != nil {
		t.Fatal(err)
	}
	first, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigureControlOutageTolerance(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	var saved time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT serving_until FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	if !saved.Equal(first.ServingUntil) {
		t.Fatal("setting mutation retroactively changed an issued grant")
	}
	policy, err := d.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		f.run.RunID, f.run.RunNumber, f.run.Token, 0, now.Add(time.Second))
	if err != nil || !policy.Policy.ValidUntil.Equal(now.Add(4*time.Second)) {
		t.Fatal("new policy did not capture the selected shorter allowance", policy, err)
	}
	next, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now.Add(time.Second),
		ServiceRunHealth{Healthy: true, StreamCapacity: 64})
	if err != nil || !next.ServingUntil.Equal(now.Add(4*time.Second)) {
		t.Fatal("new heartbeat did not capture the selected shorter allowance", next, err)
	}
}

func TestIntegrationControlOutageRoleDetectionStillPermitsFastReplacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "control_outage_roles")
	if err := d.ConfigureControlOutageTolerance(8 * time.Second); err != nil {
		t.Fatal(err)
	}
	registration := relayLifecycleRegistration("outage-roles")
	first, err := d.RegisterRelay(t.Context(), registration, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !first.LeaseExpiresAt.Equal(now.Add(time.Second)) || !first.ServingUntil.Equal(now.Add(8*time.Second)) {
		t.Fatal("serving allowance inflated role liveness", first)
	}
	renewed, err := d.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: first.RelayLeaseIdentity}, now.Add(2*time.Second), time.Second)
	if err != nil || renewed.RelayLeaseRevision != first.RelayLeaseRevision {
		t.Fatal("same process could not recover before its serving deadline", renewed, err)
	}
	replacement := registration
	replacement.RelayRunID, _ = opaqueid.New(opaqueid.RelayRunPrefix)
	replaced, err := d.RegisterRelay(t.Context(), replacement, now.Add(4*time.Second), time.Second)
	if err != nil || replaced.RelayLeaseRevision <= renewed.RelayLeaseRevision {
		t.Fatal("serving allowance delayed dead-process replacement", replaced, err)
	}
	if _, err := d.RenewRelay(t.Context(), RelayRenewal{RelayLeaseIdentity: renewed.RelayLeaseIdentity}, now.Add(4*time.Second), time.Second); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatal("replaced process revived stale authority", err)
	}
}

func TestIntegrationControlOutageRetainsEarlierServicePublisherAndCertificateExpiry(t *testing.T) {
	for _, parent := range []string{"service", "publisher grant", "certificate"} {
		t.Run(parent, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			d, now := f.database, f.now
			if err := d.ConfigureControlOutageTolerance(2 * time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			lifetime := time.Hour
			if parent == "certificate" {
				lifetime = 7 * time.Second
			}
			installPrivateTestCertificate(t, d, f.prepared, f.run, now, lifetime)
			until := now.Add(7 * time.Second)
			switch parent {
			case "service":
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.services SET expires_at=$2 WHERE id=$1`, f.service.ID, until); err != nil {
					t.Fatal(err)
				}
			case "publisher grant":
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, f.publisher.GrantID, until); err != nil {
					t.Fatal(err)
				}
			}
			f.readyConnections(t, now)
			for _, at := range []time.Time{now, now.Add(time.Second)} {
				heartbeat, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at,
					ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				if err != nil || !heartbeat.ServingUntil.Equal(until) {
					t.Fatal("operator allowance replaced an earlier actual expiry", heartbeat.ServingUntil, until, err)
				}
				policy, err := d.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
					f.run.RunID, f.run.RunNumber, f.run.Token, 0, at)
				if err != nil || !policy.Policy.ValidUntil.Equal(until) {
					t.Fatal("publisher policy escaped its earlier parent expiry", policy.Policy.ValidUntil, until, err)
				}
			}
			if _, err := d.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, until,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("expired parent retained serving authority", err)
			}
		})
	}
}
