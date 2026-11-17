package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationConfigureServiceClosureSettlesCertificateAndRecovery(t *testing.T) {
	for _, operation := range []string{"target_trust", "visitor_tls"} {
		t.Run(operation, func(t *testing.T) {
			f := publicServingFixture(t, newServicePublicationFixture(t))
			d, ctx := f.database, t.Context()
			actor := f.actor(t)
			prepareServingPublisher(t, f)
			sibling := f.sibling(t, "unaffected", f.now)
			sibling.start(t, "unaffected", f.now)
			ingress := registerServingIngress(t, f, "configure-recovery", f.now)
			work := createPlanIssuanceWork(t, d, f.now, f.run, f.prepared.CertificatePlan, false, nil)
			at := f.now.Add(time.Second)
			claimed, found, err := d.ClaimACMEOrderWork(ctx, "configure-in-flight", at, time.Minute)
			if err != nil || !found || claimed.ID != work.ID {
				t.Fatal("claim unfinished service certificate", found, err)
			}
			slot := f.run.Connections[0]
			lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err := d.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID,
				f.run.RunID, f.run.RunNumber, slot.Revision, lease, at, true); err != nil {
				t.Fatal(err)
			}
			capturedAt := f.now.Add(2 * time.Second)
			admission, err := readIngressServiceRun(ctx, d, ingress, f.service.ID, f.run.RunID, capturedAt)
			if err != nil || admission.RecoveryEpisodeID == nil || len(admission.Relays) != 1 {
				t.Fatal("surviving HTTP relay omitted recovery", err)
			}
			visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			evidence := recoverySourceEvidence(t, admission, visitor, capturedAt)
			episodeID := *admission.RecoveryEpisodeID
			declaration, digest, err := d.GetServiceConfiguration(ctx, f.service.ID, actor)
			if err != nil || declaration == nil {
				t.Fatal("read saved HTTP configuration", err)
			}
			metadata := f.service.ServiceMetadata
			if operation == "target_trust" {
				declaration.TargetTLS = appliedTargetTrust(t, "replacement.internal")
				metadata.TLS, err = appliedServiceTargetTrust(declaration.TargetTLS)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				declaration.RequirePostQuantum = new(true)
			}
			closedAt := f.now.Add(3 * time.Second)
			updated, err := d.ConfigureService(ctx, f.service.ID, actor, metadata, declaration,
				ServiceUpdateConditions{ConfigurationDigest: digest}, closedAt)
			if err != nil {
				t.Fatal("configure HTTP service", err)
			}
			wantTrust := f.service.TrustRevision
			if operation == "target_trust" {
				wantTrust++
			}
			if updated.ID != f.service.ID || updated.TrustRevision != wantTrust || updated.EndpointRevision != f.service.EndpointRevision {
				t.Fatal("settlement changed service identity or unrelated revisions", updated)
			}
			// the installed leaf's completed presentation and its replacement's
			// unfinished presentation both remain recorded, but neither is active.
			assertServiceCertificateRetired(t, d, claimed, closedAt, 2)
			var closed, siblingOpen, canceled, observed bool
			var settledAt time.Time
			if err := d.pool.QueryRow(ctx, `SELECT run.state='closed' AND run.closed_at IS NOT NULL,
				EXISTS(SELECT 1 FROM control.service_runs WHERE id=$2 AND closed_at IS NULL),
				episode.state='canceled' AND episode.canceled_at=run.closed_at AND run.closed_at>=$4,
				episode.observed_at IS NOT NULL,run.closed_at
				FROM control.service_runs run JOIN control.service_recovery_episodes episode ON episode.id=$3
				WHERE run.id=$1`, f.run.RunID, sibling.run.RunID, episodeID, closedAt).
				Scan(&closed, &siblingOpen, &canceled, &observed, &settledAt); err != nil || !closed || !siblingOpen || !canceled || observed {
				t.Fatal("configure skipped recovery settlement or closed another service", closed, siblingOpen, canceled, observed, err)
			}
			var before, after int64
			if err := d.pool.QueryRow(ctx, `SELECT observation_count FROM control.service_recovery_histogram WHERE id=1`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			deliveredAt := settledAt.Add(time.Second)
			if !claimed.WorkExpiresAt.After(deliveredAt) {
				t.Fatal("fixture exhausted the original certificate work lease")
			}
			if _, found, err := d.ClaimACMEOrderWork(ctx, "early-configure-cleanup", deliveredAt, time.Minute); err != nil || found {
				t.Fatal("configure cleanup overtook the in-flight worker's deadline", found, err)
			}
			ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
			if _, err := d.ObserveServiceRecovery(ctx, ingress, ref,
				visitor, uint64(episodeID), deliveredAt, evidence, deliveredAt); !errors.Is(err, ErrServiceRecoveryEpisodeStale) {
				t.Fatal("configured HTTP run accepted delayed recovery", err)
			}
			if err := d.pool.QueryRow(ctx, `SELECT observation_count FROM control.service_recovery_histogram WHERE id=1`).Scan(&after); err != nil || after != before {
				t.Fatal("configured HTTP run incremented the recovery histogram", after-before, err)
			}
			if _, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, deliveredAt,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("configured service retained old run authority", err)
			}
			if _, err := d.HeartbeatServiceRun(ctx, sibling.service.ID, sibling.run.RunID, sibling.run.Token, deliveredAt,
				ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
				t.Fatal("configure retired an unrelated service's authority", err)
			}
			cleanup, found, err := d.ClaimACMEOrderWork(ctx, "configure-cleanup", claimed.WorkExpiresAt, time.Minute)
			if err != nil || !found || cleanup.ID != claimed.ID || cleanup.State != ACMEOrderCanceled ||
				len(cleanup.Authorizations) != 1 || cleanup.Authorizations[0].State != ACMEAuthorizationCleaning {
				t.Fatal("configure lost deferred challenge cleanup", cleanup, found, err)
			}
		})
	}
}
