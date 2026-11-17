package state

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func appliedCertificateRequest(e restoredCertificateEnvironment, project string, applied AppliedProjectConfiguration, now time.Time) ApplyProjectConfigurationRequest {
	return selectedProjectRequest(ApplyProjectConfigurationRequest{
		TeamID: e.team.ID, ActorID: e.actor, ProjectKey: project, ProjectLabel: project,
		SourceFingerprint: strings.Repeat("c", 64), DNSAutomation: true, Now: now,
		ExpectedRevision: applied.Revision, Configuration: applied.Configuration,
	}, "production")
}

func assertServiceCertificateRetired(t *testing.T, d *Database, claimed ACMEOrderWork, now time.Time, presentations int) {
	t.Helper()
	var closed bool
	var state, authorization, owner string
	var revision int64
	if err := d.pool.QueryRow(t.Context(), `SELECT run.closed_at IS NOT NULL,
		issuance.state,issuance.order_revision,COALESCE(issuance.work_owner,''),auth.state
		FROM control.service_runs run JOIN control.acme_orders issuance ON issuance.service_run_id=run.id
		JOIN control.acme_authorizations auth ON auth.order_id=issuance.id
		WHERE issuance.id=$1`, claimed.ID).Scan(&closed, &state, &revision, &owner, &authorization); err != nil {
		t.Fatal(err)
	}
	if !closed || state != "canceled" || authorization != "cleaning" ||
		uint64(revision) <= claimed.OrderRevision || owner != claimed.WorkerID {
		t.Fatal("closure did not settle the final certificate consumer", closed, state, authorization, revision, owner)
	}
	challenge, err := d.GetDNSChallengeContextForSubject(t.Context(), claimed.Subject, claimed.Authorizations[0].ID)
	if err != nil || challenge.State != ACMEAuthorizationCleaning || len(challenge.Presentations) != presentations {
		t.Fatal("closure retained a desired challenge presentation", challenge, err)
	}
	for _, presentation := range challenge.Presentations {
		if presentation.Active {
			t.Fatal("closure retained an active challenge presentation")
		}
	}
	if _, err := d.SaveACMEOrderWork(t.Context(), claimed, now); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatal("closure allowed a claimed worker to resume issuance", err)
	}
}

func TestIntegrationAppliedServiceClosureRetiresUnusedCertificateWork(t *testing.T) {
	for _, operation := range []string{"target", "visitor_tls", "remove_binding", "retire_project"} {
		t.Run(operation, func(t *testing.T) {
			e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
			applied, replica := e.deployment(t, "apply-closure", true, map[string]ProjectServiceConfiguration{
				"api": {Protocol: "http", Target: "localhost:3000", Public: new(true)},
			})
			f := e.startAssigned(t, replica, "api")
			work := createPlanIssuanceWork(t, e.database, e.now, f.run, f.prepared.CertificatePlan, false, nil)
			at := e.now.Add(time.Second)
			claimed, found, err := e.database.ClaimACMEOrderWork(t.Context(), "apply-in-flight", at, time.Minute)
			if err != nil || !found || claimed.ID != work.ID {
				t.Fatal("claim unfinished issuance", found, err)
			}
			if operation == "retire_project" {
				_, err = e.database.RetireProject(t.Context(), e.team.ID, "apply-closure", e.actor, applied.Revision, at)
			} else {
				request := appliedCertificateRequest(e, "apply-closure", applied, at)
				service := request.Configuration.Services["api"]
				switch operation {
				case "target":
					service.Target = "replacement.internal:8080"
				case "visitor_tls":
					service.RequirePostQuantum = new(true)
				}
				request.Configuration.Services["api"] = service
				if operation == "remove_binding" {
					delete(request.Configuration.Services, "api")
				}
				_, err = e.database.ApplyProjectConfiguration(t.Context(), request)
			}
			if err != nil {
				t.Fatal("apply closure", err)
			}
			assertServiceCertificateRetired(t, e.database, claimed, at, 1)
		})
	}
}

func TestIntegrationAppliedServiceClosureRetainsSiblingCertificateConsumer(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
	applied, replica := e.deployment(t, "apply-consumers", true, map[string]ProjectServiceConfiguration{
		"first":  {Protocol: "http", Target: "localhost:3000", Public: new(true)},
		"second": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
	})
	first := e.startAssigned(t, replica, "first")
	second := e.startAssigned(t, replica, "second")
	work := createPlanIssuanceWork(t, e.database, e.now, first.run, first.prepared.CertificatePlan, false, nil)
	at := e.now.Add(time.Second)
	claimed, found, err := e.database.ClaimACMEOrderWork(t.Context(), "shared-in-flight", at, time.Minute)
	if err != nil || !found || claimed.ID != work.ID {
		t.Fatal("claim shared issuance", found, err)
	}
	request := appliedCertificateRequest(e, "apply-consumers", applied, at)
	delete(request.Configuration.Services, "first")
	applied, err = e.database.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var firstClosed, siblingOpen bool
	if err := e.database.pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM control.service_runs WHERE id=$1 AND closed_at IS NOT NULL),
		EXISTS(SELECT 1 FROM control.service_runs WHERE id=$2 AND closed_at IS NULL)`,
		first.run.RunID, second.run.RunID).Scan(&firstClosed, &siblingOpen); err != nil || !firstClosed || !siblingOpen {
		t.Fatal("apply closed an unrelated sibling", firstClosed, siblingOpen, err)
	}
	retained, err := e.database.GetServiceCertificateIssuance(t.Context(), second.service.ID, second.run.RunID, second.run.Token, work.ID, at)
	if err != nil || retained.State != ACMEOrderAuthorizing {
		t.Fatal("apply canceled a legitimate sibling's shared certificate work", retained.State, err)
	}
	challenge, err := e.database.GetDNSChallengeContextForSubject(t.Context(), claimed.Subject, claimed.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || !challenge.Presentations[0].Active {
		t.Fatal("apply removed a sibling's desired challenge", challenge, err)
	}
	claimed, err = e.database.SaveACMEOrderWork(t.Context(), claimed, at)
	if err != nil {
		t.Fatal("apply fenced work still needed by a sibling", err)
	}
	// reclaim before closing the final sibling to prove its exact live revision
	// is fenced even though the issuance's originating run was already closed.
	claimed, found, err = e.database.ClaimACMEOrderWork(t.Context(), "shared-final-in-flight", at, time.Minute)
	if err != nil || !found {
		t.Fatal("reclaim shared issuance", found, err)
	}
	if _, err := e.database.RetireProject(t.Context(), e.team.ID, "apply-consumers", e.actor, applied.Revision, at); err != nil {
		t.Fatal(err)
	}
	assertServiceCertificateRetired(t, e.database, claimed, at, 1)
}

func TestIntegrationAppliedServiceClosureSettlesLocalTrustChange(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, true)
	request := projectServiceSelection(ApplyProjectConfigurationRequest{
		TeamID: e.team.ID, ActorID: e.actor, ProjectKey: "local-closure", ProjectLabel: "local-closure",
		SourceFingerprint: strings.Repeat("c", 64), DNSAutomation: true, Now: e.now,
		Configuration: ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
			"api": {Protocol: "http", Target: "localhost:3000", Public: new(true)},
		}},
	}, "local", "api")
	applied, err := e.database.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	local, err := e.database.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
		TeamID: e.team.ID, ActorID: e.actor, ProjectKey: request.ProjectKey, SourceFingerprint: request.SourceFingerprint,
		Service: "api", WorktreeKey: "checkout", DNSAutomation: true, Now: e.now, Configuration: request.Configuration.Services["api"],
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := e.database.GetService(t.Context(), local.ServiceID, e.actor)
	if err != nil {
		t.Fatal(err)
	}
	publisher, prepared := adminPreparedRun(t, e.database, service, e.actor, e.now)
	run, err := e.database.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, e.now)
	if err != nil {
		t.Fatal(err)
	}
	work := createPlanIssuanceWork(t, e.database, e.now, run, prepared.CertificatePlan, false, nil)
	at := e.now.Add(time.Second)
	claimed, found, err := e.database.ClaimACMEOrderWork(t.Context(), "local-in-flight", at, time.Minute)
	if err != nil || !found || claimed.ID != work.ID {
		t.Fatal("claim local issuance", found, err)
	}
	declaration := request.Configuration.Services["api"]
	declaration.Target, declaration.TargetTLS = "https://target.internal:3000", &ProjectTargetTLS{Hostname: "target.internal"}
	request.Configuration.Services["api"] = declaration
	request.ExpectedRevision, request.Now = applied.Revision, at
	if _, err := e.database.ApplyProjectConfiguration(t.Context(), request); err != nil {
		t.Fatal("apply local trust change", err)
	}
	assertServiceCertificateRetired(t, e.database, claimed, at, 1)
}

func TestIntegrationAppliedServiceClosureCancelsRecovery(t *testing.T) {
	for _, operation := range []string{"ordinary_close", "target", "visitor_tls", "remove_binding"} {
		t.Run(operation, func(t *testing.T) {
			f := newAppliedEndpointFixture(t, "http", true, true)
			ctx := t.Context()
			slot := f.run.Connections[0]
			lease := f.connector.leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err := f.d.DisconnectServicePublisherConnection(ctx, slot.PublisherConnectionID,
				f.run.RunID, f.run.RunNumber, slot.Revision, lease, f.now.Add(time.Second), true); err != nil {
				t.Fatal(err)
			}
			visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			capturedAt := f.now.Add(2 * time.Second)
			admission, err := readIngressServiceRun(ctx, f.d, f.ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, capturedAt)
			if err != nil || admission.RecoveryEpisodeID == nil || len(admission.Relays) != 1 {
				t.Fatal("surviving HTTP relay omitted the recovery episode", err)
			}
			evidence := recoverySourceEvidence(t, admission, visitor, capturedAt)
			episodeID := *admission.RecoveryEpisodeID
			closedAt := f.now.Add(3 * time.Second)
			if operation == "ordinary_close" {
				err = f.d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, closedAt)
			} else {
				request := f.nextRequest(t)
				request.Now = closedAt
				service := request.Configuration.Services["api"]
				if operation == "target" {
					service.Target = "replacement.internal:8080"
				} else if operation == "visitor_tls" {
					service.RequirePostQuantum = new(true)
				}
				request.Configuration.Services["api"] = service
				if operation == "remove_binding" {
					delete(request.Configuration.Services, "api")
				}
				_, err = f.d.ApplyProjectConfiguration(ctx, request)
			}
			if err != nil {
				t.Fatal("close recovering service", err)
			}
			var closed, siblingOpen, canceled, observed bool
			if err := f.d.pool.QueryRow(ctx, `SELECT run.state='closed' AND run.closed_at IS NOT NULL,
				EXISTS(SELECT 1 FROM control.service_runs WHERE id=$2 AND closed_at IS NULL),
				episode.state='canceled' AND episode.canceled_at=$4,episode.observed_at IS NOT NULL
				FROM control.service_runs run JOIN control.service_recovery_episodes episode ON episode.id=$3
				WHERE run.id=$1`, f.run.RunID, f.sibling.RunID, episodeID, closedAt).
				Scan(&closed, &siblingOpen, &canceled, &observed); err != nil || !closed || !siblingOpen || !canceled || observed {
				t.Fatal("closure skipped recovery settlement or closed a sibling", closed, siblingOpen, canceled, observed, err)
			}
			var before, after int64
			if err := f.d.pool.QueryRow(ctx, `SELECT observation_count FROM control.service_recovery_histogram WHERE id=1`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			deliveredAt := closedAt.Add(time.Second)
			ref := ServiceRunReference{ServiceID: f.service.ID, RunID: f.run.RunID, RunNumber: f.run.RunNumber}
			if _, err := f.d.ObserveServiceRecovery(ctx, f.ingress.IngressLeaseIdentity, ref,
				visitor, uint64(episodeID), deliveredAt, evidence, deliveredAt); !errors.Is(err, ErrServiceRecoveryEpisodeStale) {
				t.Fatal("closed HTTP run accepted a delayed recovery report", err)
			}
			if err := f.d.pool.QueryRow(ctx, `SELECT observation_count FROM control.service_recovery_histogram WHERE id=1`).Scan(&after); err != nil || after != before {
				t.Fatal("closed HTTP run incremented the recovery histogram", after-before, err)
			}
		})
	}
}
