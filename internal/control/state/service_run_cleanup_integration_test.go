package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func preparedCleanupFixture(t *testing.T) servicePublicationFixture {
	t.Helper()
	f := newServicePublicationFixture(t)
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, f.now); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Second)
	var err error
	f.prepared, err = f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "cleanup-owned", f.now,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assertUnstartedCleanupRun(t *testing.T, f servicePublicationFixture, id, state string) {
	t.Helper()
	var unchanged bool
	err := f.database.pool.QueryRow(t.Context(), `SELECT run.state=$2
		AND run.started_at IS NULL AND run.run_token_digest IS NULL
		AND (run.closed_at IS NOT NULL)=($2='closed')
		AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=run.id)
		AND NOT EXISTS(SELECT 1 FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.start')
		FROM control.service_runs run WHERE run.id=$1`, id, state).Scan(&unchanged)
	if err != nil || !unchanged {
		t.Fatal("cleanup changed a never-started run's serving state, assignments, or audit", err)
	}
}

func TestIntegrationPreparedRunTokenOnlyAuthorizesCleanup(t *testing.T) {
	f := preparedCleanupFixture(t)
	p := f.prepared
	if _, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(p.Token)); err != nil {
		t.Fatal("preparation did not return its canonical cleanup credential", err)
	}
	assertUnstartedCleanupRun(t, f, p.RunID, "prepared")
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, p.RunID, p.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared token renewed serving authority", err)
	}
	csr := newTestIssuanceCSR(t, f)
	if _, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, p.RunID, p.Token,
		"https://acme.example.test/directory", "prepared-certificate", p.RunNumber, csr, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared token authorized certificate issuance", err)
	}
	if _, err := f.database.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID},
		p.RunID, p.RunNumber, p.Token, 0, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared token acquired serving policy", err)
	}
	if _, err := f.database.ListConnectorPeerPairs(t.Context(), f.service.ID, p.RunID, "", p.Token, f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("prepared token acquired connector work", err)
	}
	tx, err := f.database.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, selectionErr := selectRoutableServiceRun(t.Context(), tx, f.service.ID, "", f.now)
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(selectionErr, pgx.ErrNoRows) {
		t.Fatal("a prepared run was selected for visitor traffic", selectionErr)
	}
	assertUnstartedCleanupRun(t, f, p.RunID, "prepared")
	retry, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, p.IdempotencyKey, f.now,
		ServiceRunRequest{Metadata: f.service.ServiceMetadata})
	if err != nil || retry.Token != p.Token || retry.RunID != p.RunID || retry.RunNumber != p.RunNumber {
		t.Fatal("preparation replay changed the exact run credential or identity", err)
	}
	started, err := f.database.StartServiceRun(t.Context(), f.service.ID, p.RunID, p.RunNumber, f.publisher, f.now)
	if err != nil || started.Token != p.Token || len(started.Connections) != 2 {
		t.Fatal("Start changed the preparation credential or failed to allocate its ordinary assignments", err)
	}
	if _, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, p.RunID, p.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("the same token was unusable after authenticated Start", err)
	}
}

func TestIntegrationServicePreparationCleanupPreservesExclusionAndRunIdentity(t *testing.T) {
	f := preparedCleanupFixture(t)
	p := f.prepared
	wrong, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, p.RunID, wrong.String(), f.now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another credential closed the preparation", err)
	}
	assertUnstartedCleanupRun(t, f, p.RunID, "prepared")
	request := ServiceRunRequest{Metadata: f.service.ServiceMetadata}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "replacement", f.now.Add(90*time.Second), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("same-owner exclusion disappeared before exact cleanup", err)
	}
	for _, at := range []time.Time{f.now.Add(91 * time.Second), f.now.Add(92 * time.Second)} {
		if err := f.database.CloseServiceRun(t.Context(), f.service.ID, p.RunID, p.Token, at); err != nil {
			t.Fatal("exact preparation cleanup was not idempotent", err)
		}
	}
	assertUnstartedCleanupRun(t, f, p.RunID, "closed")
	if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, p.RunID, p.RunNumber, f.publisher, f.now.Add(93*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("Start revived an exactly closed preparation", err)
	}
	if _, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, p.IdempotencyKey, f.now.Add(93*time.Second), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a late preparation replay revived the canceled invocation", err)
	}
	next, err := f.database.PrepareServiceRun(t.Context(), f.service.ID, f.publisher, "replacement", f.now.Add(93*time.Second), request)
	if err != nil || next.RunID == p.RunID || next.RunNumber != p.RunNumber+1 || next.Token == p.Token {
		t.Fatal("replacement did not immediately receive its own run and credential", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, next.RunID, p.Token, f.now.Add(94*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old preparation token closed the replacement", err)
	}
	if err := f.database.CloseServiceRun(t.Context(), f.service.ID, p.RunID, p.Token, f.now.Add(94*time.Second)); err != nil {
		t.Fatal("late exact cleanup failed after replacement", err)
	}
	assertUnstartedCleanupRun(t, f, next.RunID, "prepared")
}

func TestIntegrationServiceRunTokenCleanupAfterRevocation(t *testing.T) {
	for _, phase := range []string{"prepared", "started"} {
		for _, revoke := range []string{"grant", "identity"} {
			t.Run(phase+"/"+revoke, func(t *testing.T) {
				f := preparedCleanupFixture(t)
				p := f.prepared
				if phase == "started" {
					started, err := f.database.StartServiceRun(t.Context(), f.service.ID, p.RunID, p.RunNumber, f.publisher, f.now)
					if err != nil || started.Token != p.Token {
						t.Fatal("Start changed the exact cleanup token", err)
					}
				}
				at := f.now.Add(time.Second)
				var err error
				if revoke == "grant" {
					err = f.database.RevokePublisherGrant(t.Context(), f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.actor(t), at)
				} else {
					err = f.database.RevokePublisherIdentity(t.Context(), f.service.TeamID, f.publisher.ID, f.actor(t), at)
				}
				if err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if err := f.database.CloseServiceRun(t.Context(), f.service.ID, p.RunID, p.Token, at); err != nil {
						t.Fatal("exact token could not confirm revoked run cleanup", err)
					}
				}
				wrong, _, err := credentials.NewServiceRunToken()
				if err != nil {
					t.Fatal(err)
				}
				if err := f.database.CloseServiceRun(t.Context(), f.service.ID, p.RunID, wrong.String(), at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("closed state bypassed exact-token authentication", err)
				}
				if phase == "prepared" {
					assertUnstartedCleanupRun(t, f, p.RunID, "closed")
				}
				if _, err := f.database.StartServiceRun(t.Context(), f.service.ID, p.RunID, p.RunNumber, f.publisher, at); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("revoked run was resurrected", err)
				}
			})
		}
	}
}

func TestIntegrationServiceRunTokenCleanupAfterSuspension(t *testing.T) {
	for _, phase := range []string{"prepared", "started"} {
		for _, closeFirst := range []bool{false, true} {
			name := phase + "/suspension"
			if closeFirst {
				name = phase + "/closed-before-suspension"
			}
			t.Run(name, func(t *testing.T) {
				f := preparedCleanupFixture(t)
				ctx, d, p := t.Context(), f.database, f.prepared
				if phase == "started" {
					if _, err := d.StartServiceRun(ctx, f.service.ID, p.RunID, p.RunNumber, f.publisher, f.now); err != nil {
						t.Fatal(err)
					}
				}
				closedAt := f.now.Add(time.Second)
				if closeFirst {
					if err := d.CloseServiceRun(ctx, f.service.ID, p.RunID, p.Token, closedAt); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := d.SetServiceEnabled(ctx, f.service.ID, f.actor(t), false, closedAt); err != nil {
					t.Fatal(err)
				}
				q := controlstatedb.New(d.pool)
				before, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: p.RunID, ServiceID: f.service.ID})
				if err != nil || before.State != "closed" || !before.ClosedAt.Valid {
					t.Fatal("suspension did not close the run", err)
				}
				wrong, _, err := credentials.NewServiceRunToken()
				if err != nil {
					t.Fatal(err)
				}
				if err := d.CloseServiceRun(ctx, f.service.ID, p.RunID, wrong.String(), closedAt); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("suspension bypassed exact-token authentication", err)
				}
				for range 2 {
					if err := d.CloseServiceRun(ctx, f.service.ID, p.RunID, p.Token, closedAt.Add(time.Second)); err != nil {
						t.Fatal("exact token could not confirm suspended run cleanup", err)
					}
				}
				run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: p.RunID, ServiceID: f.service.ID})
				if err != nil || !reflect.DeepEqual(run, before) {
					t.Fatal("cleanup retry changed the terminal run", err)
				}
				if _, err := d.StartServiceRun(ctx, f.service.ID, p.RunID, p.RunNumber, f.publisher, closedAt); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("suspended run was resurrected", err)
				}
				if _, err := d.SetServiceEnabled(ctx, f.service.ID, f.actor(t), true, closedAt); err != nil {
					t.Fatal(err)
				}
				if _, err := d.StartServiceRun(ctx, f.service.ID, p.RunID, p.RunNumber, f.publisher, closedAt); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("enabling the service resurrected its closed run", err)
				}
				next, err := d.PrepareServiceRun(ctx, f.service.ID, f.publisher, "after-suspension", closedAt,
					ServiceRunRequest{Metadata: f.service.ServiceMetadata})
				if err != nil || next.RunID == p.RunID || next.RunNumber != p.RunNumber+1 {
					t.Fatal("enabled service did not prepare a fresh run", err)
				}
				if err := d.CloseServiceRun(ctx, f.service.ID, next.RunID, p.Token, closedAt); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("old token closed the replacement", err)
				}
				if err := d.CloseServiceRun(ctx, f.service.ID, p.RunID, p.Token, closedAt); err != nil {
					t.Fatal("late exact cleanup failed after replacement", err)
				}
				assertUnstartedCleanupRun(t, f, next.RunID, "prepared")
				if phase == "prepared" {
					assertUnstartedCleanupRun(t, f, p.RunID, "closed")
				}
			})
		}
	}
}
