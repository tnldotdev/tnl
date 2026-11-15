package state

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationServiceRunDeadlineIncludesPublisherGrant(t *testing.T) {
	d, now, request, _, service := serviceReleaseProject(t, "tcp", false)
	ctx := t.Context()
	publisher := serviceReleasePublisher(t, d, request, now)
	deadline := now.Truncate(time.Microsecond).Add(20 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publisher.GrantID, deadline); err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "grant-expiry", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil || !prepared.ExpiresAt.Equal(deadline) {
		t.Fatal("preparation extended the publisher grant", prepared.ExpiresAt, err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil || !run.ExpiresAt.Equal(deadline) {
		t.Fatal("starting the run extended the publisher grant", run.ExpiresAt, err)
	}
	renewed, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 1})
	if err != nil || !renewed.ExpiresAt.Equal(deadline) {
		t.Fatal("publisher renewal extended its grant", renewed.ExpiresAt, err)
	}
}

func TestIntegrationServiceRunRejectsExpirationDuringDatabaseWait(t *testing.T) {
	for _, operation := range []string{"prepare", "recover", "start", "heartbeat"} {
		for _, boundary := range []string{"service", "grant"} {
			for _, gate := range []string{"admission", "write", "deferred"} {
				if operation == "recover" && gate != "admission" {
					continue
				}
				t.Run(operation+"/"+boundary+"/"+gate, func(t *testing.T) {
					d, now, request, _, service := serviceReleaseProject(t, "tcp", false)
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					workers := newIntegrationWorkers(t, cancel)
					defer workers.stop()
					publisher := serviceReleasePublisher(t, d, request, now)
					var prepared ServiceRunPreparation
					var run ServiceRunState
					var err error
					if operation != "prepare" {
						prepared, err = d.PrepareServiceRun(ctx, service.ID, publisher, "wait-expiry", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
						if err != nil {
							t.Fatal(err)
						}
					}
					if operation == "heartbeat" {
						run, err = d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
						if err != nil {
							t.Fatal(err)
						}
					}
					// the expiration is measured from operation entry below, not
					// from potentially slow fixture setup.
					deadline := now.Add(200 * time.Millisecond)
					query := `UPDATE control.services SET expires_at=$2 WHERE id=$1`
					id := service.ID
					if boundary == "grant" {
						query, id = `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publisher.GrantID
					}
					if _, err := d.pool.Exec(ctx, query, id, deadline); err != nil {
						t.Fatal(err)
					}
					snapshot := func() []byte {
						t.Helper()
						var data []byte
						if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
							'next',service.next_run_number,
							'runs',(SELECT COALESCE(jsonb_agg(to_jsonb(run) ORDER BY run.id),'[]'::jsonb) FROM control.service_runs run WHERE run.service_id=service.id),
							'slots',(SELECT COALESCE(jsonb_agg(to_jsonb(slot) ORDER BY slot.publisher_connection_id),'[]'::jsonb) FROM control.service_connection_slots slot WHERE slot.service_id=service.id))
							FROM control.services service WHERE service.id=$1`, service.ID).Scan(&data); err != nil {
							t.Fatal(err)
						}
						return data
					}
					before := snapshot()
					blocker, err := d.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer rollbackTestTransaction(t, blocker)
					if gate == "admission" {
						_, err = blocker.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, service.ID)
					} else {
						_, err = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(7381)`)
						if err == nil {
							trigger := `CREATE TRIGGER service_deadline_wait BEFORE INSERT OR UPDATE ON control.service_runs`
							if gate == "deferred" {
								trigger = `CREATE CONSTRAINT TRIGGER service_deadline_wait AFTER INSERT OR UPDATE ON control.service_runs DEFERRABLE INITIALLY DEFERRED`
							}
							_, err = d.pool.Exec(ctx, `CREATE FUNCTION control.service_deadline_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(7381); RETURN NEW; END $$; `+trigger+` FOR EACH ROW EXECUTE FUNCTION control.service_deadline_wait()`)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					entered := make(chan time.Time, 1)
					workers.Go(func() {
						entered <- time.Now()
						switch operation {
						case "prepare", "recover":
							_, err := d.PrepareServiceRun(ctx, service.ID, publisher, "wait-expiry", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
							done <- err
						case "start":
							_, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
							done <- err
						case "heartbeat":
							_, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 1})
							done <- err
						}
					})
					waitForPostgresBlock(t, ctx, d, int32(blocker.Conn().PgConn().PID()), done)
					started := awaitIntegrationResult(t, ctx, entered)
					timer := time.NewTimer(max(0, time.Until(started.Add(250*time.Millisecond))))
					defer timer.Stop()
					select {
					case <-timer.C:
					case <-ctx.Done():
						t.Fatal(context.Cause(ctx))
					}
					if err := blocker.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
						t.Fatal("database wait extended expired publication permission", err)
					}
					if !bytes.Equal(before, snapshot()) {
						t.Fatal("denied operation changed a run, connection assignment, or run number")
					}
				})
			}
		}
	}
}

func TestIntegrationServiceExpirationCannotBeExtendedByPublisherRenewal(t *testing.T) {
	d, now, request, _, service := serviceReleaseProject(t, "tcp", false)
	ctx := t.Context()
	deadline := now.Truncate(time.Microsecond).Add(20 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET expires_at=$2 WHERE id=$1`, service.ID, deadline); err != nil {
		t.Fatal(err)
	}
	publisher := serviceReleasePublisher(t, d, request, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "fixed-expiry", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil || !prepared.ExpiresAt.Equal(deadline) {
		t.Fatal("preparation extended the service deadline", prepared.ExpiresAt, err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil || !run.ExpiresAt.Equal(deadline) {
		t.Fatal("starting the run extended the service deadline", run.ExpiresAt, err)
	}
	health := ServiceRunHealth{Healthy: true, StreamCapacity: 1}
	renewed, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now.Add(time.Second), health)
	if err != nil || !renewed.ExpiresAt.Equal(deadline) {
		t.Fatal("publisher renewal extended the service deadline", renewed.ExpiresAt, err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, deadline, health); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("publisher renewed after service expiration", err)
	}
	if changed, err := d.ExpireServiceRuns(ctx, deadline); err != nil || changed != 2 {
		t.Fatal("expiration did not close the run and delete the service", changed, err)
	}
	var retired bool
	if err := d.pool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL AND NOT enabled FROM control.services WHERE id=$1`, service.ID).Scan(&retired); err != nil || !retired {
		t.Fatal("fixed-expiration service remained enabled", retired, err)
	}
	if _, err := d.PrepareServiceRun(ctx, service.ID, publisher, "after-expiry", deadline, ServiceRunRequest{Metadata: service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired service accepted another publication", err)
	}
}

func TestIntegrationEphemeralServiceCleanupKeepsSavedServicesAndWorktreeIdentity(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			ctx := t.Context()
			project := appliedProjectRequest(t, d, now)
			target := "127.0.0.1:3000"
			if protocol == "http" {
				target = "app"
			}
			request := RealizeLocalProjectServiceRequest{
				TeamID: project.TeamID, ActorID: project.ActorID, ProjectKey: project.ProjectKey,
				SourceFingerprint: project.SourceFingerprint, Service: "app", WorktreeKey: "ephemeral-worktree",
				Configuration: ProjectServiceConfiguration{Protocol: protocol, Target: target, Ephemeral: true}, Now: now,
			}
			ephemeral, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			record, err := d.GetService(ctx, ephemeral.ServiceID, project.ActorID)
			if err != nil {
				t.Fatal(err)
			}
			savedRequest := request
			savedRequest.Service, savedRequest.Configuration.Ephemeral = "saved", false
			saved, err := d.RealizeLocalProjectService(ctx, savedRequest)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.expireServices(ctx, record.CreatedAt.Add(ephemeralServiceGracePeriod-time.Microsecond)); err != nil {
				t.Fatal(err)
			}
			if _, err := d.GetService(ctx, ephemeral.ServiceID, project.ActorID); err != nil {
				t.Fatal("ephemeral service disappeared before its grace period", err)
			}
			expiration := record.CreatedAt.Add(ephemeralServiceGracePeriod)
			if err := d.expireServices(ctx, expiration); err != nil {
				t.Fatal(err)
			}
			if _, err := d.GetService(ctx, ephemeral.ServiceID, project.ActorID); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("idle ephemeral service remained available", err)
			}
			if _, err := d.GetService(ctx, saved.ServiceID, project.ActorID); err != nil {
				t.Fatal("ephemeral cleanup removed a saved service", err)
			}
			request.Now = expiration
			replacement, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || replacement.ServiceID == ephemeral.ServiceID || replacement.Hostname != ephemeral.Hostname {
				t.Fatal("ephemeral restart lost worktree identity or revived a deleted service", replacement, err)
			}
			request.Configuration.Ephemeral = false
			request.WorktreeKey = "other-worktree"
			other, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || other.ServiceID == replacement.ServiceID || other.Hostname == replacement.Hostname {
				t.Fatal("ephemeral restart let another worktree adopt its service", other, err)
			}
		})
	}
}

func TestIntegrationEphemeralServiceCleanupWaitsForTheLastClosedRun(t *testing.T) {
	d, now, request, _, service := serviceReleaseProject(t, "tcp", false)
	ctx := t.Context()
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET ephemeral=true WHERE id=$1`, service.ID); err != nil {
		t.Fatal(err)
	}
	publisher := serviceReleasePublisher(t, d, request, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "ephemeral-idle", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	closedAt := now.Truncate(time.Microsecond).Add(2 * ephemeralServiceGracePeriod)
	if err := d.expireServices(ctx, closedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(ctx, service.ID, request.ActorID); err != nil {
		t.Fatal("idle cleanup removed a service before its run closed", err)
	}
	if err := d.CloseServiceRun(ctx, service.ID, run.RunID, run.Token, closedAt); err != nil {
		t.Fatal(err)
	}
	// endpoint edits must not restart the idle grace period.
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET updated_at=$2 WHERE id=$1`, service.ID, closedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := d.expireServices(ctx, closedAt.Add(ephemeralServiceGracePeriod-time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(ctx, service.ID, request.ActorID); err != nil {
		t.Fatal("idle cleanup measured its grace period from service creation", err)
	}
	if err := d.expireServices(ctx, closedAt.Add(ephemeralServiceGracePeriod)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(ctx, service.ID, request.ActorID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("closed ephemeral service outlived its idle grace period", err)
	}
}
