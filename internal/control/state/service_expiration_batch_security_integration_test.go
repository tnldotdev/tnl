package state

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestIntegrationEphemeralServiceExpirationExactBatchBound(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	for index := range 101 {
		name := fmt.Sprintf("ephemeral-%03d", index)
		if _, err := d.CreateServiceAt(t.Context(), team.ID, owner, name, name, ServicePlacement{}, now,
			ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Ephemeral: true}); err != nil {
			t.Fatal(err)
		}
	}
	permanent, err := d.CreateServiceAt(t.Context(), team.ID, owner, "permanent", "permanent", ServicePlacement{}, now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	at := now.Add(ephemeralServiceGracePeriod + time.Minute)
	for pass, want := range []int{100, 1, 0} {
		count, err := d.ExpireServiceRuns(t.Context(), at)
		if err != nil || count != want {
			t.Fatal("service expiry exceeded or lost its bounded remainder", pass, count, want, err)
		}
		expected := 100
		if pass > 0 {
			expected = 101
		}
		var deleted, audits, liveEndpoints int
		var exactAudits bool
		if err := d.pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM control.services WHERE team_id=$1 AND ephemeral AND deleted_at IS NOT NULL),
			(SELECT count(*) FROM control.service_audit_events WHERE team_id=$1 AND event_type='service.delete'),
			(SELECT count(*) FROM control.service_endpoints endpoint JOIN control.services service ON service.id=endpoint.service_id
				WHERE service.team_id=$1 AND service.ephemeral AND endpoint.retired_at IS NULL),
			NOT EXISTS(SELECT 1 FROM control.services service WHERE service.team_id=$1 AND service.ephemeral
				AND (SELECT count(*) FROM control.service_audit_events WHERE service_id=service.id AND event_type='service.delete')
					<> CASE WHEN service.deleted_at IS NULL THEN 0 ELSE 1 END)`, team.ID).
			Scan(&deleted, &audits, &liveEndpoints, &exactAudits); err != nil ||
			deleted != expected || audits != expected || liveEndpoints != 101-expected || !exactAudits {
			t.Fatal("bounded expiry lost tombstones, exact audits, or endpoint retirement", pass, deleted, audits, liveEndpoints, exactAudits, err)
		}
		if service, err := d.GetService(t.Context(), permanent.ID, owner); err != nil || !service.Enabled {
			t.Fatal("ephemeral cleanup changed a permanent service", err)
		}
	}
}

func TestIntegrationEphemeralServiceExpirationRechecksNewRunAfterDiscovery(t *testing.T) {
	d, now, owner, firstTeam := newAuthorityTeam(t)
	first, err := d.CreateServiceAt(t.Context(), firstTeam.ID, owner, "first-expiry", "first-expiry",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	// a second owner can prepare its run while expiry holds the first owner's
	// mutation guard. both services are idle when candidate discovery completes.
	other := "identity_expiry_other_owner"
	insertAuthorityIdentity(t, d, other, "", false, now)
	request := authorityTeamRequest(other)
	request.DisplayName = "expiry-other"
	team, err := d.CreateTeam(t.Context(), request, now)
	if err != nil || team.ID == firstTeam.ID {
		t.Fatal(err)
	}
	second, err := d.CreateServiceAt(t.Context(), team.ID, other, "second-expiry", "second-expiry", ServicePlacement{},
		now.Add(time.Second), ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3001", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	publisher, previous := adminPreparedRun(t, d, second, other, now.Add(2*time.Second))
	if err := d.CloseServiceRun(t.Context(), second.ID, previous.RunID, previous.Token, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	at := now.Add(ephemeralServiceGracePeriod + time.Minute)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	key := "tnl:test:security-service-expiry:" + first.ID
	for _, statement := range []string{
		`CREATE FUNCTION control.security_service_expiry_pause() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.id=TG_ARGV[0] THEN
					PERFORM pg_advisory_xact_lock(hashtextextended('tnl:test:security-service-expiry:'||NEW.id,0));
				END IF;
				RETURN NEW;
			END; $$`,
		fmt.Sprintf(`CREATE TRIGGER security_service_expiry_pause AFTER UPDATE OF deleted_at ON control.services
			FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
			EXECUTE FUNCTION control.security_service_expiry_pause('%s')`, first.ID),
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, key); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	type result struct {
		count int
		err   error
	}
	done, outcome := make(chan error, 1), make(chan result, 1)
	workers.Go(func() {
		count, err := d.ExpireServiceRuns(ctx, at)
		outcome <- result{count, err}
		done <- err
	})
	// this exact deletion can only run after both idle candidates have been
	// discovered. verify the real query and full advisory lock identities.
	waitForExpirationProgressAdvisory(t, ctx, d, int32(gate.Conn().PgConn().PID()),
		"ExclusiveLock", "ExclusiveLock", key, "-- name: DeleteService", done)
	current, err := d.PrepareServiceRun(ctx, second.ID, publisher, "after-discovery", at,
		ServiceRunRequest{Metadata: second.ServiceMetadata})
	if err != nil || current.RunNumber != previous.RunNumber+1 {
		t.Fatal("second owner could not prepare a fresh run after expiry discovery", err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	expired := <-outcome
	if expired.err != nil || expired.count != 1 {
		t.Fatal("stale idle discovery deleted the service with a newly prepared run", expired)
	}
	var retained bool
	if err := d.pool.QueryRow(ctx, `SELECT service.deleted_at IS NULL AND service.enabled
		AND run.closed_at IS NULL AND run.state='prepared'
		AND NOT EXISTS(SELECT 1 FROM control.service_audit_events WHERE service_id=service.id AND event_type='service.delete')
		AND EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=service.id AND retired_at IS NULL)
		AND EXISTS(SELECT 1 FROM control.services WHERE id=$2 AND deleted_at IS NOT NULL)
		AND (SELECT count(*)=1 FROM control.service_audit_events WHERE service_id=$2 AND event_type='service.delete')
		FROM control.services service JOIN control.service_runs run ON run.service_id=service.id WHERE run.id=$1`,
		current.RunID, first.ID).Scan(&retained); err != nil || !retained {
		t.Fatal("expiry failed to retain new preparation or commit only the idle neighbor", err)
	}
}
