package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationServicePoolManagementRestoration(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	ctx := t.Context()
	metadata := ServiceMetadata{Protocol: "http", PublisherPool: true}
	configuration := &ProjectServiceConfiguration{Target: "http://127.0.0.1:3000"}
	service, err := d.CreateServiceAt(ctx, team.ID, owner, "pool-management", "pool-management-create",
		ServicePlacement{}, now, metadata, configuration)
	if err != nil {
		t.Fatal(err)
	}
	leases := make(map[string]RelayLease)
	for _, name := range []string{"pool-management-a", "pool-management-b"} {
		registration := relayLifecycleRegistration(name)
		registration.ConnectionCapacity = 100
		lease, err := d.RegisterRelay(ctx, registration, now, 48*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	var runs [2]poolRunFixture
	for index := range runs {
		enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: team.ID, ActingIdentityID: owner},
			PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, now)
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "pool-management", now,
			ServiceRunRequest{Metadata: service.ServiceMetadata})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
		if err != nil {
			t.Fatal(err)
		}
		installPrivateTestCertificate(t, d, prepared, run, now)
		readyPoolServiceRun(t, d, run, leases, now)
		runs[index] = poolRunFixture{publisher: publisher, prepared: prepared, run: run}
	}
	assertReadyPool := func(t *testing.T) {
		t.Helper()
		var total, publishers, ready, slots int
		if err := d.pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT publisher_identity_id),
			count(*) FILTER(WHERE state='ready' AND healthy AND closed_at IS NULL
				AND certificate_expires_at>$2 AND publisher_expires_at>$2),
			(SELECT count(*) FROM control.service_connection_slots
				WHERE service_id=$1 AND state='ready' AND session_open)
			FROM control.service_runs WHERE service_id=$1`, service.ID, now).Scan(&total, &publishers, &ready, &slots); err != nil ||
			total != 2 || publishers != 2 || ready != 2 || slots != 4 {
			t.Fatal("management probes require two distinct ready publishers with both slots", total, publishers, ready, slots, err)
		}
	}
	assertReadyPool(t)
	assertService := func(t *testing.T, got ServiceRecord) {
		t.Helper()
		// recovery is a local receipt flag, not a different saved service.
		got.Recovered = false
		if !reflect.DeepEqual(got, service) {
			t.Fatal("pooled management lookup changed or duplicated the saved service", got)
		}
	}
	snapshot := func(t *testing.T) string {
		t.Helper()
		var saved string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
			(SELECT to_jsonb(service) FROM control.services service WHERE id=$1),
			(SELECT jsonb_agg(to_jsonb(run) ORDER BY id) FROM control.service_runs run WHERE service_id=$1),
			(SELECT jsonb_agg(to_jsonb(slot) ORDER BY publisher_connection_id)
				FROM control.service_connection_slots slot WHERE service_id=$1))::text`, service.ID).Scan(&saved); err != nil {
			t.Fatal(err)
		}
		return saved
	}
	t.Run("identity inventory", func(t *testing.T) {
		page, next, err := d.ListAvailableServices(ctx, owner, "", "connector", now)
		if err != nil || len(page) != 1 || next != "" || page[0].ID != service.ID ||
			page[0].ServiceRunID != runs[0].run.RunID && page[0].ServiceRunID != runs[1].run.RunID {
			t.Fatal("identity inventory assumed one publisher or duplicated the service", page, next, err)
		}
	})
	t.Run("team management list", func(t *testing.T) {
		page, next, err := d.ListServices(ctx, team.ID, owner, "")
		if err != nil || len(page) != 1 || next != "" {
			t.Fatal("team management list assumed one publisher", page, next, err)
		}
		assertService(t, page[0])
	})
	t.Run("management get", func(t *testing.T) {
		got, err := d.GetService(ctx, service.ID, owner)
		if err != nil {
			t.Fatal("management get assumed one publisher", err)
		}
		assertService(t, got)
	})
	t.Run("exact hostname selection", func(t *testing.T) {
		// current hostname selection is a reservation, not a retired url lookup.
		got, err := d.CreateServiceAt(ctx, team.ID, owner, service.Name, "pool-management-hostname",
			ServicePlacement{Reserve: true, DomainID: service.DomainID, Hostname: service.Endpoint.Hostname},
			now, metadata, configuration)
		if err != nil || !got.Recovered {
			t.Fatal("exact hostname selection assumed one publisher or allocated again", err)
		}
		assertService(t, got)
	})
	t.Run("original creation retry", func(t *testing.T) {
		before := snapshot(t)
		got, err := d.CreateServiceAt(ctx, team.ID, owner, service.Name, "pool-management-create",
			ServicePlacement{}, now, metadata, configuration)
		if err != nil {
			t.Fatal("original creation retry assumed one publisher", err)
		}
		assertService(t, got)
		if snapshot(t) != before {
			t.Fatal("creation retry changed the saved service, runs, or slots")
		}
	})
	t.Run("visitor is not a manager", func(t *testing.T) {
		member := addAuthorityMember(t, d, now, owner, team.ID, "pool-visitor", TeamRoleMember)
		page, next, err := d.ListAvailableServices(ctx, member.IdentityID, "", "connector", now)
		if err != nil || len(page) != 0 || next != "" {
			t.Fatal("membership alone granted pooled visitor discovery", page, next, err)
		}
		if _, err := d.CreateServiceGrant(ctx, service.ID, owner, "pool-visitor", "identity", member.IdentityID, nil, now); err != nil {
			t.Fatal(err)
		}
		page, next, err = d.ListAvailableServices(ctx, member.IdentityID, "", "connector", now)
		if err != nil || len(page) != 1 || next != "" || page[0].ID != service.ID {
			t.Fatal("explicit pooled visitor grant lost exact service discovery", page, next, err)
		}
		if records, next, err := d.ListServices(ctx, team.ID, member.IdentityID, ""); !errors.Is(err, ErrServiceAccess) ||
			len(records) != 0 || next != "" {
			t.Fatal("visitor grant became team management listing authority", records, next, err)
		}
		if got, err := d.GetService(ctx, service.ID, member.IdentityID); !errors.Is(err, ErrServiceAccess) || got.ID != "" {
			t.Fatal("visitor grant became saved-service management authority", got, err)
		}
	})
	t.Run("one active publisher constraint", func(t *testing.T) {
		before := snapshot(t)
		// clone otherwise valid authority with fresh run identity and retry keys.
		// an in-place publisher swap could fail on the sibling's signing-key foreign key.
		_, err := d.pool.Exec(ctx, `INSERT INTO control.service_runs (
			id,service_id,team_id,guest_id,protocol,run_number,
			publisher_identity_id,publisher_grant_id,publisher_key_id,idempotency_key,request_digest,
			preparation_expires_at,assignment_seed_ciphertext,assignment_seed_storage_key_id,
			state,traffic_limits,preferred_regions,certificate_cache_key,certificate_scope,
			certificate_identifiers,certificate_domain_id,certificate_hostname,certificate_namespace,
			require_post_quantum,created_at,publisher_expires_at)
			SELECT $2,service_id,team_id,guest_id,protocol,
				(SELECT max(run_number)+1 FROM control.service_runs WHERE service_id=$3),
				publisher_identity_id,publisher_grant_id,publisher_key_id,'pool-management-duplicate',request_digest,
				preparation_expires_at,assignment_seed_ciphertext,assignment_seed_storage_key_id,
				'prepared',traffic_limits,preferred_regions,certificate_cache_key,certificate_scope,
				certificate_identifiers,certificate_domain_id,certificate_hostname,certificate_namespace,
				require_post_quantum,created_at,publisher_expires_at
			FROM control.service_runs WHERE id=$1`, runs[0].run.RunID, mustOpaqueID(t, opaqueid.ServiceRunPrefix), service.ID)
		var violation *pgconn.PgError
		if !errors.As(err, &violation) || violation.Code != "23505" || violation.ConstraintName != "service_runs_active" ||
			violation.SchemaName != "control" || violation.TableName != "service_runs" {
			t.Errorf("duplicate active publisher must fail at control.service_runs_active (23505): %v", err)
		}
		if snapshot(t) != before {
			t.Error("failed duplicate publisher mutation changed the saved service, runs, or slots")
		}
	})
	assertReadyPool(t)
}
