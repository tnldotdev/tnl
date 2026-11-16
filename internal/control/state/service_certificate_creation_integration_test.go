package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

const creationTestDirectory = "https://acme.example.test/directory"

func certificateCreationSnapshot(t *testing.T, f servicePublicationFixture) string {
	t.Helper()
	var snapshot string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'orders',(SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM control.acme_orders o),
		'requests',(SELECT jsonb_agg(to_jsonb(r) ORDER BY idempotency_key) FROM control.service_certificate_requests r),
		'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY cursor) FROM control.service_audit_events a WHERE service_id=$1))::text`,
		f.service.ID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestIntegrationCertificateCreationRejectsWrongOrExpiredRunAuthority(t *testing.T) {
	for _, boundary := range []string{"token", "run-number", "expired-run"} {
		t.Run(boundary, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			csr := newTestIssuanceCSR(t, f)
			token, number, at := f.run.Token, f.run.RunNumber, f.now
			switch boundary {
			case "token":
				wrong, _, err := credentials.NewServiceRunToken()
				if err != nil {
					t.Fatal(err)
				}
				token = wrong.String()
			case "run-number":
				number++
			case "expired-run":
				at = f.run.ExpiresAt.Add(time.Second)
			}
			before := certificateCreationSnapshot(t, f)
			_, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, token,
				creationTestDirectory, "rejected-creation", number, csr, at)
			requireRestoredOnlyError(t, err, ErrServiceAccess)
			if certificateCreationSnapshot(t, f) != before {
				t.Fatal("denied certificate creation retained an order, request, or audit")
			}
		})
	}
}

func TestIntegrationCertificateCreationMaintenanceAllowsExactRecoveryNotNewWork(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, ctx := f.database, t.Context()
	csr, nextCSR := newTestIssuanceCSR(t, f), newTestIssuanceCSR(t, f)
	first, err := d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "before-pause", f.run.RunNumber, csr, f.now)
	if err != nil || !first.NewOrder {
		t.Fatal("initial creation did not create an order", err)
	}
	setServiceMaintenance(t, d, f.actor(t), MaintenanceControlCertificateIssuance, false, f.now)
	before := certificateCreationSnapshot(t, f)
	retry, err := d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "before-pause", f.run.RunNumber, csr, f.now)
	if err != nil || retry.ID != first.ID || retry.NewOrder || certificateCreationSnapshot(t, f) != before {
		t.Fatal("maintenance blocked exact recovery or repeated creation side effects", err)
	}
	_, err = d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "during-pause", f.run.RunNumber, nextCSR, f.now)
	if !errors.Is(err, ErrCertificateIssuanceGated) || certificateCreationSnapshot(t, f) != before {
		t.Fatal("paused creation committed new work or consumed its request", err)
	}
	setServiceMaintenance(t, d, f.actor(t), MaintenanceControlCertificateIssuance, true, f.now)
	next, err := d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "during-pause", f.run.RunNumber, nextCSR, f.now)
	if err != nil || !next.NewOrder || next.ID == first.ID {
		t.Fatal("paused request could not create its own order after resume", err)
	}
}

func TestIntegrationCertificateCreationRollsBackLateAuditFailure(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, ctx := f.database, t.Context()
	csr := newTestIssuanceCSR(t, f)
	before := certificateCreationSnapshot(t, f)
	for _, statement := range []string{
		`CREATE FUNCTION control.reject_certificate_creation_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			DECLARE orders bigint;
			BEGIN
				SELECT count(*) INTO orders FROM control.acme_orders
					WHERE service_run_id=NEW.run_id AND length(csr_der)>0;
				IF orders<>1 THEN
					RAISE EXCEPTION 'audit preceded certificate creation' USING ERRCODE='P0001';
				END IF;
				RAISE EXCEPTION 'late certificate creation audit failure'
					USING ERRCODE='23514',CONSTRAINT='reject_certificate_creation_audit',DETAIL='new order observed';
			END; $$`,
		`CREATE TRIGGER reject_certificate_creation_audit BEFORE INSERT ON control.service_audit_events
			FOR EACH ROW WHEN (NEW.event_type='certificate.issue') EXECUTE FUNCTION control.reject_certificate_creation_audit()`,
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	_, err := d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "audit-retry", f.run.RunNumber, csr, f.now)
	requireRestoredPostgresFailure(t, err, "23514", "reject_certificate_creation_audit", "new order observed")
	if certificateCreationSnapshot(t, f) != before {
		t.Fatal("failed certificate creation retained an order, request, or audit")
	}
	if _, err := d.pool.Exec(ctx, `DROP TRIGGER reject_certificate_creation_audit ON control.service_audit_events`); err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateServiceCertificateIssuance(ctx, f.service.ID, f.run.RunID, f.run.Token,
		creationTestDirectory, "audit-retry", f.run.RunNumber, csr, f.now)
	if err != nil || !created.NewOrder {
		t.Fatal("late audit failure consumed the issuance request or CSR", err)
	}
}
