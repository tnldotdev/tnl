package state

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationCertificateInstallRestoredNewerThenOlderAcknowledgment(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	d, q := f.database, controlstatedb.New(f.database.pool)
	// the existing helper submits a real CSR, signs a matching leaf, completes
	// authorizations, and persists work through the actual issuance worker API.
	older := createPlanIssuanceWork(t, d, f.now, f.run, f.prepared.CertificatePlan, true, nil)
	if older.NotAfter == nil {
		t.Fatal("older issuance has no certificate expiry")
	}
	if err := d.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token,
		older.ID, f.run.RunNumber, *older.NotAfter, f.now); err != nil {
		t.Fatal("valid older issuance could not install before the newer one", err)
	}
	newer := createPlanIssuanceWork(t, d, f.now.Add(time.Second), f.run, f.prepared.CertificatePlan, true, nil,
		planIssuanceOptions{lifetime: 48 * time.Hour})
	if newer.NotAfter == nil || newer.ID == older.ID || newer.NotAfter.Equal(*older.NotAfter) {
		t.Fatal("newer fixture did not create distinct issuance identity and expiry")
	}
	oldOrder, err := q.GetACMEOrder(ctx, older.ID)
	if err != nil {
		t.Fatal(err)
	}
	newOrder, err := q.GetACMEOrder(ctx, newer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if oldOrder.CreatedRevision >= newOrder.CreatedRevision || bytes.Equal(oldOrder.CsrDer, newOrder.CsrDer) ||
		oldOrder.ServiceRunID != f.run.RunID || newOrder.ServiceRunID != f.run.RunID ||
		oldOrder.ServiceID != f.service.ID || newOrder.ServiceID != f.service.ID {
		t.Fatal("anti-rollback fixture did not establish ordered same-publisher distinct CSRs")
	}
	for _, order := range []controlstatedb.ControlAcmeOrder{oldOrder, newOrder} {
		csr, err := x509.ParseCertificateRequest(order.CsrDer)
		if err != nil {
			t.Fatal(err)
		}
		if err := csr.CheckSignature(); err != nil {
			t.Fatal("issuance CSR signature is invalid", err)
		}
		if !validInstalledCertificate(order, f.service.Endpoint.Hostname, f.now.Add(2*time.Second)) {
			t.Fatal("issuance material was invalid before the ordering check")
		}
	}
	if err := d.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token,
		newer.ID, f.run.RunNumber, *newer.NotAfter, f.now.Add(time.Second)); err != nil {
		t.Fatal("valid newer issuance could not install", err)
	}
	var installed string
	var expires time.Time
	if err := d.pool.QueryRow(ctx, `SELECT certificate_issuance_id,certificate_expires_at
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&installed, &expires); err != nil ||
		installed != newer.ID || !expires.Equal(*newer.NotAfter) {
		t.Fatal("newer installation did not commit exact issuance and expiry", err)
	}
	before := restoredAssignmentSnapshot(t, ctx, d.pool, f.run.RunID)
	err = d.MarkServiceCertificateInstalled(ctx, f.service.ID, f.run.RunID, f.run.Token,
		older.ID, f.run.RunNumber, *older.NotAfter, f.now.Add(2*time.Second))
	requireRestoredOnlyError(t, err, ErrCertificateIssuanceInvalid)
	if after := restoredAssignmentSnapshot(t, ctx, d.pool, f.run.RunID); after != before {
		t.Fatal("late older installation changed stored run, expiry, slots, or audit")
	}
	if err := d.pool.QueryRow(ctx, `SELECT certificate_issuance_id,certificate_expires_at
		FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&installed, &expires); err != nil ||
		installed != newer.ID || !expires.Equal(*newer.NotAfter) {
		t.Fatal("late older acknowledgment replaced the newer issuance or expiry", err)
	}
	var installs int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events
		WHERE run_id=$1 AND event_type='certificate.install'`, f.run.RunID).Scan(&installs); err != nil || installs != 2 {
		t.Fatal("older rejection added an install audit or lost a valid install", installs, err)
	}
}
