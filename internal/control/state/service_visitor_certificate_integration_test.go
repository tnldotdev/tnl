package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationPrivateVisitorCertificateDeadline(t *testing.T) {
	f := newNativePairFixture(t)
	d, now, ctx := f.d, f.now, f.visitor
	var issuance string
	if err := d.pool.QueryRow(ctx, `SELECT certificate_issuance_id FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&issuance); err != nil {
		t.Fatal(err)
	}
	expires := now.Add(5 * time.Second)
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, f.run.RunID, expires); err != nil {
		t.Fatal(err)
	}
	selection, err := d.SelectServiceRun(ctx, f.run.ServiceID, f.request.Subject.IdentityID, f.request.Subject.DeviceID, now)
	if err != nil || selection.ExpiresAt.After(expires) {
		t.Fatal("selection outlived service certificate", err)
	}
	pair := f.create(t)
	if pair.ExpiresAt.After(expires) {
		t.Fatal("native preparation outlived service certificate")
	}
	for slot := range pair.Relays {
		f.claim(t, pair, slot, now)
	}
	delivery, err := d.DeliverNativePeerPair(ctx, pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, now)
	if err != nil || delivery.ExpiresAt.After(expires) {
		t.Fatal("installed native authority outlived service certificate", err)
	}
	// direct admission has the same certificate boundary, without a native session.
	var port int
	if err := d.pool.QueryRow(ctx, `UPDATE control.services SET public=true WHERE id=$1 RETURNING service_port`, pair.ServiceID).Scan(&port); err != nil {
		t.Fatal(err)
	}
	lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "certificate", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	admit := func() (DirectVisitorAdmission, error) {
		return d.AdmitDirectServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, port, netip.MustParseAddr("192.0.2.4"), now)
	}
	initial, err := admit()
	if err != nil || initial.ExpiresAt.After(expires) {
		t.Fatal("initial direct admission outlived service certificate", err)
	}
	for _, expiry := range []any{nil, now} {
		if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2,certificate_issuance_id=CASE WHEN $2::timestamptz IS NULL THEN NULL ELSE $3 END WHERE id=$1`, pair.ServiceRunID, expiry, issuance); err != nil {
			t.Fatal(err)
		}
		if _, err := d.SelectServiceRun(ctx, pair.ServiceID, pair.Subject.IdentityID, pair.Subject.DeviceID, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("missing/expired certificate selected a native run", err)
		}
		if _, err := d.PrepareNativePeerPair(ctx, f.request, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("missing/expired certificate recovered native authority", err)
		}
		if _, err := d.DeliverNativePeerPair(ctx, pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("native recheck ignored missing/expired certificate", err)
		}
		if _, err := admit(); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("direct retry ignored missing/expired certificate", err)
		}
	}
}
