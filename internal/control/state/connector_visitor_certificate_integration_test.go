package state

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationPrivateVisitorCertificateDeadline(t *testing.T) {
	f := newPublishRunFixture(t)
	d, now, ctx := f.database, f.now, t.Context()
	run := privateClaimRun(t, f)
	expires := now.Add(5 * time.Second)
	const directory = "https://acme.example.test/directory"
	if _, err := d.EnsureACMEAccount(ctx, directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := d.pool.QueryRow(ctx, `SELECT certificate_identifiers FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&names); err != nil {
		t.Fatal(err)
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := d.CreateServiceCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "certificate", run.RunNumber, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	// install a short deadline without waiting for an external CA exchange.
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET healthy=true,certificate_issuance_id=$3,certificate_expires_at=$2 WHERE id=$1`, run.RunID, expires, issuance.ID); err != nil {
		t.Fatal(err)
	}
	for _, slot := range run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	var identity string
	if err := d.pool.QueryRow(ctx, `SELECT created_by_identity_id FROM control.services WHERE id=$1`, run.ServiceID).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, identity, public, now)
	if err != nil {
		t.Fatal(err)
	}
	ingress, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "certificate", IngressRunID: "certificate-run", ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 8, IngressPoolID: PrimaryIngressPoolID,
		ConnectorAddress: "127.0.0.1:9443", ConnectorTLSServerName: "ingress.example.test"}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	session, err := d.CreateVisitorIngressAssignment(ctx, identity, device.ID, run.ServiceID, "", "certificate", now)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := tunnelv1.NewConnectorSessionNonce()
	if err != nil {
		t.Fatal(err)
	}
	hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", ServiceID: run.ServiceID, SessionID: session.ID,
		Credential: session.Credential, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: identity, DeviceID: device.ID}, Nonce: nonce}
	digest, err := hello.Claim().Digest()
	if err != nil {
		t.Fatal(err)
	}
	hello.Signature = ed25519.Sign(key, digest)
	source := netip.MustParseAddr("192.0.2.4")
	if _, err := d.AuthenticateVisitorConnector(ctx, ingress.IngressLeaseIdentity, hello.Claim(), source, now); err != nil {
		t.Fatal(err)
	}
	selection, err := d.SelectServiceRun(ctx, run.ServiceID, identity, device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if selection.ExpiresAt.After(expires) {
		t.Errorf("selection outlived service certificate: %v > %v", selection.ExpiresAt, expires)
	}
	request := StreamCapacityRequest{Owner: ingress.IngressLeaseIdentity, Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}, RunID: run.RunID, RunNumber: run.RunNumber, RequestID: "certificate", Capacity: 1}
	initial, err := d.AllocateStreamCapacity(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if initial.ValidUntil.After(expires) {
		t.Errorf("prepared capacity outlived service certificate: %v > %v", initial.ValidUntil, expires)
	}
	renewed, err := d.AllocateStreamCapacity(ctx, request, now.Add(time.Second))
	if err != nil || renewed.ValidUntil.After(expires) {
		t.Errorf("background capacity renewal ignored certificate deadline: %+v %v", renewed, err)
	}
	prepareVisitorTokenKeys(t, d, now)
	policy, err := d.ReadIngressVisitorPolicy(ctx, ingress.IngressLeaseIdentity, request.Scope, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	update, err := visitorlease.Decode(policy)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Pointer[time.Time]
	clock.Store(&now)
	local, err := visitorlease.New(request.Scope, func() time.Time { return *clock.Load() })
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	if err := local.Apply(local.Begin(), update); err != nil {
		t.Fatal(err)
	}
	header := tunnelv1.StreamReservation{ID: "sres_aaaaaaaaaaaaaaaaaaaaaa", AllocationID: initial.ID, Sequence: 1, ResourceKind: "service", ResourceID: run.ServiceID, RunID: run.RunID, RunNumber: uint64(run.RunNumber), VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", IngressID: ingress.IngressID, IngressRunID: ingress.IngressRunID, IngressLeaseRevision: ingress.IngressLeaseRevision}
	if err := local.ValidateReservation(header); err != nil {
		t.Fatal("current prepared reservation denied", err)
	}
	clock.Store(&expires)
	if err := local.ValidateReservation(header); err == nil {
		t.Fatal("current policy allowed capacity beyond the publisher certificate")
	}
	for _, expiry := range []any{nil, now} {
		if _, err := d.pool.Exec(ctx, `UPDATE control.service_runs SET certificate_expires_at=$2,certificate_issuance_id=CASE WHEN $2::timestamptz IS NULL THEN NULL ELSE $3 END WHERE id=$1`, run.RunID, expiry, issuance.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := d.SelectServiceRun(ctx, run.ServiceID, identity, device.ID, now); !errors.Is(err, ErrServiceRunUnavailable) {
			t.Errorf("missing/expired certificate selection = %v, want temporarily unavailable", err)
		}
		if _, err := d.AllocateStreamCapacity(ctx, request, now); err == nil {
			t.Error("missing/expired certificate renewed native capacity")
		}
	}
}
