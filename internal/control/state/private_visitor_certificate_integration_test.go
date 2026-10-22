package controlstate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	if err := d.pool.QueryRow(ctx, `SELECT certificate_identifiers FROM control.private_service_runs WHERE id=$1`, run.RunID).Scan(&names); err != nil {
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
	issuance, err := d.CreatePrivateCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "certificate", run.RunNumber, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	// install a short deadline without waiting for an external CA exchange.
	if _, err := d.pool.Exec(ctx, `UPDATE control.private_service_runs SET healthy=true,certificate_issuance_id=$3,certificate_expires_at=$2 WHERE id=$1`, run.RunID, expires, issuance.ID); err != nil {
		t.Fatal(err)
	}
	for _, slot := range run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimPrivatePublisherConnection(ctx, slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyPrivatePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	var identity string
	if err := d.pool.QueryRow(ctx, `SELECT created_by_identity_id FROM control.private_services WHERE id=$1`, run.ServiceID).Scan(&identity); err != nil {
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
	ingress, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "certificate", IngressRunID: "certificate-run", ProtocolVersion: 1, ConnectionCapacity: 8,
		PrivateConnectorAddress: "127.0.0.1:9443", PrivateConnectorTLSServerName: "ingress.example.test"}, now, time.Minute)
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
	hello := tunnelv1.PrivateConnectorSessionHello{ProtocolVersion: 1, Kind: "private_connector_session", PrivateServiceID: run.ServiceID, SessionID: session.ID,
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
	visitor, err := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := d.SelectPrivateServiceRun(ctx, run.ServiceID, identity, device.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if selection.ExpiresAt.After(expires) {
		t.Errorf("selection outlived service certificate: %v > %v", selection.ExpiresAt, expires)
	}
	initial, err := d.AuthorizePrivateServiceStream(ctx, ingress.IngressLeaseIdentity, run.ServiceID, run.RunID, session.ID, visitor, run.RunNumber, source, now)
	if err != nil {
		t.Fatal(err)
	}
	if initial.ValidUntil.After(expires) {
		t.Errorf("initial admission outlived service certificate: %v > %v", initial.ValidUntil, expires)
	}
	rechecked, err := d.RecheckPrivateServiceVisitor(ctx, ingress.IngressLeaseIdentity, run.ServiceID, run.RunID, session.ID, identity, visitor, run.RunNumber, source, now)
	if err != nil || !rechecked.Allowed || rechecked.ValidUntil.After(expires) {
		t.Errorf("human recheck ignored service certificate deadline: %+v %v", rechecked, err)
	}
	for _, expiry := range []any{nil, now} {
		if _, err := d.pool.Exec(ctx, `UPDATE control.private_service_runs SET certificate_expires_at=$2,certificate_issuance_id=CASE WHEN $2::timestamptz IS NULL THEN NULL ELSE $3 END WHERE id=$1`, run.RunID, expiry, issuance.ID); err != nil {
			t.Fatal(err)
		}
		decision, err := d.RecheckPrivateServiceVisitor(ctx, ingress.IngressLeaseIdentity, run.ServiceID, run.RunID, session.ID, identity, visitor, run.RunNumber, source, now)
		if err != nil || decision.Allowed {
			t.Errorf("missing/expired certificate kept admitted human stream: %+v %v", decision, err)
		}
	}
}
