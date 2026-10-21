package controlstate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func testDirectManagedAdmission(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, applied AppliedProjectConfiguration, run PrivateRunState, now time.Time) {
	t.Helper()
	ctx := t.Context()
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	port := 0
	for _, service := range applied.Services {
		if service.ServiceID == run.ServiceID {
			port = service.Port
		}
	}
	lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-ingress", IngressRunID: id(opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	visitor := id(opaqueid.VisitorConnectionPrefix)
	source := netip.MustParseAddr("192.0.2.44")
	admit := func() (DirectVisitorAdmission, error) {
		return d.AdmitDirectServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID, visitor, port, source, now)
	}
	if _, err = admit(); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("private endpoint admitted direct traffic", err)
	}
	setPublic := func(public bool) {
		t.Helper()
		r.DNSAutomation = true
		group := r.Configuration.Publishers["production"]
		group.Public = public
		r.Configuration.Publishers["production"] = group
		r.ExpectedRevision = applied.Revision
		applied, err = d.ApplyProjectConfiguration(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
	}
	setPublic(true)
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports='{}' WHERE ingress_id=$1`, lease.IngressID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimManagedEndpointDNSWork(ctx, "before-exposure", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded an exposed port: found=%t error=%v", found, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports=ARRAY[$2::int] WHERE ingress_id=$1`, lease.IngressID, port); err != nil {
		t.Fatal(err)
	}
	other, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-not-exposed", IngressRunID: id(opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimManagedEndpointDNSWork(ctx, "partial-pool", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded complete pool exposure: found=%t error=%v", found, err)
	}
	if _, err := d.BeginIngressDrain(ctx, other.IngressLeaseIdentity, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publicDNS, found, err := d.ClaimManagedEndpointDNSWork(ctx, "after-exposure", now, time.Minute)
	if err != nil || !found || publicDNS.ServiceID != run.ServiceID || !publicDNS.Public {
		t.Fatalf("ready native service DNS was not claimable: found=%t error=%v", found, err)
	}
	if err := d.ValidateManagedEndpointDNSWork(ctx, publicDNS, now); err != nil {
		t.Fatal(err)
	}
	admitted, err := admit()
	if err != nil || admitted.RunID != run.RunID || len(admitted.Relays) != 2 {
		t.Fatal("direct selection lost the certified run", admitted, err)
	}
	retry, err := admit()
	if err != nil || retry.ServiceID != admitted.ServiceID || retry.RunID != admitted.RunID || retry.RunNumber != admitted.RunNumber || retry.ConnectionID != admitted.ConnectionID || !retry.ExpiresAt.Equal(admitted.ExpiresAt) || !reflect.DeepEqual(retry.Relays, admitted.Relays) {
		t.Fatal("lost admission response changed its reservation", retry, err)
	}
	if err = d.PromoteDirectServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("promoted before visitor authentication", err)
	}
	deviceKey, _, _ := ed25519.GenerateKey(rand.Reader)
	device, err := d.EnrollVisitorDevice(ctx, r.ActorID, deviceKey, now)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	credential, err := d.IssueServiceClientCertificate(ctx, run.ServiceID, r.ActorID, device.ID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(credential.CertificatePEM))
	authorize := func(ip netip.Addr) (PrivateVisitorValidity, error) {
		return d.AuthorizeServiceClientCertificate(ctx, run.ServiceID, run.RunID, run.Token, visitor, run.RunNumber, ip, block.Bytes, now)
	}
	if _, err = authorize(netip.MustParseAddr("192.0.2.45")); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("certificate moved to another source", err)
	}
	decision, err := authorize(source)
	if err != nil || !decision.Allowed || decision.Admitted {
		t.Fatal("TLS authorization bypassed ingress capacity", decision, err)
	}
	status, err := d.DirectServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != DirectVisitorAuthenticated {
		t.Fatal("identity was not awaiting promotion", status, err)
	}
	wrong := lease.IngressLeaseIdentity
	wrong.IngressRunID = id(opaqueid.IngressRunPrefix)
	if err = d.PromoteDirectServiceVisitor(ctx, wrong, visitor, now); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("another ingress promoted the visitor", err)
	}
	for range 2 {
		if err = d.PromoteDirectServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); err != nil {
			t.Fatal("promotion did not recover a lost response", err)
		}
	}
	decision, err = authorize(source)
	if err != nil || !decision.Allowed || !decision.Admitted {
		t.Fatal("authenticated visitor remained pending", decision, err)
	}
	if err = d.RevokeVisitorDevice(ctx, r.ActorID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = authorize(source); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("revoked certificate retained access", err)
	}
	status, err = d.DirectServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, visitor, now)
	if err != nil || status.State != DirectVisitorDenied {
		t.Fatal("ingress did not observe revocation", status, err)
	}
	setPublic(false)
	if err := d.ValidateManagedEndpointDNSWork(ctx, publicDNS, now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatalf("public DNS worker survived private transition: %v", err)
	}
	if _, err = admit(); !errors.Is(err, ErrPrivateServiceAccess) {
		t.Fatal("stale direct endpoint remained admitted", err)
	}
	if err = d.CloseDirectServiceVisitor(ctx, lease.IngressLeaseIdentity, visitor, now); err != nil {
		t.Fatal(err)
	}
}
