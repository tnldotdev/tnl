package state

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func testDirectManagedAdmission(t *testing.T, d *Database, request ApplyProjectConfigurationRequest, applied AppliedProjectConfiguration, run ServiceRunState, now time.Time) {
	t.Helper()
	ctx := t.Context()
	port := 0
	for _, service := range applied.Services {
		if service.ServiceID == run.ServiceID {
			port = service.Port
		}
	}
	lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-ingress", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prepareVisitorTokenKeys(t, d, now)
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
	read := func() (visitorlease.Update, error) {
		wire, err := d.ReadIngressVisitorPolicy(ctx, lease.IngressLeaseIdentity, scope, 0, now)
		if err != nil {
			return visitorlease.Update{}, err
		}
		return visitorlease.Decode(wire)
	}
	private, err := read()
	if err != nil || !private.Enabled || private.View.Public {
		t.Fatal("private service allowed direct visitors", err)
	}
	setPublic := func(public bool) {
		t.Helper()
		request.DNSAutomation = true
		group := request.Configuration.PublisherGroups["production"]
		group.Public = public
		request.Configuration.PublisherGroups["production"] = group
		request.ExpectedRevision = applied.Revision
		applied, err = d.ApplyProjectConfiguration(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
	}
	setPublic(true)
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports='{}' WHERE ingress_id=$1`, lease.IngressID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "before-exposure", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded an exposed port: found=%t error=%v", found, err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_ports=ARRAY[$2::int] WHERE ingress_id=$1`, lease.IngressID, port); err != nil {
		t.Fatal(err)
	}
	other, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "managed-direct-not-exposed", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: tunnelv1.Version, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID}, now, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "partial-pool", now, time.Minute); err != nil || found {
		t.Fatalf("public DNS preceded complete pool exposure: found=%t error=%v", found, err)
	}
	if _, err := d.BeginIngressDrain(ctx, other.IngressLeaseIdentity, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publicDNS, found, err := d.ClaimServiceEndpointDNSWork(ctx, "after-exposure", now, time.Minute)
	if err != nil || !found || publicDNS.ServiceID != run.ServiceID || !publicDNS.Public {
		t.Fatalf("ready native service DNS was not claimable: found=%t error=%v", found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, publicDNS, now); err != nil {
		t.Fatal(err)
	}
	selected, err := d.SelectServiceRun(ctx, run.ServiceID, request.ActorID, "", now)
	if err == nil || selected.ServiceRunID != "" {
		t.Fatal("an unregistered device selected a native run", err)
	}
	parent := browserTestControlSession(t, d, request.ActorID, now)
	principal := WithControlPrincipal(ctx, ControlPrincipal{IdentityID: request.ActorID, SessionID: parent.SessionID})
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(principal, request.ActorID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = d.SelectServiceRun(ctx, run.ServiceID, request.ActorID, device.ID, now)
	if err != nil || selected.ServiceRunID != run.RunID || selected.ExpiresAt.IsZero() {
		t.Fatal("direct preparation lost the certified run", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := d.IssueVisitorClientCertificate(principal, testVisitorIssuer, scope, DeviceTokenSource{DeviceID: device.ID}, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(credential.CertificatePEM))
	if block == nil {
		t.Fatal("missing signed certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	local, err := read()
	if err != nil || !local.View.Public || local.View.Port != uint16(port) || local.ClientAuthorities == nil {
		t.Fatal("direct policy lost the destination port or client issuer", err)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: local.ClientAuthorities, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: chains}
	token, err := visitortoken.CertificateToken(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyCertificate(token, local.View, state, now); err != nil {
		t.Fatal("locally verified client certificate was denied", err)
	}
	bad := state
	bad.VerifiedChains = nil
	if _, err := visitortoken.VerifyCertificate(token, local.View, bad, now); err == nil {
		t.Fatal("unverified certificate chain admitted a direct visitor")
	}
	allocation, err := d.AllocateStreamCapacity(ctx, StreamCapacityRequest{Owner: lease.IngressLeaseIdentity, Scope: scope, RunID: run.RunID, RunNumber: run.RunNumber, RequestID: "direct-capacity", Capacity: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	local, err = read()
	if err != nil {
		t.Fatal(err)
	}
	reservation := tunnelv1.StreamReservation{ID: mustOpaqueID(t, "sres_"), AllocationID: allocation.ID, Slot: 0, Sequence: 1, ResourceKind: "service", ResourceID: scope.ID, RunID: run.RunID, RunNumber: uint64(run.RunNumber), VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), IngressID: lease.IngressID, IngressRunID: lease.IngressRunID, IngressLeaseRevision: lease.IngressLeaseRevision}
	view, err := visitorlease.New(scope, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	if err := view.Apply(view.Begin(), local); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("192.0.2.44")
	guard, err := view.BindReservationFrom(reservation, source, func() {})
	if err != nil {
		t.Fatal("exact ingress allocation did not reserve local capacity", err)
	}
	defer guard.Close()
	if err := guard.BindSource(netip.MustParseAddr("192.0.2.45")); err == nil {
		t.Fatal("direct visitor changed the ingress-observed source")
	}
	wrong := reservation
	wrong.IngressRunID = other.IngressRunID
	if err := view.ValidateReservation(wrong); err == nil {
		t.Fatal("another ingress process reused direct capacity")
	}
	if err := d.RevokeVisitorDevice(principal, request.ActorID, device.ID, now); err != nil {
		t.Fatal(err)
	}
	current, err := read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := visitortoken.VerifyCertificate(token, current.View, state, now); err == nil {
		t.Fatal("revoked certificate retained signed permission")
	}
	setPublic(false)
	if err := d.ValidateServiceEndpointDNSWork(ctx, publicDNS, now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatalf("public DNS worker survived private transition: %v", err)
	}
	private, err = read()
	if err != nil || private.View.Public {
		t.Fatal("stale direct endpoint remained available", err)
	}
}
