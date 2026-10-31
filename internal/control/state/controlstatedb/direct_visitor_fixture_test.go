package controlstatedb_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// direct visitors use the real device, certificate and pending admission APIs.
// native possession and exact relay-process proofs remain with native pair tests.
func directVisitorCertificate(t *testing.T, ctx context.Context, d *controlstate.Database, service, identity string, now time.Time) (string, *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(ctx, identity, public, now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := d.IssueServiceClientCertificate(ctx, service, identity, device.ID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil {
		t.Fatal("missing direct certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return device.ID, leaf
}

func directIngressLease(t *testing.T, ctx context.Context, d *controlstate.Database, name string, port int, now time.Time) controlstate.IngressLeaseIdentity {
	t.Helper()
	run, err := opaqueid.New(opaqueid.IngressRunPrefix)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: name, IngressRunID: run, ProtocolVersion: 1, ConnectionCapacity: 8, IngressPoolID: controlstate.PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return lease.IngressLeaseIdentity
}
